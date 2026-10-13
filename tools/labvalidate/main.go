// Command labvalidate runs the REAL content loader (internal/content) over the
// learning-tree content directory and validates every lesson's optional
// interactive `lab:` front-matter block together with its fixture bundle.
//
// A lab is "broken" when:
//   - kind is missing/unsupported (only "shell" exists today);
//   - workdir is missing or not absolute;
//   - check is empty (nothing to verify the student against);
//   - there are no hints, or a hint is empty;
//   - the referenced bundle (<content>/labs/<bundle||lesson-id>.json) is
//     missing or not valid JSON;
//   - a file declared in `lab.files` is not seeded by the bundle's `fs`;
//   - the bundle's `expect.file` is not inside the lab workdir;
//   - a tool fixture case has an empty `match`, an uncompilable regexp, or an
//     empty `output`.
//
// Usage: go run ./tools/labvalidate [-content ./content] [-json]
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"learningtree/internal/content"
)

type issue struct {
	Lesson string `json:"lesson"`
	Slug   string `json:"slug"`
	Kind   string `json:"kind"`
	Detail string `json:"detail"`
}

type seed struct {
	Path string  `json:"path"`
	Type string  `json:"type"`
	Text *string `json:"text"`
	B64  *string `json:"b64"`
	Mode string  `json:"mode"`
}

type toolCase struct {
	Match   string `json:"match"`
	Output  string `json:"output"`
	Example string `json:"example"`
}

type tool struct {
	Help  string     `json:"help"`
	Cases []toolCase `json:"cases"`
}

type bundle struct {
	ID      string          `json:"id"`
	Workdir string          `json:"workdir"`
	FS      []seed          `json:"fs"`
	Tools   map[string]tool `json:"tools"`
	Expect  *struct {
		File     string `json:"file"`
		Contains string `json:"contains"`
		Equals   string `json:"equals"`
	} `json:"expect"`
}

func main() {
	contentDir := flag.String("content", "./content", "content directory")
	asJSON := flag.Bool("json", false, "machine-readable output")
	flag.Parse()

	store := content.NewStore(*contentDir)
	if err := store.Load(); err != nil {
		fmt.Fprintf(os.Stderr, "load error: %v\n", err)
		os.Exit(2)
	}

	var issues []issue
	perCat := map[string]int{}
	withLab := 0

	lessons := store.All()
	sort.Slice(lessons, func(i, j int) bool { return lessons[i].ID < lessons[j].ID })

	for _, l := range lessons {
		if l.Lab == nil {
			continue
		}
		withLab++
		perCat[l.Category]++
		add := func(kind, detail string) {
			issues = append(issues, issue{Lesson: l.Title, Slug: l.ID, Kind: kind, Detail: detail})
		}

		lab := l.Lab
		if lab.Kind == "" {
			add("lab.kind", "kind is required")
		} else if lab.Kind != "shell" {
			add("lab.kind", fmt.Sprintf("unsupported kind %q (only \"shell\" is implemented)", lab.Kind))
		}
		if lab.Workdir == "" {
			add("lab.workdir", "workdir is required")
		} else if !strings.HasPrefix(lab.Workdir, "/") {
			add("lab.workdir", fmt.Sprintf("workdir %q must be absolute", lab.Workdir))
		}
		if strings.TrimSpace(lab.Check) == "" {
			add("lab.check", "check is required (the student needs something to verify against)")
		}
		if len(lab.Hints) == 0 {
			add("lab.hints", "at least one hint is recommended")
		}
		for i, h := range lab.Hints {
			if strings.TrimSpace(h) == "" {
				add("lab.hints", fmt.Sprintf("hint #%d is empty", i+1))
			}
		}
		if len(lab.Files) == 0 {
			add("lab.files", "files is empty — the student has nothing to start from")
		}

		// --- bundle ---
		bundleID := lab.Bundle
		if bundleID == "" {
			bundleID = l.ID
		}
		b, err := loadBundle(*contentDir, bundleID)
		if err != nil {
			add("bundle", err.Error())
			continue
		}
		if b.ID != "" && b.ID != bundleID {
			add("bundle.id", fmt.Sprintf("bundle id %q does not match %q", b.ID, bundleID))
		}
		if lab.Workdir != "" && b.Workdir != "" && lab.Workdir != b.Workdir {
			add("bundle.workdir", fmt.Sprintf("bundle workdir %q != lab workdir %q", b.Workdir, lab.Workdir))
		}

		seeded := map[string]bool{}
		for i, s := range b.FS {
			if s.Path == "" {
				add("bundle.fs", fmt.Sprintf("fs[%d] has no path", i))
				continue
			}
			isDir := s.Type == "dir"
			if !isDir && s.Text == nil && s.B64 == nil {
				add("bundle.fs", fmt.Sprintf("fs[%d] %q has neither text nor b64", i, s.Path))
			}
			seeded[s.Path] = true
		}
		for _, f := range lab.Files {
			found := seeded[f]
			if !found && lab.Workdir != "" {
				found = seeded[filepath.ToSlash(filepath.Join(lab.Workdir, f))]
			}
			if !found {
				add("lab.files", fmt.Sprintf("declared file %q is not seeded by the bundle", f))
			}
		}

		if b.Expect != nil && b.Expect.File != "" && lab.Workdir != "" {
			if !strings.HasPrefix(filepath.ToSlash(b.Expect.File), strings.TrimSuffix(lab.Workdir, "/")+"/") {
				add("bundle.expect", fmt.Sprintf("expect.file %q is outside workdir %q", b.Expect.File, lab.Workdir))
			}
		}

		for name, t := range b.Tools {
			if strings.TrimSpace(t.Help) == "" {
				add("bundle.tools", fmt.Sprintf("tool %q has no help text", name))
			}
			if len(t.Cases) == 0 {
				add("bundle.tools", fmt.Sprintf("tool %q has no cases", name))
			}
			for i, c := range t.Cases {
				if strings.TrimSpace(c.Match) == "" {
					add("bundle.tools", fmt.Sprintf("tool %q case #%d has no match", name, i+1))
					continue
				}
				if _, err := regexp.Compile(c.Match); err != nil {
					add("bundle.tools", fmt.Sprintf("tool %q case #%d match is not a valid regexp: %v", name, i+1, err))
				}
				if strings.TrimSpace(c.Output) == "" {
					add("bundle.tools", fmt.Sprintf("tool %q case #%d has empty output", name, i+1))
				}
			}
		}
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{
			"lessons_with_lab": withLab,
			"per_category":     perCat,
			"issues":           issues,
		})
	} else {
		fmt.Printf("labvalidate: %d lesson(s) with a lab\n", withLab)
		for _, c := range sortedKeys(perCat) {
			fmt.Printf("  %-12s %d\n", c, perCat[c])
		}
		if len(issues) == 0 {
			fmt.Println("OK — every lab block and bundle is well-formed")
		} else {
			fmt.Printf("\n%d issue(s):\n", len(issues))
			for _, is := range issues {
				fmt.Printf("  [%s] %s (%s): %s\n", is.Kind, is.Slug, is.Lesson, is.Detail)
			}
		}
	}
	if len(issues) > 0 {
		os.Exit(1)
	}
}

func loadBundle(contentDir, id string) (*bundle, error) {
	p := filepath.Join(contentDir, "labs", id+".json")
	raw, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("bundle %q not found at %s", id, p)
	}
	var b bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, fmt.Errorf("bundle %q is not valid JSON: %v", id, err)
	}
	return &b, nil
}

func sortedKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
