package content

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"learningtree/internal/model"
)

// --- splitFrontmatter ------------------------------------------------------

func TestSplitFrontmatter(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		wantNil  bool
		wantID   string
		wantBody string
	}{
		{
			name:     "standard",
			raw:      "---\nid: web-sqli\ntitle: SQLi\n---\nbody line 1\nbody line 2\n",
			wantID:   "web-sqli",
			wantBody: "body line 1\nbody line 2\n",
		},
		{
			name:     "leading blank lines allowed",
			raw:      "\n\n---\nid: a\n---\nbody\n",
			wantID:   "a",
			wantBody: "body\n",
		},
		{
			name:     "crlf normalised",
			raw:      "---\r\nid: a\r\n---\r\nbody\r\n",
			wantID:   "a",
			wantBody: "body\n",
		},
		{
			name:     "no frontmatter",
			raw:      "just body\n",
			wantNil:  true,
			wantBody: "just body\n",
		},
		{
			name:     "unterminated frontmatter",
			raw:      "---\nid: a\nno closing fence\n",
			wantNil:  true,
			wantBody: "---\nid: a\nno closing fence\n",
		},
		{
			name:     "non-blank content before fence",
			raw:      "hello\n---\nid: a\n---\nbody\n",
			wantNil:  true,
			wantBody: "hello\n---\nid: a\n---\nbody\n",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fm, body := splitFrontmatter(tc.raw)
			if tc.wantNil {
				if fm != nil {
					t.Fatalf("expected nil frontmatter, got %v", fm)
				}
			} else if fm == nil {
				t.Fatalf("expected frontmatter, got nil")
			} else if got := getString(fm, "id"); got != tc.wantID {
				t.Fatalf("id = %q, want %q", got, tc.wantID)
			}
			if body != tc.wantBody {
				t.Fatalf("body = %q, want %q", body, tc.wantBody)
			}
		})
	}
}

// --- parseSimpleYAML -------------------------------------------------------

func TestParseSimpleYAML(t *testing.T) {
	raw := strings.Join([]string{
		"id: web-sqli",
		"title: \"SQL-инъекции: основы\"",
		"order: 3",
		"tags: [sqli, injection, xss]",
		"prerequisites:",
		"  - web-http-basics",
		"  - web-architecture",
		"empty:",
		"# comment line",
		"useful_for:",
		"  - 'CTF Web'",
		"difficulty: hard",
	}, "\n")

	fm := parseSimpleYAML(strings.Split(raw, "\n"))

	if got := getString(fm, "id"); got != "web-sqli" {
		t.Errorf("id = %q", got)
	}
	if got := getString(fm, "title"); got != "SQL-инъекции: основы" {
		t.Errorf("quoted title = %q", got)
	}
	if got := getInt(fm, "order"); got != 3 {
		t.Errorf("order = %d", got)
	}
	if got := getList(fm, "tags"); !reflect.DeepEqual(got, []string{"sqli", "injection", "xss"}) {
		t.Errorf("tags = %v", got)
	}
	if got := getList(fm, "prerequisites"); !reflect.DeepEqual(got, []string{"web-http-basics", "web-architecture"}) {
		t.Errorf("prerequisites = %v", got)
	}
	if got := getList(fm, "useful_for"); !reflect.DeepEqual(got, []string{"CTF Web"}) {
		t.Errorf("useful_for = %v", got)
	}
	if got, ok := fm["empty"].([]string); !ok || len(got) != 0 {
		t.Errorf("empty should be an empty []string, got %#v", fm["empty"])
	}
	if got := getString(fm, "difficulty"); got != "hard" {
		t.Errorf("difficulty = %q", got)
	}
}

// --- getString / getInt / getList -----------------------------------------

func TestGetHelpers(t *testing.T) {
	m := map[string]any{
		"s":    "text",
		"i":    7,
		"istr": "42",
		"list": []string{"a", "b"},
		"one":  "solo",
	}

	if got := getString(m, "s"); got != "text" {
		t.Errorf("getString = %q", got)
	}
	if got := getString(m, "i"); got != "" {
		t.Errorf("getString(int) = %q, want empty", got)
	}
	if got := getString(m, "missing"); got != "" {
		t.Errorf("getString(missing) = %q", got)
	}

	if got := getInt(m, "i"); got != 7 {
		t.Errorf("getInt(int) = %d", got)
	}
	if got := getInt(m, "istr"); got != 42 {
		t.Errorf("getInt(string) = %d", got)
	}
	if got := getInt(m, "s"); got != 0 {
		t.Errorf("getInt(non-numeric) = %d", got)
	}

	if got := getList(m, "list"); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Errorf("getList([]string) = %v", got)
	}
	if got := getList(m, "one"); !reflect.DeepEqual(got, []string{"solo"}) {
		t.Errorf("getList(string) = %v", got)
	}
	if got := getList(m, "missing"); got != nil {
		t.Errorf("getList(missing) = %v, want nil", got)
	}
}

// --- splitSections ---------------------------------------------------------

func TestSplitSections(t *testing.T) {
	body := strings.Join([]string{
		"вступление без заголовка",
		"## Теория",
		"одно два три четыре пять шесть семь восемь девять",
		"## Практика",
		"слово",
	}, "\n")

	secs := splitSections(body)
	if len(secs) != 3 {
		t.Fatalf("got %d sections, want 3: %#v", len(secs), secs)
	}
	if secs[0].Title != "Введение" {
		t.Errorf("section 0 title = %q, want Введение", secs[0].Title)
	}
	if secs[1].Title != "Теория" || secs[2].Title != "Практика" {
		t.Errorf("titles = %q, %q", secs[1].Title, secs[2].Title)
	}
	// required_seconds = words/3 clamped to [6,150].
	for _, s := range secs {
		if s.RequiredSeconds < 6 || s.RequiredSeconds > 150 {
			t.Errorf("section %q required_seconds = %d out of [6,150]", s.Title, s.RequiredSeconds)
		}
	}
	// tiny section is clamped up to the 6 s floor
	if secs[2].RequiredSeconds != 6 {
		t.Errorf("tiny section required_seconds = %d, want 6", secs[2].RequiredSeconds)
	}
}

func TestSplitSectionsClampCeiling(t *testing.T) {
	long := strings.Repeat("word ", 1000) // 1000 words -> 333 -> clamp 150
	secs := splitSections("## Big\n" + long)
	if len(secs) != 1 {
		t.Fatalf("got %d sections", len(secs))
	}
	if secs[0].RequiredSeconds != 150 {
		t.Errorf("required_seconds = %d, want 150 (ceiling)", secs[0].RequiredSeconds)
	}
}

func TestSplitSectionsFallbackTitle(t *testing.T) {
	// An empty "## " heading produces an untitled, non-first section which gets
	// the "Раздел N" fallback.
	secs := splitSections("## \ncontent here")
	if len(secs) != 1 {
		t.Fatalf("got %d sections: %#v", len(secs), secs)
	}
	if secs[0].Title != "Раздел 1" {
		t.Errorf("fallback title = %q, want Раздел 1", secs[0].Title)
	}
}

func TestSplitSectionsEmpty(t *testing.T) {
	if secs := splitSections("   \n\n"); len(secs) != 0 {
		t.Fatalf("expected no sections, got %#v", secs)
	}
}

// --- extractQuizBlock / parseQuizYAML --------------------------------------

func TestExtractQuizBlock(t *testing.T) {
	md := strings.Join([]string{
		"## Квиз",
		"",
		"```quiz",
		"- question: \"2+2?\"",
		"  options:",
		"    - \"3\"",
		"    - \"4\"",
		"    - \"5\"",
		"  answer: 1",
		"  explanation: \"basic math\"",
		"- q: \"Capital of France?\"",
		"  options:",
		"    - Paris",
		"    - London",
		"    - Berlin",
		"  answer: A",
		"```",
		"",
		"trailing prose",
	}, "\n")

	qs, cleaned, ok := extractQuizBlock(md)
	if !ok {
		t.Fatalf("expected block to be extracted")
	}
	if len(qs) != 2 {
		t.Fatalf("got %d questions, want 2", len(qs))
	}
	if qs[0].Question != "2+2?" || qs[0].Answer != 1 || qs[0].Explanation != "basic math" {
		t.Errorf("q0 = %#v", qs[0])
	}
	if !reflect.DeepEqual(qs[0].Options, []string{"3", "4", "5"}) {
		t.Errorf("q0 options = %v", qs[0].Options)
	}
	if qs[1].Answer != 0 { // letter A -> index 0
		t.Errorf("q1 answer = %d, want 0", qs[1].Answer)
	}
	if strings.Contains(cleaned, "```quiz") {
		t.Errorf("cleaned markdown still contains the quiz fence: %q", cleaned)
	}
	if !strings.Contains(cleaned, "trailing prose") {
		t.Errorf("cleaned markdown lost trailing prose: %q", cleaned)
	}
}

func TestExtractQuizBlockNoBlock(t *testing.T) {
	md := "just some markdown\n"
	qs, cleaned, ok := extractQuizBlock(md)
	if ok || qs != nil {
		t.Fatalf("expected no block, got qs=%v ok=%v", qs, ok)
	}
	if cleaned != md {
		t.Fatalf("markdown should be unchanged")
	}
}

func TestExtractQuizBlockUnterminated(t *testing.T) {
	md := "```quiz\n- question: x\n  options: [a, b]\n  answer: 0\n"
	qs, _, ok := extractQuizBlock(md)
	if ok || qs != nil {
		t.Fatalf("unterminated block must be rejected, got %v %v", qs, ok)
	}
}

func TestParseQuizYAMLRejectsMalformed(t *testing.T) {
	block := strings.Join([]string{
		"- question: \"only one option\"",
		"  options:",
		"    - \"solo\"",
		"  answer: 0",
		"- question: \"answer out of range\"",
		"  options: [a, b]",
		"  answer: 5",
		"- question: \"\"",
		"  options: [a, b]",
		"  answer: 0",
		"- question: \"no options\"",
		"  answer: 0",
	}, "\n")

	qs := parseQuizYAML(block)
	if len(qs) != 0 {
		t.Fatalf("malformed questions must be dropped, got %#v", qs)
	}
}

func TestParseQuizYAMLOptionContinuation(t *testing.T) {
	block := strings.Join([]string{
		"- question: \"Q?\"",
		"  options:",
		"    - \"first part\"",
		"      continued here",
		"    - \"second\"",
		"  answer: 0",
	}, "\n")
	qs := parseQuizYAML(block)
	if len(qs) != 1 {
		t.Fatalf("got %d questions", len(qs))
	}
	if qs[0].Options[0] != "first part continued here" {
		t.Errorf("continuation not merged: %q", qs[0].Options[0])
	}
}

func TestParseAnswer(t *testing.T) {
	cases := map[string]int{
		"0": 0, "2": 2, "A": 0, "b": 1, "C": 2, "D": 3,
		"": -1, "!": -1, "x": 23, // letters map to A=0..; out-of-range filtered by caller
	}
	for in, want := range cases {
		if got := parseAnswer(in); got != want {
			t.Errorf("parseAnswer(%q) = %d, want %d", in, got, want)
		}
	}
}

// --- parseQuizMarkdown (the "## Квиз" section format) ----------------------

func TestParseQuizMarkdownFormats(t *testing.T) {
	md := strings.Join([]string{
		"**1. Какой оператор даёт обход аутентификации?**",
		"- A) `$eq`",
		"- B) `$ne`",
		"- C) `$sum`",
		"- D) `$unwind`",
		"- **Правильный ответ: B.** — истинно для любого пароля.",
		"",
		"**2. Что означает 403?**",
		"- A) не аутентифицирован",
		"- [x] B) нет прав на ресурс",
		"- C) не найдено",
		"",
		"3. Чему равно (P ^ K) ^ K?",
		"   - A) 0",
		"   - B) P ✅",
		"   - C) K",
		"",
		"**4. Что делает -I?**",
		"- A) идёт по редиректам",
		"- B) отправляет HEAD-запрос **(правильный ответ)**",
		"- C) cookie-jar",
		"",
		"**5. Каким заголовком передаётся JSON?**",
		"- A) `Accept`",
		"- B) `Content-Type`",
		"- C) `Content-Encoding`",
		"",
		"**Ответ: B** — Content-Type описывает тело запроса.",
	}, "\n")

	qs := parseQuizMarkdown(md)
	if len(qs) != 5 {
		t.Fatalf("got %d questions, want 5: %#v", len(qs), qs)
	}
	wantAnswers := []int{1, 1, 1, 1, 1}
	for i, q := range qs {
		if q.Answer != wantAnswers[i] {
			t.Errorf("q%d answer = %d, want %d (%q)", i, q.Answer, wantAnswers[i], q.Question)
		}
		if len(q.Options) < 2 {
			t.Errorf("q%d has %d options", i, len(q.Options))
		}
		if strings.Contains(q.Question, "**") || strings.Contains(q.Options[q.Answer], "**") {
			t.Errorf("q%d still contains bold markers: %q / %q", i, q.Question, q.Options[q.Answer])
		}
	}
	if qs[0].Explanation == "" {
		t.Errorf("q0 explanation not captured")
	}
	if !strings.Contains(qs[2].Options[1], "P") || strings.Contains(qs[2].Options[1], "✅") {
		t.Errorf("q2 option marker not stripped: %q", qs[2].Options[1])
	}
}

func TestParseQuizMarkdownRejectsIncomplete(t *testing.T) {
	md := strings.Join([]string{
		"**1. Single option question?**",
		"- A) only one",
		"**2. No answer declared?**",
		"- A) one",
		"- B) two",
	}, "\n")
	if qs := parseQuizMarkdown(md); len(qs) != 0 {
		t.Fatalf("incomplete questions must be dropped, got %#v", qs)
	}
}

func TestQuizAnswerToken(t *testing.T) {
	cases := []struct {
		raw  string
		n    int
		want int
	}{
		{"B** — explanation", 4, 1},
		{"A** — x", 4, 0},
		{"2", 4, 1},
		{"D.", 4, 3},
		{"", 4, -1},
		{"Z", 4, 25}, // out of range; caller filters
	}
	for _, c := range cases {
		if got := quizAnswerToken(c.raw, c.n); got != c.want {
			t.Errorf("quizAnswerToken(%q) = %d, want %d", c.raw, got, c.want)
		}
	}
}

// --- buildTree -------------------------------------------------------------

func lesson(id, parent, cat string, order int) *model.Lesson {
	l := &model.Lesson{LessonMeta: model.LessonMeta{ID: id, Title: id, Parent: parent, Category: cat, Order: order, Difficulty: "easy"}}
	return l
}

func TestBuildTree(t *testing.T) {
	lessons := map[string]*model.Lesson{
		"root":    lesson("root", "", "web", 1),
		"child-b": lesson("child-b", "root", "web", 2),
		"child-a": lesson("child-a", "root", "web", 1),
		"grand":   lesson("grand", "child-a", "web", 1),
		"orphan":  lesson("orphan", "does-not-exist", "web", 5),
		"selfie":  lesson("selfie", "selfie", "web", 6),
	}
	roots, nodes := buildTree(lessons)

	if len(nodes) != len(lessons) {
		t.Fatalf("nodes = %d, want %d", len(nodes), len(lessons))
	}
	// roots: root, orphan, selfie (sorted by order)
	var rootIDs []string
	for _, r := range roots {
		rootIDs = append(rootIDs, r.ID)
		if r.Depth != 0 {
			t.Errorf("root %s depth = %d, want 0", r.ID, r.Depth)
		}
	}
	if !reflect.DeepEqual(rootIDs, []string{"root", "orphan", "selfie"}) {
		t.Fatalf("roots = %v", rootIDs)
	}
	// children sorted by order: child-a then child-b
	root := nodes["root"]
	if len(root.Children) != 2 || root.Children[0].ID != "child-a" || root.Children[1].ID != "child-b" {
		t.Fatalf("root children = %v", root.Children)
	}
	if root.Children[0].Depth != 1 || nodes["grand"].Depth != 2 {
		t.Errorf("depths wrong: child=%d grand=%d", root.Children[0].Depth, nodes["grand"].Depth)
	}
	// orphan/selfie became roots, not children
	if nodes["orphan"].Depth != 0 || nodes["selfie"].Depth != 0 {
		t.Errorf("orphan/selfie should be depth 0")
	}
}

// --- Search ----------------------------------------------------------------

func TestSearch(t *testing.T) {
	s := NewStore(t.TempDir())
	seedLessons(t, s,
		"title-hit", "SQLi injection basics", "sqli", "medium", "learn sqli here", "unrelated body",
		"tag-hit", "Networking", "sqli", "easy", "no summary match", "nothing",
		"summary-hit", "Something", "other", "easy", "all about sqli attacks", "nothing",
		"body-hit", "Something else", "other", "easy", "nothing here", "the sqli payload works",
	)

	res := s.Search("sqli")
	if len(res) != 4 {
		t.Fatalf("got %d results, want 4: %v", len(res), res)
	}
	byID := map[string]int{}
	for _, r := range res {
		byID[r["id"].(string)] = r["score"].(int)
	}
	if byID["title-hit"] <= byID["tag-hit"] {
		t.Errorf("title score (%d) should beat tag score (%d)", byID["title-hit"], byID["tag-hit"])
	}
	if byID["tag-hit"] <= byID["summary-hit"] {
		t.Errorf("tag score should beat summary score")
	}
	if byID["summary-hit"] <= byID["body-hit"] {
		t.Errorf("summary score should beat body score")
	}

	if got := s.Search("  "); got != nil {
		t.Errorf("blank query should return nil, got %v", got)
	}
	if got := s.Search("zzzznotpresent"); len(got) != 0 {
		t.Errorf("no-match query should return nothing, got %v", got)
	}
}

// seedLessons writes simple lessons into a fresh store and loads them.
func seedLessons(t *testing.T, s *Store, specs ...string) {
	t.Helper()
	for i := 0; i+5 < len(specs); i += 6 {
		id, title, tag, diff, summary, body := specs[i], specs[i+1], specs[i+2], specs[i+3], specs[i+4], specs[i+5]
		md := "---\nid: " + id + "\ntitle: \"" + title + "\"\ncategory: web\ndifficulty: " + diff +
			"\ntags: [" + tag + "]\nsummary: \"" + summary + "\"\n---\n## Section\n" + body + "\n"
		if err := os.WriteFile(filepath.Join(s.Dir(), id+".md"), []byte(md), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Load(); err != nil {
		t.Fatal(err)
	}
}

// --- parseLesson -----------------------------------------------------------

func TestParseLessonDefaults(t *testing.T) {
	// parseLesson derives fallbacks from the *path* string, so use a synthetic
	// path that mirrors the real layout (content/<category>/<slug>.md).
	path := "content/web/my-lesson.md"
	raw := "---\nsummary: \"x\"\n---\n## One\ntext\n"
	l, err := parseLesson(raw, path)
	if err != nil {
		t.Fatal(err)
	}
	if l.ID != "my-lesson" {
		t.Errorf("id fallback = %q", l.ID)
	}
	if l.Title != "my-lesson" {
		t.Errorf("title fallback = %q", l.Title)
	}
	if l.Category != "web" {
		t.Errorf("category fallback = %q", l.Category)
	}
	if l.Difficulty != "medium" {
		t.Errorf("difficulty fallback = %q", l.Difficulty)
	}
	if l.EstimatedMinutes != l.Words/180+2 {
		t.Errorf("estimated minutes = %d, words = %d", l.EstimatedMinutes, l.Words)
	}
}

func TestParseLessonQuizSection(t *testing.T) {
	raw := strings.Join([]string{
		"---",
		"id: q-lesson",
		"title: \"Quiz lesson\"",
		"category: web",
		"difficulty: easy",
		"---",
		"## Теория",
		"body text here",
		"## Квиз",
		"**1. 2+2?**",
		"- A) 3",
		"- [x] B) 4",
		"- C) 5",
		"## Где пригодится",
		"- CTF",
	}, "\n")

	l, err := parseLesson(raw, "content/web/q-lesson.md")
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Quiz) != 1 {
		t.Fatalf("expected 1 parsed quiz question, got %d", len(l.Quiz))
	}
	if l.Quiz[0].Answer != 1 {
		t.Errorf("quiz answer = %d, want 1", l.Quiz[0].Answer)
	}
	// The answer-revealing markdown must not remain in the rendered section.
	for _, sec := range l.Sections {
		if isQuizSection(sec.Title) && strings.Contains(sec.Markdown, "[x]") {
			t.Errorf("quiz section still exposes the marked answer: %q", sec.Markdown)
		}
	}
}

// --- content validation over the real ./content tree -----------------------

// TestContentDirectoryValid walks the real content directory and asserts the
// invariants the tree/UI rely on. Failures are reported per file so an author
// can fix the offending lesson.
func TestContentDirectoryValid(t *testing.T) {
	root := filepath.Join("..", "..", "content")
	if _, err := os.Stat(root); err != nil {
		t.Skipf("content directory not found (%v)", err)
	}

	type lessonFile struct {
		path string
		l    *model.Lesson
	}
	var files []lessonFile
	ids := map[string]string{}
	validDiff := map[string]bool{"beginner": true, "easy": true, "medium": true, "hard": true, "expert": true}

	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() {
			if p != root && (strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_")) {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") {
			return nil
		}
		if !strings.HasSuffix(name, ".md") && !strings.HasSuffix(name, ".markdown") {
			return nil
		}
		raw, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		l, perr := parseLesson(string(raw), p)
		if perr != nil {
			t.Errorf("%s: parse error: %v", p, perr)
			return nil
		}
		files = append(files, lessonFile{p, l})
		if prev, dup := ids[l.ID]; dup {
			t.Errorf("duplicate lesson id %q: %s and %s", l.ID, prev, p)
		} else {
			ids[l.ID] = p
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	if len(files) == 0 {
		t.Fatalf("no lessons found under %s", root)
	}

	quizLessons := 0
	for _, lf := range files {
		p, l := lf.path, lf.l

		// Raw frontmatter must explicitly declare a valid category/difficulty.
		fm, _ := splitFrontmatter(mustRead(t, p))
		if getString(fm, "category") == "" {
			t.Errorf("%s: missing 'category' in frontmatter", p)
		}
		if d := getString(fm, "difficulty"); d == "" {
			t.Errorf("%s: missing 'difficulty' in frontmatter", p)
		} else if !validDiff[d] {
			t.Errorf("%s: invalid difficulty %q", p, d)
		}
		if l.Category == "" {
			t.Errorf("%s: empty category", p)
		}
		if !validDiff[l.Difficulty] {
			t.Errorf("%s: invalid parsed difficulty %q", p, l.Difficulty)
		}
		if l.Parent != "" {
			if _, ok := ids[l.Parent]; !ok {
				t.Errorf("%s: parent %q does not resolve to an existing lesson id", p, l.Parent)
			}
		}

		// Every "## Квиз" section must yield a valid parsed quiz.
		hasQuiz := false
		for _, sec := range l.Sections {
			if isQuizSection(sec.Title) {
				hasQuiz = true
			}
		}
		if hasQuiz {
			quizLessons++
			if len(l.Quiz) == 0 {
				t.Errorf("%s: has a '## Квиз' section but no parseable quiz", p)
				continue
			}
			for i, q := range l.Quiz {
				if q.Question == "" {
					t.Errorf("%s: quiz q%d has empty question", p, i)
				}
				if len(q.Options) < 2 {
					t.Errorf("%s: quiz q%d has %d options (need >=2)", p, i, len(q.Options))
				}
				if q.Answer < 0 || q.Answer >= len(q.Options) {
					t.Errorf("%s: quiz q%d answer %d out of range [0,%d)", p, i, q.Answer, len(q.Options))
				}
			}
		}
	}
	t.Logf("validated %d lessons (%d with quizzes)", len(files), quizLessons)
}

func mustRead(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read %s: %v", p, err)
	}
	return string(b)
}

// --- hard content-integrity assertions over the real ./content tree --------
//
// These complement TestContentDirectoryValid and are exactly what the CI
// (`make test`) and tools/quizvalidate enforce. They run the REAL loader, so a
// lesson the loader silently skips is caught too.

// contentRoot resolves the real content directory relative to this package and
// skips the test when it is absent (e.g. an installed binary).
func contentRoot(t *testing.T) string {
	t.Helper()
	root := filepath.Join("..", "..", "content")
	if _, err := os.Stat(root); err != nil {
		t.Skipf("content directory not found (%v)", err)
	}
	return root
}

// walkLessonFiles returns every authorable lesson file under root, skipping the
// loader's dot/underscore service files (e.g. content/_template.md).
func walkLessonFiles(t *testing.T, root string) []string {
	t.Helper()
	var files []string
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() {
			if p != root && (strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_")) {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") {
			return nil
		}
		if !strings.HasSuffix(name, ".md") && !strings.HasSuffix(name, ".markdown") {
			return nil
		}
		files = append(files, p)
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return files
}

// legacyQuizMarkers are answer-revealing tokens that must never survive into the
// visible quiz text (question/option) or a rendered quiz section. "правильный
// ответ" / "ответ:" cover the old prose answer lines.
var legacyQuizMarkers = []string{"[x]", "[ ]", "(верно)", "✅", "правильный ответ", "ответ:"}

func hasLegacyMarker(s string) (string, bool) {
	low := strings.ToLower(s)
	for _, m := range legacyQuizMarkers {
		if strings.Contains(low, m) {
			return m, true
		}
	}
	return "", false
}

// TestContentQuizIntegrity asserts that every lesson in the real tree carries a
// well-formed interactive quiz: non-empty, >=3 questions, each with non-empty
// text, >=2 options and an in-range 0-based answer index; no backslash-escaped
// quote leaking into parsed text; and no leftover legacy answer markers in
// either the parsed quiz or the rendered quiz section.
func TestContentQuizIntegrity(t *testing.T) {
	root := contentRoot(t)
	store := NewStore(root)
	if err := store.Load(); err != nil {
		t.Fatalf("load %s: %v", root, err)
	}
	lessons := store.All()
	if len(lessons) == 0 {
		t.Fatalf("no lessons loaded from %s", root)
	}

	checked := 0
	for _, l := range lessons {
		if len(l.Quiz) == 0 {
			t.Errorf("%s (%s): no parsed quiz — every lesson must have a '## Квиз' section with a ```quiz block", l.ID, l.Category)
			continue
		}
		if len(l.Quiz) < 3 {
			t.Errorf("%s (%s): quiz has %d question(s), want >=3", l.ID, l.Category, len(l.Quiz))
		}
		for qi, q := range l.Quiz {
			if strings.TrimSpace(q.Question) == "" {
				t.Errorf("%s: quiz q%d has empty question text", l.ID, qi)
			}
			if len(q.Options) < 2 {
				t.Errorf("%s: quiz q%d has %d option(s) (need >=2)", l.ID, qi, len(q.Options))
			}
			if q.Answer < 0 || q.Answer >= len(q.Options) {
				t.Errorf("%s: quiz q%d answer=%d out of range [0,%d)", l.ID, qi, q.Answer, len(q.Options))
			}
			// unquote() strips only the outer quotes and does NOT unescape
			// backslashes, so a source `\"` leaks literally into visible text.
			if strings.Contains(q.Question, `\"`) || strings.Contains(q.Question, `\'`) {
				t.Errorf("%s: quiz q%d question leaks a backslash-escaped quote: %q", l.ID, qi, q.Question)
			}
			if m, bad := hasLegacyMarker(q.Question); bad {
				t.Errorf("%s: quiz q%d question contains legacy marker %q: %q", l.ID, qi, m, q.Question)
			}
			for oi, o := range q.Options {
				if strings.TrimSpace(o) == "" {
					t.Errorf("%s: quiz q%d option[%d] is empty", l.ID, qi, oi)
				}
				if strings.Contains(o, `\"`) || strings.Contains(o, `\'`) {
					t.Errorf("%s: quiz q%d option[%d] leaks a backslash-escaped quote: %q", l.ID, qi, oi, o)
				}
				if m, bad := hasLegacyMarker(o); bad {
					t.Errorf("%s: quiz q%d option[%d] contains legacy marker %q: %q", l.ID, qi, oi, m, o)
				}
			}
		}
		// The rendered quiz section must not re-expose the answer-revealing
		// markdown (legacy `[x]`/`Ответ:` etc.).
		for _, sec := range l.Sections {
			if !isQuizSection(sec.Title) {
				continue
			}
			if m, bad := hasLegacyMarker(sec.Markdown); bad {
				t.Errorf("%s: rendered quiz section %q still exposes legacy marker %q", l.ID, sec.Title, m)
			}
		}
		checked++
	}
	t.Logf("quiz integrity OK for %d lessons", checked)
}

// TestContentUniqueIDsAndParentsResolve asserts the invariants the tree UI
// depends on, using BOTH the raw files (to detect duplicate ids that the loader
// would silently overwrite in its id-keyed map) and the real loader (to detect
// silently skipped files).
func TestContentUniqueIDsAndParentsResolve(t *testing.T) {
	root := contentRoot(t)
	files := walkLessonFiles(t, root)
	if len(files) == 0 {
		t.Fatalf("no lesson files under %s", root)
	}

	ids := map[string]string{} // id -> file that declared it
	type parentRef struct{ file, parent string }
	var refs []parentRef

	for _, p := range files {
		l, err := parseLesson(mustRead(t, p), p)
		if err != nil {
			t.Errorf("%s: parse error: %v", p, err)
			continue
		}
		if l.ID == "" {
			t.Errorf("%s: empty lesson id", p)
			continue
		}
		if prev, dup := ids[l.ID]; dup {
			t.Errorf("duplicate lesson id %q: %s and %s", l.ID, prev, p)
		} else {
			ids[l.ID] = p
		}
		refs = append(refs, parentRef{p, l.Parent})
	}

	for _, r := range refs {
		if r.parent == "" {
			continue
		}
		if _, ok := ids[r.parent]; !ok {
			t.Errorf("%s: parent %q does not resolve to an existing lesson id", r.file, r.parent)
		}
	}

	// The loader keys lessons by id, so a duplicate collapses two files into
	// one. Its count must therefore equal the number of distinct ids.
	store := NewStore(root)
	if err := store.Load(); err != nil {
		t.Fatalf("load %s: %v", root, err)
	}
	if got := len(store.All()); got != len(ids) {
		t.Errorf("loader loaded %d lessons, but %d distinct ids exist across %d files (silent skip or duplicate id)", got, len(ids), len(files))
	}
	t.Logf("validated %d lesson files, %d distinct ids, all parents resolve", len(files), len(ids))
}

// --- lab front-matter block ------------------------------------------------

func TestParseLabBlock(t *testing.T) {
	raw := strings.Join([]string{
		"id: forensics-file-magic",
		"title: \"Магия байтов\"",
		"tags: [file, hex]",
		"useful_for:",
		"  - CTF",
		"lab:",
		"  kind: shell",
		"  title: \"Практика: разбор файла\"",
		"  toolset: [core, grep, hex]",
		"  workdir: /home/student/task",
		"  files: [task.md, evidence.dat]",
		"  check: \"grep -q 'nto{' found.txt\"",
		"  hints:",
		"    - \"Сначала посмотри тип файла\"",
		"    - \"Загляни внутрь через strings\"",
		"difficulty: beginner",
	}, "\n")

	fm := parseSimpleYAML(strings.Split(raw, "\n"))

	// A nested block must not pollute the top-level list keys around it.
	if got := getList(fm, "tags"); !reflect.DeepEqual(got, []string{"file", "hex"}) {
		t.Errorf("tags = %v", got)
	}
	if got := getList(fm, "useful_for"); !reflect.DeepEqual(got, []string{"CTF"}) {
		t.Errorf("useful_for = %v", got)
	}
	if got := getString(fm, "difficulty"); got != "beginner" {
		t.Errorf("difficulty after lab block = %q (block swallowed following keys?)", got)
	}

	lab := getLab(fm, "lab")
	if lab == nil {
		t.Fatal("lab block not parsed")
	}
	if lab.Kind != "shell" {
		t.Errorf("kind = %q", lab.Kind)
	}
	if lab.Title != "Практика: разбор файла" {
		t.Errorf("title = %q", lab.Title)
	}
	if !reflect.DeepEqual(lab.Toolset, []string{"core", "grep", "hex"}) {
		t.Errorf("toolset = %v", lab.Toolset)
	}
	if lab.Workdir != "/home/student/task" {
		t.Errorf("workdir = %q", lab.Workdir)
	}
	if !reflect.DeepEqual(lab.Files, []string{"task.md", "evidence.dat"}) {
		t.Errorf("files = %v", lab.Files)
	}
	if lab.Check != "grep -q 'nto{' found.txt" {
		t.Errorf("check = %q", lab.Check)
	}
	if !reflect.DeepEqual(lab.Hints, []string{"Сначала посмотри тип файла", "Загляни внутрь через strings"}) {
		t.Errorf("hints = %v", lab.Hints)
	}
}

func TestParseLabBlockAbsent(t *testing.T) {
	fm := parseSimpleYAML(strings.Split("id: web-sqli\ntags: [sqli]", "\n"))
	if lab := getLab(fm, "lab"); lab != nil {
		t.Errorf("expected no lab, got %#v", lab)
	}
}

func TestParseLessonWithLab(t *testing.T) {
	raw := strings.Join([]string{
		"---",
		"id: forensics-file-magic",
		"title: \"Магия байтов\"",
		"lab:",
		"  kind: shell",
		"  workdir: /home/student/task",
		"  check: \"grep -q nto{ flag.txt\"",
		"---",
		"## Введение",
		"текст",
	}, "\n")

	l, err := parseLesson(raw, "/x/forensics/02-file-magic.md")
	if err != nil {
		t.Fatalf("parseLesson: %v", err)
	}
	if l.Lab == nil {
		t.Fatal("lesson.Lab is nil")
	}
	if l.Lab.Kind != "shell" || l.Lab.Workdir != "/home/student/task" {
		t.Errorf("lab = %#v", l.Lab)
	}
}

// --- waystone gates ---------------------------------------------------------

func TestGetBool(t *testing.T) {
	m := map[string]any{"t": "true", "y": "yes", "one": "1", "f": "false", "b": true}
	for _, k := range []string{"t", "y", "one", "b"} {
		if !getBool(m, k) {
			t.Errorf("getBool(%q) = false, want true", k)
		}
	}
	for _, k := range []string{"f", "missing"} {
		if getBool(m, k) {
			t.Errorf("getBool(%q) = true, want false", k)
		}
	}
}

func TestParseLessonWaystone(t *testing.T) {
	raw := strings.Join([]string{
		"---",
		"id: network-waystone-demo",
		"title: \"Вейстоун\"",
		"category: network",
		"waystone: true",
		"waystone_tasks: [a, b, c, d, e]",
		"---",
		"## Введение",
		"текст",
	}, "\n")
	l, err := parseLesson(raw, "content/network/network-waystone-demo.md")
	if err != nil {
		t.Fatal(err)
	}
	if !l.Waystone {
		t.Error("Waystone = false, want true")
	}
	want := []string{"a", "b", "c", "d", "e"}
	if !reflect.DeepEqual(l.WaystoneTasks, want) {
		t.Errorf("WaystoneTasks = %v, want %v", l.WaystoneTasks, want)
	}
}

func TestParseLessonNotWaystoneByDefault(t *testing.T) {
	l, err := parseLesson("---\nid: plain\n---\nbody\n", "content/web/plain.md")
	if err != nil {
		t.Fatal(err)
	}
	if l.Waystone || len(l.WaystoneTasks) != 0 {
		t.Errorf("default lesson must not be a waystone: %v %v", l.Waystone, l.WaystoneTasks)
	}
}

func TestBuildTreeCarriesWaystone(t *testing.T) {
	gate := &model.Lesson{LessonMeta: model.LessonMeta{
		ID: "g", Title: "Gate", Category: "network", Waystone: true,
		WaystoneTasks: []string{"t1", "t2"},
	}}
	child := &model.Lesson{LessonMeta: model.LessonMeta{ID: "c", Title: "Child", Category: "network", Parent: "g"}}
	_, nodes := buildTree(map[string]*model.Lesson{"g": gate, "c": child})
	if nodes["g"] == nil || !nodes["g"].Waystone {
		t.Fatalf("gate node lost its waystone flag: %#v", nodes["g"])
	}
	if got := nodes["g"].WaystoneTasks; !reflect.DeepEqual(got, []string{"t1", "t2"}) {
		t.Errorf("gate node tasks = %v", got)
	}
	if nodes["c"].Waystone {
		t.Error("child node must not be a waystone")
	}
}

func TestSplitInlineList(t *testing.T) {
	got := splitInlineList(`[core, "a, b", grep]`)
	want := []string{"core", "a, b", "grep"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("splitInlineList = %v, want %v", got, want)
	}
	if got := splitInlineList("[]"); got != nil {
		t.Errorf("empty list = %v", got)
	}
}

func TestLabBundle(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "labs"), 0o755); err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"id":"demo","tools":{}}`)
	if err := os.WriteFile(filepath.Join(dir, "labs", "demo.json"), body, 0o644); err != nil {
		t.Fatal(err)
	}
	s := NewStore(dir)
	if b, ok := s.LabBundle("demo"); !ok || string(b) != string(body) {
		t.Errorf("LabBundle(demo) = %q, %v", b, ok)
	}
	if _, ok := s.LabBundle("missing"); ok {
		t.Error("LabBundle(missing) should be false")
	}
	// Path traversal ids must be rejected outright.
	for _, bad := range []string{"../secret", "a/b", ".env", "x.json"} {
		if _, ok := s.LabBundle(bad); ok {
			t.Errorf("LabBundle(%q) should be rejected", bad)
		}
	}
}

// TestContentLabsValid runs the real loader over ./content and asserts that
// every lesson carrying a `lab:` block references an existing, well-formed
// fixture bundle. This is the CI counterpart of tools/labvalidate.
func TestContentLabsValid(t *testing.T) {
	root := contentRoot(t)
	store := NewStore(root)
	if err := store.Load(); err != nil {
		t.Fatalf("load %s: %v", root, err)
	}

	type seed struct {
		Path string `json:"path"`
		Type string `json:"type"`
		Text *string `json:"text"`
		B64  *string `json:"b64"`
	}
	type toolCase struct {
		Match  string `json:"match"`
		Output string `json:"output"`
	}
	type bundle struct {
		ID      string                 `json:"id"`
		Workdir string                 `json:"workdir"`
		FS      []seed                 `json:"fs"`
		Tools   map[string]struct {
			Help  string     `json:"help"`
			Cases []toolCase `json:"cases"`
		} `json:"tools"`
	}

	withLab := 0
	for _, l := range store.All() {
		if l.Lab == nil {
			continue
		}
		withLab++
		lab := l.Lab
		if lab.Kind != "shell" {
			t.Errorf("%s: unsupported lab kind %q", l.ID, lab.Kind)
		}
		if !strings.HasPrefix(lab.Workdir, "/") {
			t.Errorf("%s: lab workdir %q must be absolute", l.ID, lab.Workdir)
		}
		if strings.TrimSpace(lab.Check) == "" {
			t.Errorf("%s: lab has no check predicate", l.ID)
		}
		if len(lab.Hints) == 0 {
			t.Errorf("%s: lab has no hints", l.ID)
		}

		bundleID := lab.Bundle
		if bundleID == "" {
			bundleID = l.ID
		}
		raw, ok := store.LabBundle(bundleID)
		if !ok {
			t.Errorf("%s: lab bundle %q missing (content/labs/%s.json)", l.ID, bundleID, bundleID)
			continue
		}
		var b bundle
		if err := json.Unmarshal(raw, &b); err != nil {
			t.Errorf("%s: lab bundle %q is not valid JSON: %v", l.ID, bundleID, err)
			continue
		}
		if b.ID != "" && b.ID != bundleID {
			t.Errorf("%s: bundle id %q != %q", l.ID, b.ID, bundleID)
		}
		seeded := map[string]bool{}
		for i, s := range b.FS {
			if s.Path == "" {
				t.Errorf("%s: bundle fs[%d] has no path", l.ID, i)
				continue
			}
			if s.Type != "dir" && s.Text == nil && s.B64 == nil {
				t.Errorf("%s: bundle fs[%d] %q has neither text nor b64", l.ID, i, s.Path)
			}
			seeded[s.Path] = true
		}
		for _, f := range lab.Files {
			if !seeded[f] && !seeded[filepath.ToSlash(filepath.Join(lab.Workdir, f))] {
				t.Errorf("%s: declared file %q is not seeded by the bundle", l.ID, f)
			}
		}
		for name, tool := range b.Tools {
			if strings.TrimSpace(tool.Help) == "" {
				t.Errorf("%s: tool %q has no help", l.ID, name)
			}
			for i, c := range tool.Cases {
				if strings.TrimSpace(c.Match) == "" || strings.TrimSpace(c.Output) == "" {
					t.Errorf("%s: tool %q case #%d is incomplete", l.ID, name, i+1)
				}
			}
		}
	}
	t.Logf("validated %d lab(s) against their fixture bundles", withLab)
}
