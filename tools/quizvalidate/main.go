// Command quizvalidate runs the REAL content loader (internal/content) over the
// learning-tree content directory and reports, per category, how many lessons
// carry a valid interactive quiz.
//
// A lesson is "broken" when it has a "## Квиз" section but the parsed Quiz is
// empty, has fewer than 3 questions, or any question is malformed (empty text,
// <2 options, out-of-range answer). It also flags source-level defect classes:
// backslash-escaped inner quotes leaking into parsed text, and leftover legacy
// answer markers.
//
// Usage: go run ./tools/quizvalidate [-content ./content] [-json]
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"learningtree/internal/content"
	"learningtree/internal/model"
)

type qIssue struct {
	Lesson string `json:"lesson"`
	Slug   string `json:"slug"`
	Kind   string `json:"kind"`
	Detail string `json:"detail"`
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
	lessons := store.All()

	// Aggregate per category.
	type stat struct {
		Total   int
		WithQ   int
		Broken  int
		NoQuiz  int // has "## Квиз" section but parsed Quiz empty
		LowQuiz int // parsed Quiz with <3 questions
	}
	stats := map[string]*stat{}
	catOf := func(l *model.Lesson) string {
		if l.Category == "" {
			return "(none)"
		}
		return l.Category
	}

	var issues []qIssue
	brokenLessons := map[string]bool{}

	for _, l := range lessons {
		c := catOf(l)
		if stats[c] == nil {
			stats[c] = &stat{}
		}
		s := stats[c]
		s.Total++

		hasQuizSection := false
		for _, sec := range l.Sections {
			if strings.Contains(strings.ToLower(sec.Title), "квиз") || strings.Contains(strings.ToLower(sec.Title), "quiz") {
				hasQuizSection = true
			}
		}

		if len(l.Quiz) > 0 {
			s.WithQ++
		}

		if hasQuizSection && len(l.Quiz) == 0 {
			brokenLessons[l.ID] = true
			s.NoQuiz++
			issues = append(issues, qIssue{l.ID, l.Slug, "empty_quiz", "## Квиз section present but parsed Quiz is empty"})
		} else if hasQuizSection && len(l.Quiz) < 3 {
			brokenLessons[l.ID] = true
			s.LowQuiz++
			issues = append(issues, qIssue{l.ID, l.Slug, "low_question_count", fmt.Sprintf("only %d parsed question(s)", len(l.Quiz))})
		}

		for qi, q := range l.Quiz {
			if strings.TrimSpace(q.Question) == "" {
				brokenLessons[l.ID] = true
				issues = append(issues, qIssue{l.ID, l.Slug, "empty_question", fmt.Sprintf("q%d", qi+1)})
			}
			if len(q.Options) < 2 {
				brokenLessons[l.ID] = true
				issues = append(issues, qIssue{l.ID, l.Slug, "too_few_options", fmt.Sprintf("q%d has %d option(s)", qi+1, len(q.Options))})
			}
			if q.Answer < 0 || q.Answer >= len(q.Options) {
				brokenLessons[l.ID] = true
				issues = append(issues, qIssue{l.ID, l.Slug, "answer_out_of_range", fmt.Sprintf("q%d answer=%d options=%d", qi+1, q.Answer, len(q.Options))})
			}
			// Defect: backslash-escaped inner quote leaked into text. The Go
			// unquote() only strips the outer quotes and does NOT unescape, so a
			// source `\"` becomes a literal backslash+quote in the visible text.
			// Plain backslashes in code (\x00, regex \d) are legitimate.
			checkLeak := func(field, v string) {
				if strings.Contains(v, `\"`) || strings.Contains(v, `\'`) {
					brokenLessons[l.ID] = true
					issues = append(issues, qIssue{l.ID, l.Slug, "escaped_quote_leak", fmt.Sprintf("q%d %s=%q", qi+1, field, v)})
				}
			}
			checkLeak("question", q.Question)
			for oi, o := range q.Options {
				checkLeak(fmt.Sprintf("option[%d]", oi), o)
			}
			// Defect: legacy answer markers left in visible option text.
			for oi, o := range q.Options {
				if strings.Contains(o, "[x]") || strings.Contains(o, "[ ]") ||
					strings.Contains(o, "(верно)") || strings.Contains(o, "✅") ||
					strings.Contains(strings.ToLower(o), "правильный ответ") {
					brokenLessons[l.ID] = true
					issues = append(issues, qIssue{l.ID, l.Slug, "legacy_marker", fmt.Sprintf("q%d option[%d]=%q", qi+1, oi, o)})
				}
			}
			if strings.Contains(q.Question, "[x]") || strings.Contains(q.Question, "[ ]") {
				brokenLessons[l.ID] = true
				issues = append(issues, qIssue{l.ID, l.Slug, "legacy_marker", fmt.Sprintf("q%d question=%q", qi+1, q.Question)})
			}
		}
	}

	// Recompute per-category broken counts from the authoritative set.
	for _, l := range lessons {
		if brokenLessons[l.ID] {
			stats[catOf(l)].Broken++
		}
	}

	var cats []string
	for c := range stats {
		cats = append(cats, c)
	}
	sort.Strings(cats)

	totalLessons, totalWithQ, totalBroken := 0, 0, 0
	for _, c := range cats {
		totalLessons += stats[c].Total
		totalWithQ += stats[c].WithQ
		totalBroken += stats[c].Broken
	}

	if *asJSON {
		perLesson := make([]map[string]any, 0, len(lessons))
		for _, l := range lessons {
			perLesson = append(perLesson, map[string]any{
				"id":        l.ID,
				"category":  catOf(l),
				"questions": len(l.Quiz),
			})
		}
		out := map[string]any{
			"lessons":    totalLessons,
			"with_quiz":  totalWithQ,
			"broken":     totalBroken,
			"issues":     issues,
			"per_lesson": perLesson,
			"per_category": func() map[string]any {
				m := map[string]any{}
				for _, c := range cats {
					s := stats[c]
					m[c] = map[string]int{"total": s.Total, "with_quiz": s.WithQ, "broken": s.Broken, "empty_quiz": s.NoQuiz, "low_quiz": s.LowQuiz}
				}
				return m
			}(),
		}
		b, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(b))
	} else {
		fmt.Printf("%-12s %6s %9s %7s %7s %7s\n", "CATEGORY", "TOTAL", "WITH_QUIZ", "BROKEN", "EMPTY", "LOW")
		for _, c := range cats {
			s := stats[c]
			fmt.Printf("%-12s %6d %9d %7d %7d %7d\n", c, s.Total, s.WithQ, s.Broken, s.NoQuiz, s.LowQuiz)
		}
		fmt.Printf("%-12s %6d %9d %7d\n", "TOTAL", totalLessons, totalWithQ, totalBroken)
		if len(issues) > 0 {
			fmt.Println("\nISSUES:")
			for _, is := range issues {
				fmt.Printf("  [%s] %s (%s): %s\n", is.Kind, is.Lesson, is.Slug, is.Detail)
			}
		}
	}

	if totalBroken > 0 {
		os.Exit(1)
	}
}
