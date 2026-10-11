// Package content loads markdown lessons from disk, parses their YAML
// front-matter and splits each lesson into readable sections.
package content

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"learningtree/internal/model"
)

// CategoryMeta describes the built-in categories (trunk branches).
type CategoryMeta struct {
	Name        string
	Color       string
	Icon        string
	Description string
}

// Categories is the ordered catalogue of top-level branches.
var Categories = []struct {
	Slug string
	CategoryMeta
}{
	{"web", CategoryMeta{"Web Exploitation", "#38bdf8", "🌐", "Веб-приложения, API, OWASP Top 10, инъекции и логические дыры."}},
	{"crypto", CategoryMeta{"Cryptography", "#a78bfa", "🔐", "Классические и современные шифры, атаки на RSA, AES, хэши, PRNG."}},
	{"pwn", CategoryMeta{"Binary Exploitation", "#f472b6", "💥", "Переполнения, ROP, heap, форматные строки, обход защит бинарников."}},
	{"reversing", CategoryMeta{"Reverse Engineering", "#fb923c", "🔎", "Дизассемблирование, декомпиляция, анализ протоколов и обфускации."}},
	{"forensics", CategoryMeta{"Forensics", "#34d399", "🧪", "Файловые системы, память, логи, артефакты ОС, стеганография контейнеров."}},
	{"osint", CategoryMeta{"OSINT & Recon", "#fbbf24", "🛰️", "Разведка по открытым источникам, метаданные, геолокация, корреляция."}},
	{"stego", CategoryMeta{"Steganography", "#22d3ee", "🖼️", "Скрытие данных в изображениях, аудио, тексте, сетевых протоколах."}},
	{"network", CategoryMeta{"Network", "#60a5fa", "📡", "Протоколы, перехват трафика, MITM, туннели, анализ PCAP."}},
	{"cloud", CategoryMeta{"Cloud", "#818cf8", "☁️", "AWS/GCP/Azure, IAM, метаданные, контейнеры, k8s, supply chain."}},
	{"mobile", CategoryMeta{"Mobile", "#2dd4bf", "📱", "Android/iOS, реверс APK/IPA, Frida, обход проверок."}},
	{"hardware", CategoryMeta{"Hardware & IoT", "#f87171", "🔌", "UART/JTAG/SPI, прошивки, радиоканал, firmware extraction."}},
	{"misc", CategoryMeta{"Misc & Programming", "#94a3b8", "🎲", "Задачи на смекалку, скриптинг, эзотерические языки, головоломки."}},
}

func categoryMetaFor(slug string) CategoryMeta {
	for _, c := range Categories {
		if c.Slug == slug {
			return c.CategoryMeta
		}
	}
	return CategoryMeta{Name: slug, Color: "#94a3b8", Icon: "📁", Description: ""}
}

// Store holds all loaded lessons and the derived tree. It is safe for
// concurrent use and hot-reloads when files change on disk.
type Store struct {
	dir string

	mu       sync.RWMutex
	lessons  map[string]*model.Lesson
	bySlug   map[string]*model.Lesson
	roots    []*model.TreeNode
	nodes    map[string]*model.TreeNode
	loadedAt time.Time
	maxMod   time.Time
}

// NewStore returns a store rooted at dir (not yet loaded).
func NewStore(dir string) *Store {
	return &Store{dir: dir, lessons: map[string]*model.Lesson{}, bySlug: map[string]*model.Lesson{}, nodes: map[string]*model.TreeNode{}}
}

// Dir returns the content directory.
func (s *Store) Dir() string { return s.dir }

// Load (re)reads every markdown file under the content directory.
func (s *Store) Load() error {
	lessons := map[string]*model.Lesson{}
	bySlug := map[string]*model.Lesson{}
	var maxMod time.Time

	walkErr := filepath.WalkDir(s.dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if (strings.HasPrefix(d.Name(), ".") || strings.HasPrefix(d.Name(), "_")) && p != s.dir {
				return filepath.SkipDir
			}
			return nil
		}
		// Файлы/каталоги с префиксом "." или "_" служебные (например,
		// content/_template.md — скелет урока) и в дерево не попадают.
		if strings.HasPrefix(d.Name(), ".") || strings.HasPrefix(d.Name(), "_") {
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".md") && !strings.HasSuffix(d.Name(), ".markdown") {
			return nil
		}
		info, ierr := d.Info()
		if ierr == nil && info.ModTime().After(maxMod) {
			maxMod = info.ModTime()
		}
		raw, rerr := os.ReadFile(p)
		if rerr != nil {
			return nil
		}
		l, perr := parseLesson(string(raw), p)
		if perr != nil {
			fmt.Fprintf(os.Stderr, "[content] skip %s: %v\n", p, perr)
			return nil
		}
		lessons[l.ID] = l
		if l.Slug != "" {
			bySlug[l.Slug] = l
		}
		return nil
	})
	if walkErr != nil && !errors.Is(walkErr, fs.ErrNotExist) {
		return walkErr
	}

	roots, nodes := buildTree(lessons)

	s.mu.Lock()
	s.lessons = lessons
	s.bySlug = bySlug
	s.roots = roots
	s.nodes = nodes
	s.loadedAt = time.Now()
	s.maxMod = maxMod
	s.mu.Unlock()
	return nil
}

// maybeReload re-reads content if any file changed since the last load.
func (s *Store) maybeReload() {
	s.mu.RLock()
	last := s.maxMod
	s.mu.RUnlock()

	var newest time.Time
	_ = filepath.WalkDir(s.dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".md") {
			return nil
		}
		if info, ierr := d.Info(); ierr == nil && info.ModTime().After(newest) {
			newest = info.ModTime()
		}
		return nil
	})
	if newest.After(last) {
		_ = s.Load()
	}
}

// Lesson returns a full lesson by id or slug.
func (s *Store) Lesson(id string) (*model.Lesson, bool) {
	s.maybeReload()
	s.mu.RLock()
	defer s.mu.RUnlock()
	if l, ok := s.lessons[id]; ok {
		return l, true
	}
	if l, ok := s.bySlug[id]; ok {
		return l, true
	}
	return nil, false
}

// All returns every lesson (unordered).
func (s *Store) All() []*model.Lesson {
	s.maybeReload()
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*model.Lesson, 0, len(s.lessons))
	for _, l := range s.lessons {
		out = append(out, l)
	}
	return out
}

// Tree returns the categories plus every node (flat, with parent links).
func (s *Store) Tree() model.TreeResponse {
	s.maybeReload()
	s.mu.RLock()
	defer s.mu.RUnlock()

	counts := map[string]int{}
	nodes := make([]*model.TreeNode, 0, len(s.nodes))
	for _, n := range s.nodes {
		counts[n.Category]++
		nodes = append(nodes, n)
	}
	sort.Slice(nodes, func(i, j int) bool {
		if nodes[i].Category != nodes[j].Category {
			return nodes[i].Category < nodes[j].Category
		}
		if nodes[i].Depth != nodes[j].Depth {
			return nodes[i].Depth < nodes[j].Depth
		}
		if nodes[i].Order != nodes[j].Order {
			return nodes[i].Order < nodes[j].Order
		}
		return nodes[i].Title < nodes[j].Title
	})

	var cats []model.Category
	for _, c := range Categories {
		cats = append(cats, model.Category{
			Slug: c.Slug, Name: c.Name, Color: c.Color, Icon: c.Icon,
			Description: c.Description, Count: counts[c.Slug],
		})
	}
	return model.TreeResponse{Categories: cats, Nodes: nodes, Total: len(nodes)}
}

// Roots returns the top-level nodes.
func (s *Store) Roots() []*model.TreeNode {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.roots
}

// Search performs a simple case-insensitive search over title/tags/summary/body.
func (s *Store) Search(q string) []map[string]any {
	q = strings.ToLower(strings.TrimSpace(q))
	if q == "" {
		return nil
	}
	s.maybeReload()
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []map[string]any
	for _, l := range s.lessons {
		var score int
		lt := strings.ToLower(l.Title)
		if strings.Contains(lt, q) {
			score += 10
		}
		for _, t := range l.Tags {
			if strings.Contains(strings.ToLower(t), q) {
				score += 6
			}
		}
		if strings.Contains(strings.ToLower(l.Summary), q) {
			score += 4
		}
		snippet := ""
		for _, sec := range l.Sections {
			if idx := strings.Index(strings.ToLower(sec.Markdown), q); idx >= 0 {
				score += 2
				if snippet == "" {
					snippet = excerpt(sec.Markdown, idx, q)
				}
			}
		}
		if score == 0 {
			continue
		}
		out = append(out, map[string]any{
			"id": l.ID, "title": l.Title, "category": l.Category,
			"difficulty": l.Difficulty, "summary": l.Summary,
			"score": score, "snippet": snippet,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i]["score"].(int) > out[j]["score"].(int)
	})
	if len(out) > 60 {
		out = out[:60]
	}
	return out
}

func excerpt(s string, idx int, q string) string {
	start := idx - 60
	if start < 0 {
		start = 0
	}
	end := idx + len(q) + 60
	if end > len(s) {
		end = len(s)
	}
	return strings.TrimSpace(strings.ReplaceAll(s[start:end], "\n", " "))
}

// --- parsing helpers -------------------------------------------------------

func parseLesson(raw, path string) (*model.Lesson, error) {
	fm, body := splitFrontmatter(raw)

	id := getString(fm, "id")
	if id == "" {
		id = strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	}
	title := getString(fm, "title")
	if title == "" {
		title = id
	}
	cat := getString(fm, "category")
	if cat == "" {
		// fall back to the first path segment under content/
		parts := strings.Split(filepath.ToSlash(path), "/")
		for i, p := range parts {
			if p == "content" && i+1 < len(parts)-1 {
				cat = parts[i+1]
				break
			}
		}
	}
	if cat == "" {
		cat = "misc"
	}
	diff := strings.ToLower(getString(fm, "difficulty"))
	if _, ok := model.DifficultyOrder[diff]; !ok {
		diff = "medium"
	}

	l := &model.Lesson{
		LessonMeta: model.LessonMeta{
			ID:               id,
			Title:            title,
			Category:         cat,
			Parent:           getString(fm, "parent"),
			Difficulty:       diff,
			Order:            getInt(fm, "order"),
			Tags:             getList(fm, "tags"),
			Prerequisites:    getList(fm, "prerequisites"),
			UsefulFor:        getList(fm, "useful_for"),
			EstimatedMinutes: getInt(fm, "estimated_minutes"),
			Summary:          getString(fm, "summary"),
			Author:           getString(fm, "author"),
		},
	}
	l.Slug = id
	l.Sections = splitSections(body)
	// Извлекаем интерактивный квиз из секций: либо из явного блока ```quiz,
	// либо из обычной секции "## Квиз" (основной формат контента). Ответы
	// уходят в структуру Lesson.Quiz и не показываются читателю до проверки.
	for i := range l.Sections {
		if q, cleaned, ok := extractQuizBlock(l.Sections[i].Markdown); ok {
			l.Quiz = append(l.Quiz, q...)
			l.Sections[i].Markdown = cleaned
			l.Sections[i].Words = countWords(cleaned)
			continue
		}
		if isQuizSection(l.Sections[i].Title) {
			if q := parseQuizMarkdown(l.Sections[i].Markdown); len(q) > 0 {
				l.Quiz = append(l.Quiz, q...)
				// Скрываем исходный текст с ответами — рендерится интерактивный квиз.
				l.Sections[i].Markdown = ""
				l.Sections[i].Words = 0
			}
		}
	}
	total := 0
	for _, s := range l.Sections {
		total += s.Words
	}
	l.Words = total
	if l.EstimatedMinutes == 0 {
		l.EstimatedMinutes = total/180 + 2
	}
	return l, nil
}

// extractQuizBlock finds a fenced ```quiz block, parses it into questions and
// returns the markdown with that block removed. The block format is a small
// YAML list:
//
//   - question: "..."
//     options:
//   - "..."
//   - "..."
//     answer: 1            # 0-based index, or a letter (A/B/C...)
//     explanation: "..."   # optional
func extractQuizBlock(md string) ([]model.QuizQuestion, string, bool) {
	lines := strings.Split(md, "\n")
	start, end := -1, -1
	for i, ln := range lines {
		t := strings.TrimSpace(ln)
		if start == -1 && (t == "```quiz" || t == "```quiz " || strings.HasPrefix(t, "```quiz")) {
			start = i
			continue
		}
		if start != -1 && t == "```" {
			end = i
			break
		}
	}
	if start == -1 || end == -1 {
		return nil, md, false
	}
	block := strings.Join(lines[start+1:end], "\n")
	qs := parseQuizYAML(block)
	cleaned := strings.Join(append(append([]string{}, lines[:start]...), lines[end+1:]...), "\n")
	return qs, cleaned, len(qs) > 0
}

func parseQuizYAML(block string) []model.QuizQuestion {
	var out []model.QuizQuestion
	var cur *model.QuizQuestion
	inOptions := false

	// stripBullet removes a leading "- " and an optional "[x]"/"[ ]" checkbox,
	// returning the remainder and whether the box was ticked.
	stripBullet := func(s string) (string, bool) {
		if !strings.HasPrefix(s, "- ") {
			return s, false
		}
		s = strings.TrimSpace(s[2:])
		if m := quizCheckboxRe.FindStringSubmatch(s); m != nil {
			return strings.TrimSpace(m[2]), strings.EqualFold(m[1], "x")
		}
		return s, false
	}

	for _, raw := range strings.Split(block, "\n") {
		if strings.TrimSpace(raw) == "" || strings.HasPrefix(strings.TrimSpace(raw), "#") {
			continue
		}
		trimmed := strings.TrimSpace(raw)
		indent := len(raw) - len(strings.TrimLeft(raw, " "))

		// Bullet lines: either the start of a new question ("- question:" /
		// "- [x] question:") or an option ("- \"...\"" / "- [ ] \"...\"").
		if strings.HasPrefix(trimmed, "- ") {
			body, ticked := stripBullet(trimmed)
			if strings.HasPrefix(body, "question:") || strings.HasPrefix(body, "q:") {
				if cur != nil && len(cur.Options) > 0 {
					out = append(out, *cur)
				}
				cur = &model.QuizQuestion{Answer: -1}
				inOptions = false
				if i := strings.Index(body, ":"); i != -1 {
					cur.Question = unquote(strings.TrimSpace(body[i+1:]))
				}
				continue
			}
			if cur != nil && inOptions {
				cur.Options = append(cur.Options, unquote(body))
				if ticked {
					cur.Answer = len(cur.Options) - 1
				}
			}
			continue
		}
		if cur == nil {
			continue
		}

		switch {
		case strings.HasPrefix(trimmed, "options:"):
			inOptions = true
		case strings.HasPrefix(trimmed, "answer:"):
			inOptions = false
			v := unquote(strings.TrimSpace(strings.TrimPrefix(trimmed, "answer:")))
			cur.Answer = parseAnswer(v)
		case strings.HasPrefix(trimmed, "explanation:"):
			inOptions = false
			cur.Explanation = unquote(strings.TrimSpace(strings.TrimPrefix(trimmed, "explanation:")))
		case strings.HasPrefix(trimmed, "question:") || strings.HasPrefix(trimmed, "q:"):
			inOptions = false
			i := strings.Index(trimmed, ":")
			cur.Question = unquote(strings.TrimSpace(trimmed[i+1:]))
		case indent > 0 && inOptions && len(cur.Options) > 0:
			// продолжение строки варианта
			last := len(cur.Options) - 1
			cur.Options[last] += " " + unquote(trimmed)
		}
	}
	if cur != nil && len(cur.Options) > 0 {
		out = append(out, *cur)
	}
	// Отбрасываем невалидные вопросы.
	valid := out[:0]
	for _, q := range out {
		if q.Question != "" && len(q.Options) >= 2 && q.Answer >= 0 && q.Answer < len(q.Options) {
			valid = append(valid, q)
		}
	}
	return valid
}

// parseAnswer accepts a 0-based index ("1"), a 1-based number, or a letter.
func parseAnswer(v string) int {
	v = strings.TrimSpace(v)
	if v == "" {
		return -1
	}
	if n, err := strconv.Atoi(v); err == nil {
		return n
	}
	r := []rune(strings.ToUpper(v))[0]
	if r >= 'A' && r <= 'Z' {
		return int(r - 'A')
	}
	if r >= 'А' && r <= 'Я' { // кириллица А, Б, В...
		return int(r - 'А')
	}
	return -1
}

// --- quiz section parsing --------------------------------------------------
//
// Lessons authored for the learning tree carry their interactive quiz inside a
// regular "## Квиз" section (see CONTENT_FORMAT.md). The formats accepted here
// mirror what the content actually uses:
//
//	**1. Вопрос?**        /  1. Вопрос?  /  1) Вопрос?  /  Вопрос 1: ...
//	- A) вариант          /  - вариант
//
// The correct option is marked with any of: [x], a bold span (**...**),
// a (верно)/(правильно)/(correct)/(правильный ответ) suffix, ✅, a trailing +,
// or a separate "Ответ: B" / "**Ответ: B**" / "- **Правильный ответ: B**" line.
var (
	quizTitleRe     = regexp.MustCompile(`(?i)^\s*(?:квиз|quiz)`)
	quizQuestionRe  = regexp.MustCompile(`^\s*\*{0,2}\s*(\d+)\s*[.)]\s*(.+?)\s*\*{0,2}\s*$`)
	quizQuestionRe2 = regexp.MustCompile(`(?i)^\s*(?:вопрос|question)\s*(\d+)\s*[:.]\s*(.+?)\s*$`)
	quizOptionRe    = regexp.MustCompile(`^\s*[-*]\s+(.+)$`)
	quizAnswerRe    = regexp.MustCompile(`(?i)^\s*\*{0,2}\s*(?:правильный\s+ответ|ответ|answer)\s*[:—–-]\s*(.*)$`)
	quizCheckboxRe  = regexp.MustCompile(`^\s*\[([ xX])\]\s*(.*)$`)
	quizMarkerRe    = regexp.MustCompile(`(?i)\((?:правильный\s+ответ|верно|правильно|correct)\)|✅`)
	quizBoldRe      = regexp.MustCompile(`\*\*(.+?)\*\*`)
	quizPlusRe      = regexp.MustCompile(`\+\s*$`)
)

// isQuizSection reports whether a section title is the interactive quiz.
func isQuizSection(title string) bool { return quizTitleRe.MatchString(title) }

// parseQuizMarkdown parses a "## Квиз" section body into validated questions.
// Only questions with a non-empty text, at least two options and an in-range
// answer index are returned, so a malformed section yields nil.
func parseQuizMarkdown(md string) []model.QuizQuestion {
	var out []model.QuizQuestion
	var cur *model.QuizQuestion

	flush := func() {
		if cur == nil {
			return
		}
		if cur.Question != "" && len(cur.Options) >= 2 && cur.Answer >= 0 && cur.Answer < len(cur.Options) {
			out = append(out, *cur)
		}
		cur = nil
	}
	newQuestion := func(text string) {
		flush()
		cur = &model.QuizQuestion{Question: cleanQuizText(text), Answer: -1}
	}

	for _, raw := range strings.Split(md, "\n") {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		// Option (bullet) line — may also be the "Правильный ответ" declaration.
		if m := quizOptionRe.FindStringSubmatch(raw); m != nil {
			if cur == nil {
				continue
			}
			content := strings.TrimSpace(m[1])
			if am := quizAnswerRe.FindStringSubmatch(content); am != nil {
				cur.Answer = quizAnswerToken(am[1], len(cur.Options))
				if e := quizExplanation(am[1]); e != "" && cur.Explanation == "" {
					cur.Explanation = e
				}
				continue
			}
			correct := false
			if cm := quizCheckboxRe.FindStringSubmatch(content); cm != nil {
				correct = strings.EqualFold(cm[1], "x")
				content = cm[2]
			}
			if quizMarkerRe.MatchString(content) || quizBoldRe.MatchString(content) || quizPlusRe.MatchString(content) {
				correct = true
			}
			cur.Options = append(cur.Options, cleanQuizOption(content))
			if correct {
				cur.Answer = len(cur.Options) - 1
			}
			continue
		}
		// Question line.
		if m := quizQuestionRe.FindStringSubmatch(raw); m != nil {
			newQuestion(m[2])
			continue
		}
		if m := quizQuestionRe2.FindStringSubmatch(raw); m != nil {
			newQuestion(m[2])
			continue
		}
		// Standalone answer line ("Ответ: B", "**Ответ: B** — пояснение").
		if m := quizAnswerRe.FindStringSubmatch(raw); m != nil {
			if cur != nil {
				cur.Answer = quizAnswerToken(m[1], len(cur.Options))
				if e := quizExplanation(m[1]); e != "" && cur.Explanation == "" {
					cur.Explanation = e
				}
			}
			continue
		}
	}
	flush()
	return out
}

// quizAnswerToken extracts a 0-based option index from the text following an
// answer declaration. It accepts a letter (A/B/C..., Latin or Cyrillic) or a
// 1-based number.
func quizAnswerToken(raw string, n int) int {
	raw = strings.TrimSpace(strings.TrimLeft(strings.TrimSpace(raw), "*"))
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return -1
	}
	r := []rune(raw)
	i := 0
	for i < len(r) && (unicode.IsLetter(r[i]) || unicode.IsDigit(r[i])) {
		i++
	}
	tok := string(r[:i])
	if tok == "" {
		return -1
	}
	allDigits := true
	for _, c := range tok {
		if !unicode.IsDigit(c) {
			allDigits = false
			break
		}
	}
	if allDigits {
		if v, err := strconv.Atoi(tok); err == nil {
			return v - 1
		}
		return -1
	}
	c := unicode.ToUpper(r[0])
	switch {
	case c >= 'A' && c <= 'Z':
		return int(c - 'A')
	case c >= 'А' && c <= 'Я':
		return int(c - 'А')
	}
	return -1
}

// quizExplanation returns the prose that follows the answer declaration.
func quizExplanation(raw string) string {
	for _, sep := range []string{"—", "–", " - "} {
		if i := strings.Index(raw, sep); i >= 0 {
			e := strings.Trim(strings.TrimSpace(raw[i+len(sep):]), "*")
			if e = strings.TrimSpace(e); e != "" {
				return e
			}
		}
	}
	return ""
}

func cleanQuizText(s string) string {
	return strings.TrimSpace(strings.ReplaceAll(s, "**", ""))
}

func cleanQuizOption(s string) string {
	s = quizMarkerRe.ReplaceAllString(s, "")
	s = strings.ReplaceAll(s, "**", "")
	s = quizPlusRe.ReplaceAllString(s, "")
	return strings.TrimSpace(s)
}

func splitFrontmatter(raw string) (map[string]any, string) {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	lines := strings.Split(raw, "\n")
	start := -1
	for i, l := range lines {
		if strings.TrimSpace(l) == "---" {
			start = i
			break
		}
		if strings.TrimSpace(l) != "" {
			return nil, raw
		}
	}
	if start == -1 {
		return nil, raw
	}
	end := -1
	for i := start + 1; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) == "---" {
			end = i
			break
		}
	}
	if end == -1 {
		return nil, raw
	}
	fm := parseSimpleYAML(lines[start+1 : end])
	return fm, strings.Join(lines[end+1:], "\n")
}

func parseSimpleYAML(lines []string) map[string]any {
	m := map[string]any{}
	curKey := ""
	for _, ln := range lines {
		if strings.TrimSpace(ln) == "" || strings.HasPrefix(strings.TrimSpace(ln), "#") {
			continue
		}
		trimmed := strings.TrimSpace(ln)
		if strings.HasPrefix(trimmed, "- ") && curKey != "" {
			item := unquote(strings.TrimSpace(trimmed[2:]))
			arr, _ := m[curKey].([]string)
			m[curKey] = append(arr, item)
			continue
		}
		idx := strings.Index(ln, ":")
		if idx == -1 {
			continue
		}
		key := strings.TrimSpace(ln[:idx])
		val := strings.TrimSpace(ln[idx+1:])
		curKey = key
		if val == "" {
			m[key] = []string{}
			continue
		}
		if strings.HasPrefix(val, "[") && strings.HasSuffix(val, "]") {
			inner := strings.TrimSpace(val[1 : len(val)-1])
			var arr []string
			if inner != "" {
				for _, p := range strings.Split(inner, ",") {
					arr = append(arr, unquote(strings.TrimSpace(p)))
				}
			}
			m[key] = arr
			continue
		}
		m[key] = unquote(val)
	}
	return m
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

func getString(m map[string]any, k string) string {
	if v, ok := m[k].(string); ok {
		return v
	}
	return ""
}

func getInt(m map[string]any, k string) int {
	switch v := m[k].(type) {
	case string:
		n, _ := strconv.Atoi(v)
		return n
	case int:
		return v
	}
	return 0
}

func getList(m map[string]any, k string) []string {
	switch v := m[k].(type) {
	case []string:
		return v
	case string:
		if v == "" {
			return nil
		}
		return []string{v}
	}
	return nil
}

func splitSections(body string) []model.Section {
	lines := strings.Split(body, "\n")
	var secs []model.Section
	var cur strings.Builder
	curTitle := ""
	first := true

	flush := func() {
		md := strings.TrimSpace(cur.String())
		title := curTitle
		if title == "" {
			if first {
				title = "Введение"
			} else {
				title = fmt.Sprintf("Раздел %d", len(secs)+1)
			}
		}
		if md == "" {
			cur.Reset()
			first = false
			return
		}
		secs = append(secs, model.Section{
			ID:       slugify(title, len(secs)),
			Title:    title,
			Markdown: md,
			Words:    countWords(md),
		})
		cur.Reset()
		first = false
	}

	for _, ln := range lines {
		if strings.HasPrefix(ln, "## ") {
			flush()
			curTitle = strings.TrimSpace(strings.TrimPrefix(ln, "## "))
			continue
		}
		cur.WriteString(ln)
		cur.WriteString("\n")
	}
	flush()

	if len(secs) == 0 {
		md := strings.TrimSpace(body)
		if md != "" {
			secs = append(secs, model.Section{ID: "intro", Title: "Введение", Markdown: md, Words: countWords(md)})
		}
	}
	for i := range secs {
		req := secs[i].Words / 3 // ~180 wpm, 0.33 s/word
		if req < 6 {
			req = 6
		}
		if req > 150 {
			req = 150
		}
		secs[i].RequiredSeconds = req
	}
	return secs
}

func countWords(s string) int {
	n := 0
	inWord := false
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			if !inWord {
				n++
				inWord = true
			}
		} else {
			inWord = false
		}
	}
	return n
}

func slugify(s string, fallback int) string {
	var b strings.Builder
	prevDash := false
	for _, r := range strings.ToLower(s) {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			b.WriteRune(r)
			prevDash = false
		default:
			if !prevDash {
				b.WriteByte('-')
				prevDash = true
			}
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return fmt.Sprintf("sec-%d", fallback)
	}
	return out
}

// --- tree building ---------------------------------------------------------

func buildTree(lessons map[string]*model.Lesson) ([]*model.TreeNode, map[string]*model.TreeNode) {
	nodes := map[string]*model.TreeNode{}
	for id, l := range lessons {
		nodes[id] = &model.TreeNode{
			ID: l.ID, Title: l.Title, Category: l.Category, Difficulty: l.Difficulty,
			Parent: l.Parent, Order: l.Order, Sections: len(l.Sections),
			Words: l.Words, EstMinutes: l.EstimatedMinutes, Tags: l.Tags,
		}
	}
	var roots []*model.TreeNode
	for _, l := range lessons {
		n := nodes[l.ID]
		if l.Parent != "" {
			if p, ok := nodes[l.Parent]; ok && p.ID != n.ID {
				p.Children = append(p.Children, n)
				continue
			}
		}
		roots = append(roots, n)
	}
	visited := map[string]bool{}
	var assignDepth func(n *model.TreeNode, d int)
	assignDepth = func(n *model.TreeNode, d int) {
		if visited[n.ID] {
			return
		}
		visited[n.ID] = true
		n.Depth = d
		sortNodes(n.Children)
		for _, c := range n.Children {
			assignDepth(c, d+1)
		}
	}
	sortNodes(roots)
	for _, r := range roots {
		assignDepth(r, 0)
	}
	return roots, nodes
}

func sortNodes(ns []*model.TreeNode) {
	sort.SliceStable(ns, func(i, j int) bool {
		if ns[i].Order != ns[j].Order {
			return ns[i].Order < ns[j].Order
		}
		return ns[i].Title < ns[j].Title
	})
}
