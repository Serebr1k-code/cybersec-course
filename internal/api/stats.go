package api

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"learningtree/internal/content"
	"learningtree/internal/model"
	"learningtree/internal/progress"
)

// xpPerLevel is the XP needed for one level (mirrors the frontend getter).
const xpPerLevel = 500

// diffOrder is the canonical difficulty ordering (easiest → hardest).
var diffOrder = []string{"beginner", "easy", "medium", "hard", "expert"}

// diffLabels maps a difficulty key to its Russian label.
var diffLabels = map[string]string{
	"beginner": "Новичок",
	"easy":     "Легко",
	"medium":   "Средне",
	"hard":     "Сложно",
	"expert":   "Эксперт",
}

// diffIcons decorates the per-difficulty achievement badge.
var diffIcons = map[string]string{
	"beginner": "🟢",
	"easy":     "🟩",
	"medium":   "🟨",
	"hard":     "🟧",
	"expert":   "🟥",
}

func catMetaFor(slug string) (name, color, icon string) {
	for _, c := range content.Categories {
		if c.Slug == slug {
			return c.Name, c.Color, c.Icon
		}
	}
	return slug, "#94a3b8", "📁"
}

func difficultyLabel(key string) string {
	if l, ok := diffLabels[key]; ok {
		return l
	}
	if key == "" {
		return "Не указано"
	}
	return key
}

// metrics aggregates everything the achievements and the stats payload need,
// computed once from the stored progress and the loaded content catalogue.
type metrics struct {
	readLessons   int // any section read
	touched       int // any progress at all (read / quiz / notes / completed)
	completed     int
	perfect       int
	perfectBack   int // perfect quiz after at least one failed attempt
	quizAnswered  int
	quizCorrect   int
	quizAttempts  int
	quizFails     int
	notesCount    int
	totalSecs     int
	fastCompleted int
	distinctDays  int
	curStreak     int
	longestStreak int
	maxGapDays    int
	nightEvents   int
	earlyEvents   int
	level         int
	catDone       map[string]int
	catTotal      map[string]int
	catTouched    map[string]bool
	diffDone      map[string]int
	diffTotal     map[string]int
}

// lessonExpectedSeconds sums the required reading time of every section.
func lessonExpectedSeconds(l *model.Lesson) int {
	t := 0
	for _, s := range l.Sections {
		t += s.RequiredSeconds
	}
	return t
}

// activityStats derives distinct active days, the longest consecutive run and
// the biggest gap (in days) between two consecutive active days.
func activityStats(act map[string]int) (distinct, longest, maxGap int) {
	days := make([]time.Time, 0, len(act))
	for k, n := range act {
		if n <= 0 {
			continue
		}
		t, err := time.Parse("2006-01-02", k)
		if err != nil {
			continue
		}
		days = append(days, t)
	}
	if len(days) == 0 {
		return 0, 0, 0
	}
	sort.Slice(days, func(i, j int) bool { return days[i].Before(days[j]) })
	distinct = len(days)
	run, longest := 1, 1
	for i := 1; i < len(days); i++ {
		gap := int(days[i].Sub(days[i-1]).Hours() / 24)
		if gap > maxGap {
			maxGap = gap
		}
		if gap == 1 {
			run++
			if run > longest {
				longest = run
			}
		} else {
			run = 1
		}
	}
	return distinct, longest, maxGap
}

// computeMetrics walks the stored progress once and aggregates all counters.
func (s *Server) computeMetrics(u *progress.User) *metrics {
	m := &metrics{
		catDone:    map[string]int{},
		catTotal:   map[string]int{},
		catTouched: map[string]bool{},
		diffDone:   map[string]int{},
		diffTotal:  map[string]int{},
	}
	lessons := s.Content.All()
	byID := make(map[string]*model.Lesson, len(lessons)*2)
	for _, l := range lessons {
		byID[l.ID] = l
		if l.Slug != "" {
			byID[l.Slug] = l
		}
		m.catTotal[l.Category]++
		m.diffTotal[l.Difficulty]++
	}

	for id, lp := range u.Lessons {
		if lp == nil {
			continue
		}
		hasRead := false
		lessonSecs := 0
		for _, sp := range lp.Sections {
			if sp == nil {
				continue
			}
			lessonSecs += sp.ReadSeconds
			if sp.Read {
				hasRead = true
			}
		}
		m.totalSecs += lessonSecs
		if hasRead {
			m.readLessons++
		}
		l := byID[id]
		if lp.Completed {
			m.completed++
			if l != nil {
				m.catDone[l.Category]++
				m.diffDone[l.Difficulty]++
				if exp := lessonExpectedSeconds(l); exp > 0 && lessonSecs <= exp*3/2 {
					m.fastCompleted++
				}
			}
		}
		if hasRead || lp.Completed || lp.QuizAttempts > 0 || strings.TrimSpace(lp.Notes) != "" {
			m.touched++
			if l != nil {
				m.catTouched[l.Category] = true
			}
		}
		if lp.QuizTotal > 0 {
			m.quizAnswered += lp.QuizTotal
			m.quizCorrect += lp.QuizBest
			m.quizAttempts += lp.QuizAttempts
			m.quizFails += lp.QuizFails
			if lp.QuizBest == lp.QuizTotal {
				m.perfect++
				if lp.QuizFails > 0 {
					m.perfectBack++
				}
			}
		}
		if strings.TrimSpace(lp.Notes) != "" {
			m.notesCount++
		}
	}

	m.curStreak = u.Streak()
	m.distinctDays, m.longestStreak, m.maxGapDays = activityStats(u.Activity)
	for h, n := range u.Hours {
		switch {
		case h >= 0 && h < 5:
			m.nightEvents += n
		case h >= 5 && h < 8:
			m.earlyEvents += n
		}
	}
	u.ComputeXP()
	m.level = u.XP/xpPerLevel + 1
	return m
}

func accuracyPct(correct, answered int) int {
	if answered <= 0 {
		return 0
	}
	return correct * 100 / answered
}

// badge is one achievement definition (or a computed one).
type badge struct {
	id, theme, title, desc, icon string
	have, need                   int
}

func (b badge) toMap() map[string]any {
	pct := 0
	if b.need > 0 {
		pct = b.have * 100 / b.need
	}
	if pct > 100 {
		pct = 100
	}
	if pct < 0 {
		pct = 0
	}
	return map[string]any{
		"id": b.id, "theme": b.theme, "title": b.title, "desc": b.desc,
		"icon": b.icon, "unlocked": b.have >= b.need,
		"progress": pct, "have": b.have, "need": b.need,
	}
}

// achievements computes the full badge catalogue (60+) for a user.
func (s *Server) achievements(u *progress.User) []map[string]any {
	m := s.computeMetrics(u)
	total := len(s.Content.All())
	acc := accuracyPct(m.quizCorrect, m.quizAnswered)
	acc80, acc95 := 0, 0
	if m.quizAnswered >= 20 {
		acc80 = acc
	}
	if m.quizAnswered >= 50 {
		acc95 = acc
	}

	defs := []badge{
		// --- чтение (объём) ------------------------------------------------
		{"first-read", "Чтение", "Первый шаг", "Прочитать первый урок", "🌱", m.readLessons, 1},
		{"reader-5", "Чтение", "Читатель", "Прочитать 5 уроков", "📖", m.readLessons, 5},
		{"reader-15", "Чтение", "Книжный червь", "Прочитать 15 уроков", "🐛", m.readLessons, 15},
		{"reader-40", "Чтение", "Эрудит", "Прочитать 40 уроков", "🧠", m.readLessons, 40},
		{"reader-100", "Чтение", "Полиглот", "Прочитать 100 уроков", "📚", m.readLessons, 100},
		{"reader-250", "Чтение", "Ходячая энциклопедия", "Прочитать 250 уроков", "🏛️", m.readLessons, 250},
		{"explorer-50", "Чтение", "Исследователь", "Открыть 50 уроков", "🧭", m.touched, 50},
		{"explorer-200", "Чтение", "Первооткрыватель", "Открыть 200 уроков", "🗺️", m.touched, 200},

		// --- завершение ----------------------------------------------------
		{"complete-1", "Завершение", "Пройдено", "Завершить первый урок на 100%", "✅", m.completed, 1},
		{"complete-10", "Завершение", "Марафонец", "Завершить 10 уроков", "🏃", m.completed, 10},
		{"complete-25", "Завершение", "Целеустремлённый", "Завершить 25 уроков", "🏅", m.completed, 25},
		{"complete-50", "Завершение", "Полтинник", "Завершить 50 уроков", "🎖️", m.completed, 50},
		{"complete-all", "Завершение", "Властелин дерева", "Завершить все уроки", "👑", m.completed, max(total, 1)},

		// --- квизы ---------------------------------------------------------
		{"quiz-first", "Квизы", "Первый квиз", "Пройти первый квиз", "📝", m.quizAttempts, 1},
		{"quiz-perfect-1", "Квизы", "Без ошибок", "Идеально пройти квиз", "🎯", m.perfect, 1},
		{"quiz-perfect-5", "Квизы", "Отличник", "5 идеальных квизов", "🥉", m.perfect, 5},
		{"quiz-perfect-10", "Квизы", "Знаток", "10 идеальных квизов", "🥈", m.perfect, 10},
		{"quiz-perfect-25", "Квизы", "Гуру квизов", "25 идеальных квизов", "🥇", m.perfect, 25},
		{"quiz-100", "Квизы", "Сотка вопросов", "Ответить на 100 вопросов", "💯", m.quizAnswered, 100},
		{"quiz-accuracy-80", "Квизы", "Снайпер", "Точность ≥ 80% (минимум 20 вопросов)", "🎪", acc80, 80},
		{"quiz-accuracy-95", "Квизы", "Безупречный", "Точность ≥ 95% (минимум 50 вопросов)", "🧿", acc95, 95},
		{"quiz-comeback", "Квизы", "Реванш", "Идеально пройти квиз после провала", "🔁", m.perfectBack, 1},

		// --- уровни XP -----------------------------------------------------
		{"level-2", "Уровни", "Новичок+", "Достичь 2 уровня", "🔹", m.level, 2},
		{"level-5", "Уровни", "Опытный", "Достичь 5 уровня", "🔷", m.level, 5},
		{"level-10", "Уровни", "Ветеран", "Достичь 10 уровня", "💠", m.level, 10},
		{"level-20", "Уровни", "Мастер", "Достичь 20 уровня", "🔱", m.level, 20},
		{"level-50", "Уровни", "Легенда", "Достичь 50 уровня", "🌟", m.level, 50},

		// --- серии ---------------------------------------------------------
		{"streak-3", "Серии", "3 дня подряд", "Серия из 3 дней", "🔥", m.longestStreak, 3},
		{"streak-7", "Серии", "Неделя", "Серия из 7 дней", "⚡", m.longestStreak, 7},
		{"streak-14", "Серии", "Две недели", "Серия из 14 дней", "🌊", m.longestStreak, 14},
		{"streak-30", "Серии", "Месяц", "Серия из 30 дней", "🏔️", m.longestStreak, 30},
		{"streak-100", "Серии", "Сто дней", "Серия из 100 дней", "💎", m.longestStreak, 100},

		// --- время чтения --------------------------------------------------
		{"time-1h", "Время", "Час за чтением", "Прочитать суммарно 1 час", "⏱️", m.totalSecs, 3600},
		{"time-5h", "Время", "Пять часов", "Прочитать суммарно 5 часов", "⏳", m.totalSecs, 5 * 3600},
		{"time-24h", "Время", "Сутки чтения", "Прочитать суммарно 24 часа", "🕰️", m.totalSecs, 24 * 3600},
		{"time-100h", "Время", "Сто часов", "Прочитать суммарно 100 часов", "🗓️", m.totalSecs, 100 * 3600},

		// --- скорость ------------------------------------------------------
		{"speed-fast", "Скорость", "Скорочит", "Завершить урок, не отвлекаясь (≤150% от ожидаемого времени)", "⚡", m.fastCompleted, 1},
		{"speed-5", "Скорость", "Реактивный", "5 уроков прочитано эффективно", "🚀", m.fastCompleted, 5},

		// --- широта --------------------------------------------------------
		{"breadth-12", "Широта", "Мультитул", "Тронуть уроки во всех категориях", "🧰", len(m.catTouched), len(content.Categories)},

		// --- конспекты -----------------------------------------------------
		{"notes-5", "Конспекты", "Конспектолог", "Написать заметки в 5 уроках", "🗒️", m.notesCount, 5},
		{"notes-25", "Конспекты", "Летописец", "Написать заметки в 25 уроках", "📓", m.notesCount, 25},

		// --- активность ----------------------------------------------------
		{"daily-7", "Активность", "Неделя активности", "Учиться в 7 разных дней", "📅", m.distinctDays, 7},
		{"daily-30", "Активность", "Месяц активности", "Учиться в 30 разных дней", "🗓️", m.distinctDays, 30},
		{"night-owl", "Активность", "Полуночник", "Учить уроки после полуночи (0:00–5:00)", "🦉", m.nightEvents, 10},
		{"early-bird", "Активность", "Ранняя пташка", "Учить уроки ранним утром (5:00–8:00)", "🐦", m.earlyEvents, 10},
		{"comeback-7", "Активность", "Возвращение", "Вернуться после перерыва в 7+ дней", "🔄", min(m.maxGapDays, 8), 8},
	}

	// --- мастерство по категориям (по одному значку на категорию) --------
	for _, c := range content.Categories {
		need := 10
		if t := m.catTotal[c.Slug]; t > 0 && t < need {
			need = t
		}
		defs = append(defs, badge{
			id:    "cat-" + c.Slug,
			theme: "Категории",
			title: "Мастер: " + c.Name,
			desc:  fmt.Sprintf("Завершить %d уроков в категории «%s»", need, c.Name),
			icon:  c.Icon,
			have:  m.catDone[c.Slug],
			need:  need,
		})
	}

	// --- все уроки уровня сложности --------------------------------------
	for _, d := range diffOrder {
		need := m.diffTotal[d]
		if need < 1 {
			need = 1
		}
		defs = append(defs, badge{
			id:    "diff-" + d,
			theme: "Сложность",
			title: "Все «" + difficultyLabel(d) + "»",
			desc:  fmt.Sprintf("Завершить все уроки уровня «%s»", difficultyLabel(d)),
			icon:  diffIcons[d],
			have:  m.diffDone[d],
			need:  need,
		})
	}

	out := make([]map[string]any, 0, len(defs))
	for _, d := range defs {
		out = append(out, d.toMap())
	}
	return out
}

// humanDuration renders a second count as a compact Russian duration.
func humanDuration(secs int) string {
	if secs < 0 {
		secs = 0
	}
	if secs < 60 {
		return fmt.Sprintf("%d сек", secs)
	}
	mins := secs / 60
	if mins < 60 {
		return fmt.Sprintf("%d мин", mins)
	}
	h := mins / 60
	mm := mins % 60
	if h < 24 {
		if mm == 0 {
			return fmt.Sprintf("%d ч", h)
		}
		return fmt.Sprintf("%d ч %d мин", h, mm)
	}
	d := h / 24
	hh := h % 24
	if hh == 0 {
		return fmt.Sprintf("%d д", d)
	}
	return fmt.Sprintf("%d д %d ч", d, hh)
}

// buildStats computes the rich statistics payload returned with /api/progress.
func (s *Server) buildStats(u *progress.User) map[string]any {
	m := s.computeMetrics(u)
	total := len(s.Content.All())
	u.ComputeXP()
	level := u.XP/xpPerLevel + 1
	lvlProgress := float64(u.XP%xpPerLevel) / float64(xpPerLevel)

	cats := make([]map[string]any, 0, len(content.Categories))
	var mostCat, leastCat map[string]any
	for _, c := range content.Categories {
		t := m.catTotal[c.Slug]
		d := m.catDone[c.Slug]
		pct := 0
		if t > 0 {
			pct = d * 100 / t
		}
		row := map[string]any{
			"slug": c.Slug, "name": c.Name, "color": c.Color, "icon": c.Icon,
			"total": t, "done": d, "pct": pct,
		}
		cats = append(cats, row)
		if t > 0 {
			if mostCat == nil || pct > mostCat["pct"].(int) {
				mostCat = row
			}
			if leastCat == nil || pct < leastCat["pct"].(int) {
				leastCat = row
			}
		}
	}

	diffs := make([]map[string]any, 0, len(diffOrder))
	for _, d := range diffOrder {
		t := m.diffTotal[d]
		done := m.diffDone[d]
		pct := 0
		if t > 0 {
			pct = done * 100 / t
		}
		diffs = append(diffs, map[string]any{
			"key": d, "label": difficultyLabel(d),
			"color": model.DifficultyColors[d], "total": t, "done": done, "pct": pct,
		})
	}

	accuracy := accuracyPct(m.quizCorrect, m.quizAnswered)
	bestScore := 0
	avgScore, attempted := 0, 0
	for _, lp := range u.Lessons {
		if lp == nil {
			continue
		}
		if lp.QuizBest > bestScore {
			bestScore = lp.QuizBest
		}
		if lp.QuizTotal > 0 {
			avgScore += lp.QuizBest * 100 / lp.QuizTotal
			attempted++
		}
	}
	if attempted > 0 {
		avgScore /= attempted
	}

	remaining := total - m.completed
	if remaining < 0 {
		remaining = 0
	}
	avgRead := 0
	if m.readLessons > 0 {
		avgRead = m.totalSecs / m.readLessons
	}

	return map[string]any{
		"total_read_seconds": m.totalSecs,
		"total_read_human":   humanDuration(m.totalSecs),
		"lessons_total":      total,
		"lessons_started":    m.touched,
		"lessons_completed":  m.completed,
		"lessons_remaining":  remaining,
		"lessons_read":       m.readLessons,
		"avg_read_seconds":   avgRead,
		"avg_read_human":     humanDuration(avgRead),
		"categories":         cats,
		"difficulties":       diffs,
		"quiz": map[string]any{
			"answered":   m.quizAnswered,
			"correct":    m.quizCorrect,
			"accuracy":   accuracy,
			"perfect":    m.perfect,
			"attempted":  attempted,
			"attempts":   m.quizAttempts,
			"fails":      m.quizFails,
			"avg_score":  avgScore,
			"best_score": bestScore,
		},
		"current_streak":            m.curStreak,
		"longest_streak":            m.longestStreak,
		"active_days":               m.distinctDays,
		"max_gap_days":              m.maxGapDays,
		"most_progressed_category":  mostCat,
		"least_progressed_category": leastCat,
		"xp":                        u.XP,
		"level":                     level,
		"level_progress":            lvlProgress,
		"xp_to_next":                xpPerLevel - u.XP%xpPerLevel,
		"xp_per_level":              xpPerLevel,
		"notes_count":               m.notesCount,
		"recent":                    s.recentActivity(u, 12),
	}
}

// recentActivity returns the most recently touched lessons (newest first).
func (s *Server) recentActivity(u *progress.User, n int) []map[string]any {
	type row struct {
		id string
		lp *progress.LessonProgress
	}
	rows := make([]row, 0, len(u.Lessons))
	for id, lp := range u.Lessons {
		if lp == nil || lp.UpdatedAt == 0 {
			continue
		}
		rows = append(rows, row{id, lp})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].lp.UpdatedAt > rows[j].lp.UpdatedAt })
	if len(rows) > n {
		rows = rows[:n]
	}
	out := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		title, cat, icon := r.id, "", "📄"
		if l, ok := s.Content.Lesson(r.id); ok {
			title = l.Title
			cat = l.Category
			_, _, icon = catMetaFor(cat)
		}
		read, secs := 0, 0
		for _, sp := range r.lp.Sections {
			if sp == nil {
				continue
			}
			secs += sp.ReadSeconds
			if sp.Read {
				read++
			}
		}
		out = append(out, map[string]any{
			"id": r.id, "title": title, "category": cat, "icon": icon,
			"updated_at": r.lp.UpdatedAt, "completed": r.lp.Completed,
			"sections_read": read, "read_seconds": secs,
		})
	}
	return out
}
