// Package api exposes the HTTP JSON API and serves the built frontend.
package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"learningtree/internal/content"
	"learningtree/internal/model"
	"learningtree/internal/progress"
)

// Server wires the content and progress stores to HTTP handlers.
type Server struct {
	Content   *content.Store
	Progress  *progress.Store
	StaticDir string
}

// New builds a server.
func New(c *content.Store, p *progress.Store, staticDir string) *Server {
	return &Server{Content: c, Progress: p, StaticDir: staticDir}
}

// Handler returns the root HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", s.handleHealth)
	mux.HandleFunc("GET /api/meta", s.handleMeta)
	mux.HandleFunc("GET /api/tree", s.handleTree)
	mux.HandleFunc("GET /api/lessons", s.handleLessons)
	mux.HandleFunc("GET /api/lessons/{id}", s.handleLesson)
	mux.HandleFunc("GET /api/search", s.handleSearch)
	mux.HandleFunc("GET /api/progress", s.handleGetProgress)
	mux.HandleFunc("POST /api/progress/section", s.handleSectionProgress)
	mux.HandleFunc("POST /api/progress/quiz", s.handleQuiz)
	mux.HandleFunc("POST /api/progress/complete", s.handleComplete)
	mux.HandleFunc("POST /api/notes", s.handleNotes)
	mux.HandleFunc("GET /api/export", s.handleExport)
	mux.HandleFunc("POST /api/import", s.handleImport)
	mux.HandleFunc("POST /api/reload", s.handleReload)
	mux.HandleFunc("/", s.handleStatic)
	return mux
}

// --- helpers ---------------------------------------------------------------

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	// Never let the browser (or an intermediary) heuristically cache API
	// responses: the content tree / progress must reflect newly added lessons
	// and fresh state on every fetch. Static assets are served elsewhere and
	// keep their own caching behaviour.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func readJSON(r *http.Request, v any) error {
	return json.NewDecoder(r.Body).Decode(v)
}

// userID returns the caller's anonymous id, creating a cookie if absent.
func (s *Server) userID(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie("lt_uid"); err == nil && c.Value != "" {
		return c.Value
	}
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	id := hex.EncodeToString(b)
	http.SetCookie(w, &http.Cookie{
		Name: "lt_uid", Value: id, Path: "/", MaxAge: 60 * 60 * 24 * 365, SameSite: http.SameSiteLaxMode,
	})
	return id
}

// --- handlers --------------------------------------------------------------

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"status": "ok", "time": time.Now().UTC()})
}

func (s *Server) handleMeta(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{
		"difficulties": []map[string]any{
			{"key": "beginner", "label": "Новичок", "color": model.DifficultyColors["beginner"]},
			{"key": "easy", "label": "Легко", "color": model.DifficultyColors["easy"]},
			{"key": "medium", "label": "Средне", "color": model.DifficultyColors["medium"]},
			{"key": "hard", "label": "Сложно", "color": model.DifficultyColors["hard"]},
			{"key": "expert", "label": "Эксперт", "color": model.DifficultyColors["expert"]},
		},
	})
}

func (s *Server) handleTree(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.Content.Tree())
}

func (s *Server) handleLessons(w http.ResponseWriter, r *http.Request) {
	all := s.Content.All()
	out := make([]model.LessonMeta, 0, len(all))
	for _, l := range all {
		out = append(out, l.LessonMeta)
	}
	writeJSON(w, 200, map[string]any{"lessons": out, "count": len(out)})
}

func (s *Server) handleLesson(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	l, ok := s.Content.Lesson(id)
	if !ok {
		writeJSON(w, 404, map[string]string{"error": "lesson not found"})
		return
	}
	writeJSON(w, 200, l)
}

func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	writeJSON(w, 200, map[string]any{"query": q, "results": s.Content.Search(q)})
}

func (s *Server) handleGetProgress(w http.ResponseWriter, r *http.Request) {
	uid := s.userID(w, r)
	u := s.Progress.Get(uid)
	u.ComputeXP()
	writeJSON(w, 200, map[string]any{
		"user":         u,
		"xp":           u.XP,
		"streak":       u.Streak(),
		"achievements": s.achievements(u),
		"stats":        s.buildStats(u),
	})
}

type sectionReq struct {
	LessonID  string `json:"lesson_id"`
	SectionID string `json:"section_id"`
	Seconds   int    `json:"seconds"`
}

func (s *Server) handleSectionProgress(w http.ResponseWriter, r *http.Request) {
	uid := s.userID(w, r)
	var req sectionReq
	if err := readJSON(r, &req); err != nil || req.LessonID == "" || req.SectionID == "" {
		writeJSON(w, 400, map[string]string{"error": "lesson_id and section_id required"})
		return
	}
	l, ok := s.Content.Lesson(req.LessonID)
	if !ok {
		writeJSON(w, 404, map[string]string{"error": "lesson not found"})
		return
	}
	// clamp the reported seconds to the section's expected reading time (anti-idle)
	var reqSec int
	found := false
	for _, sec := range l.Sections {
		if sec.ID == req.SectionID {
			reqSec, found = sec.RequiredSeconds, true
			break
		}
	}
	if !found {
		writeJSON(w, 404, map[string]string{"error": "section not found"})
		return
	}
	secs := req.Seconds
	if secs < 0 {
		secs = 0
	}
	if secs > reqSec*3 {
		secs = reqSec * 3
	}

	u := s.Progress.Get(uid)
	lp := u.Lesson(l.ID)
	sp := lp.Sections[req.SectionID]
	if sp == nil {
		sp = &progress.SectionProgress{}
		lp.Sections[req.SectionID] = sp
	}
	sp.ReadSeconds += secs
	if sp.ReadSeconds >= reqSec {
		sp.Read = true
	}
	sp.UpdatedAt = time.Now().Unix()
	lp.UpdatedAt = sp.UpdatedAt

	read := 0
	for _, sec := range l.Sections {
		if p := lp.Sections[sec.ID]; p != nil && p.Read {
			read++
		}
	}
	if len(l.Sections) > 0 && read == len(l.Sections) {
		lp.Completed = true
	}
	if secs > 0 {
		u.Bump()
	}
	u.ComputeXP()
	_ = s.Progress.Save(u)

	ratio := 0.0
	if len(l.Sections) > 0 {
		ratio = float64(read) / float64(len(l.Sections))
	}
	writeJSON(w, 200, map[string]any{
		"lesson_id":       l.ID,
		"section_id":      req.SectionID,
		"read_seconds":    sp.ReadSeconds,
		"required":        reqSec,
		"read":            sp.Read,
		"lesson_progress": ratio,
		"completed":       lp.Completed,
		"xp":              u.XP,
	})
}

type quizReq struct {
	LessonID string `json:"lesson_id"`
	Score    int    `json:"score"`
	Total    int    `json:"total"`
}

func (s *Server) handleQuiz(w http.ResponseWriter, r *http.Request) {
	uid := s.userID(w, r)
	var req quizReq
	if err := readJSON(r, &req); err != nil || req.LessonID == "" {
		writeJSON(w, 400, map[string]string{"error": "lesson_id required"})
		return
	}
	u := s.Progress.Get(uid)
	lp := u.Lesson(req.LessonID)
	if req.Score > lp.QuizBest {
		lp.QuizBest = req.Score
	}
	lp.QuizTotal = req.Total
	lp.QuizAttempts++
	if req.Total > 0 && req.Score < req.Total {
		lp.QuizFails++
	}
	lp.UpdatedAt = time.Now().Unix()
	if req.Total > 0 && req.Score == req.Total {
		lp.Completed = true
	}
	u.Bump()
	u.ComputeXP()
	_ = s.Progress.Save(u)
	writeJSON(w, 200, map[string]any{"quiz_best": lp.QuizBest, "quiz_total": lp.QuizTotal, "xp": u.XP})
}

func (s *Server) handleComplete(w http.ResponseWriter, r *http.Request) {
	uid := s.userID(w, r)
	// `completed` is optional: absent means "mark complete" (backwards compatible),
	// while an explicit `false` unmarks the lesson (used by the tree context menu).
	var req struct {
		LessonID  string `json:"lesson_id"`
		Completed *bool  `json:"completed"`
	}
	if err := readJSON(r, &req); err != nil || req.LessonID == "" {
		writeJSON(w, 400, map[string]string{"error": "lesson_id required"})
		return
	}
	done := true
	if req.Completed != nil {
		done = *req.Completed
	}
	u := s.Progress.Get(uid)
	lp := u.Lesson(req.LessonID)
	now := time.Now().Unix()
	if done {
		// Marking a lesson complete must also fill its reading progress: every
		// section becomes fully read (100% ring fill). Previously only the
		// `completed` flag flipped, so the green fill stayed at 0.
		if l, ok := s.Content.Lesson(req.LessonID); ok {
			for _, sec := range l.Sections {
				sp := lp.Sections[sec.ID]
				if sp == nil {
					sp = &progress.SectionProgress{}
					lp.Sections[sec.ID] = sp
				}
				if sp.ReadSeconds < sec.RequiredSeconds {
					sp.ReadSeconds = sec.RequiredSeconds
				}
				sp.Read = true
				sp.UpdatedAt = now
			}
		}
		lp.Completed = true
	} else {
		// Unmarking resets the reading progress: the ring returns to 0% (no
		// sections read). Notes and quiz results are intentionally preserved.
		lp.Sections = map[string]*progress.SectionProgress{}
		lp.Completed = false
	}
	lp.UpdatedAt = now
	u.Bump()
	u.ComputeXP()
	_ = s.Progress.Save(u)
	writeJSON(w, 200, map[string]any{
		"completed": lp.Completed,
		"xp":        u.XP,
		"sections":  lp.Sections,
	})
}

func (s *Server) handleNotes(w http.ResponseWriter, r *http.Request) {
	uid := s.userID(w, r)
	var req struct {
		LessonID string `json:"lesson_id"`
		Text     string `json:"text"`
	}
	if err := readJSON(r, &req); err != nil || req.LessonID == "" {
		writeJSON(w, 400, map[string]string{"error": "lesson_id required"})
		return
	}
	u := s.Progress.Get(uid)
	lp := u.Lesson(req.LessonID)
	lp.Notes = req.Text
	lp.UpdatedAt = time.Now().Unix()
	_ = s.Progress.Save(u)
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	uid := s.userID(w, r)
	u := s.Progress.Get(uid)
	u.ComputeXP()
	w.Header().Set("Content-Disposition", "attachment; filename=learning-tree-progress.json")
	writeJSON(w, 200, u)
}

func (s *Server) handleImport(w http.ResponseWriter, r *http.Request) {
	uid := s.userID(w, r)
	var u progress.User
	if err := readJSON(r, &u); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid json"})
		return
	}
	u.UserID = uid
	if u.Lessons == nil {
		u.Lessons = map[string]*progress.LessonProgress{}
	}
	if u.Activity == nil {
		u.Activity = map[string]int{}
	}
	if u.Hours == nil {
		u.Hours = map[int]int{}
	}
	_ = s.Progress.Save(&u)
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) handleReload(w http.ResponseWriter, r *http.Request) {
	if err := s.Content.Load(); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "total": s.Content.Tree().Total})
}

// achievements and buildStats live in stats.go.

// handleStatic serves the built frontend with SPA fallback.
func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		writeJSON(w, 404, map[string]string{"error": "not found"})
		return
	}
	clean := filepath.Clean("/" + r.URL.Path)
	full := filepath.Join(s.StaticDir, clean)
	if info, err := os.Stat(full); err == nil && !info.IsDir() {
		http.ServeFile(w, r, full)
		return
	}
	index := filepath.Join(s.StaticDir, "index.html")
	if _, err := os.Stat(index); err == nil {
		http.ServeFile(w, r, index)
		return
	}
	writeJSON(w, 200, map[string]string{
		"message": "API is running. Build the frontend (cd frontend && npm run build) to serve the UI.",
	})
}
