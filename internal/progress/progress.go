// Package progress persists per-user reading progress, quiz results and notes.
package progress

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// SectionProgress is the accumulated reading state of one section.
type SectionProgress struct {
	ReadSeconds int   `json:"read_seconds"`
	Read        bool  `json:"read"`
	UpdatedAt   int64 `json:"updated_at"`
}

// LessonProgress is the per-lesson progress record.
type LessonProgress struct {
	Sections     map[string]*SectionProgress `json:"sections"`
	Completed    bool                        `json:"completed"`
	QuizBest     int                         `json:"quiz_best"`
	QuizTotal    int                         `json:"quiz_total"`
	QuizAttempts int                         `json:"quiz_attempts,omitempty"`
	QuizFails    int                         `json:"quiz_fails,omitempty"`
	Notes        string                      `json:"notes"`
	UpdatedAt    int64                       `json:"updated_at"`
}

// User is the full progress document of one anonymous reader.
type User struct {
	UserID    string                     `json:"user_id"`
	Lessons   map[string]*LessonProgress `json:"lessons"`
	XP        int                        `json:"xp"`
	Activity  map[string]int             `json:"activity"`         // YYYY-MM-DD -> events
	Hours     map[int]int                `json:"hours,omitempty"`  // local hour 0-23 -> events
	CreatedAt int64                      `json:"created_at"`
	UpdatedAt int64                      `json:"updated_at"`
}

// Store persists users as one JSON file each, guarded by a mutex.
type Store struct {
	dir string
	mu  sync.Mutex
}

// NewStore creates (if needed) the data directory.
func NewStore(dir string) *Store {
	_ = os.MkdirAll(dir, 0o755)
	return &Store{dir: dir}
}

// NewUser returns a blank user record.
func NewUser(id string) *User {
	now := time.Now().Unix()
	return &User{
		UserID: id, Lessons: map[string]*LessonProgress{}, Activity: map[string]int{},
		Hours: map[int]int{}, CreatedAt: now, UpdatedAt: now,
	}
}

func sanitize(id string) string {
	var b strings.Builder
	for _, r := range id {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "anon"
	}
	return b.String()
}

func (s *Store) path(id string) string {
	return filepath.Join(s.dir, sanitize(id)+".json")
}

// Get loads a user, returning a blank one if it does not exist yet.
func (s *Store) Get(id string) *User {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := os.ReadFile(s.path(id))
	if err != nil {
		return NewUser(id)
	}
	var u User
	if err := json.Unmarshal(data, &u); err != nil {
		return NewUser(id)
	}
	if u.Lessons == nil {
		u.Lessons = map[string]*LessonProgress{}
	}
	if u.Activity == nil {
		u.Activity = map[string]int{}
	}
	if u.Hours == nil {
		u.Hours = map[int]int{}
	}
	u.UserID = id
	return &u
}

// Save writes the user atomically.
func (s *Store) Save(u *User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u.UpdatedAt = time.Now().Unix()
	data, err := json.MarshalIndent(u, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path(u.UserID) + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, s.path(u.UserID))
}

// Lesson returns (creating if needed) the progress record for a lesson.
func (u *User) Lesson(id string) *LessonProgress {
	lp, ok := u.Lessons[id]
	if !ok {
		lp = &LessonProgress{Sections: map[string]*SectionProgress{}}
		u.Lessons[id] = lp
	}
	if lp.Sections == nil {
		lp.Sections = map[string]*SectionProgress{}
	}
	return lp
}

// Bump records one activity event for the streak heat-map.
func (u *User) Bump() {
	now := time.Now()
	if u.Activity == nil {
		u.Activity = map[string]int{}
	}
	u.Activity[now.Format("2006-01-02")]++
	if u.Hours == nil {
		u.Hours = map[int]int{}
	}
	u.Hours[now.Hour()]++
}

// ComputeXP derives the XP score from the stored progress.
func (u *User) ComputeXP() int {
	xp := 0
	for _, lp := range u.Lessons {
		for _, sp := range lp.Sections {
			if sp.Read {
				xp += 5
			}
		}
		if lp.Completed {
			xp += 40
		}
		xp += lp.QuizBest * 10
	}
	u.XP = xp
	return xp
}

// Streak returns the current consecutive-day reading streak.
func (u *User) Streak() int {
	streak := 0
	day := time.Now()
	for {
		key := day.Format("2006-01-02")
		if u.Activity[key] > 0 {
			streak++
			day = day.AddDate(0, 0, -1)
			continue
		}
		if streak == 0 {
			// allow "yesterday" to keep the streak alive before today's read
			day = day.AddDate(0, 0, -1)
			key = day.Format("2006-01-02")
			if u.Activity[key] > 0 {
				streak++
				day = day.AddDate(0, 0, -1)
				continue
			}
		}
		break
	}
	return streak
}
