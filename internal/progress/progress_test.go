package progress

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func day(offset int) string {
	return time.Now().AddDate(0, 0, offset).Format("2006-01-02")
}

func TestNewUser(t *testing.T) {
	u := NewUser("alice")
	if u.UserID != "alice" {
		t.Errorf("UserID = %q", u.UserID)
	}
	if u.Lessons == nil || u.Activity == nil {
		t.Fatalf("maps must be initialised: %#v", u)
	}
	if u.CreatedAt == 0 || u.UpdatedAt == 0 {
		t.Errorf("timestamps not set: %#v", u)
	}
}

func TestComputeXP(t *testing.T) {
	u := NewUser("x")
	l1 := u.Lesson("l1")
	l1.Sections["s1"] = &SectionProgress{Read: true}
	l1.Sections["s2"] = &SectionProgress{Read: true}
	l1.Sections["s3"] = &SectionProgress{Read: false}
	l1.Completed = true
	l1.QuizBest = 3

	l2 := u.Lesson("l2")
	l2.Sections["s1"] = &SectionProgress{Read: true}
	l2.QuizBest = 0

	// l1: 2*5 + 40 + 3*10 = 80 ; l2: 1*5 = 5
	if got := u.ComputeXP(); got != 85 {
		t.Fatalf("ComputeXP = %d, want 85", got)
	}
	if u.XP != 85 {
		t.Errorf("u.XP = %d, want 85", u.XP)
	}
}

func TestStreak(t *testing.T) {
	cases := []struct {
		name string
		days []int
		want int
	}{
		{"empty", nil, 0},
		{"today only", []int{0}, 1},
		{"today+yesterday", []int{0, -1}, 2},
		{"three days", []int{0, -1, -2}, 3},
		{"yesterday only keeps streak", []int{-1}, 1},
		{"gap breaks streak", []int{-2}, 0},
		{"old days only", []int{-5, -6, -7}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u := NewUser("x")
			for _, off := range tc.days {
				u.Activity[day(off)] = 1
			}
			if got := u.Streak(); got != tc.want {
				t.Errorf("Streak(%v) = %d, want %d", tc.days, got, tc.want)
			}
		})
	}
}

func TestLessonCreatesAndReuses(t *testing.T) {
	u := NewUser("x")
	lp := u.Lesson("web-sqli")
	if lp == nil || lp.Sections == nil {
		t.Fatalf("Lesson() did not initialise the record: %#v", lp)
	}
	lp.QuizBest = 2
	if again := u.Lesson("web-sqli"); again != lp {
		t.Errorf("Lesson() returned a different pointer")
	}
	if u.Lessons["web-sqli"].QuizBest != 2 {
		t.Errorf("record not stored in map")
	}
}

func TestBump(t *testing.T) {
	u := NewUser("x")
	u.Bump()
	u.Bump()
	if got := u.Activity[day(0)]; got != 2 {
		t.Errorf("today activity = %d, want 2", got)
	}
}

func TestSaveGetRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir)

	u := NewUser("alice")
	lp := u.Lesson("l1")
	lp.Sections["s1"] = &SectionProgress{ReadSeconds: 12, Read: true}
	lp.Completed = true
	lp.QuizBest = 4
	lp.QuizTotal = 5
	lp.Notes = "мой конспект"
	u.Bump()
	if err := s.Save(u); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got := s.Get("alice")
	if got.UserID != "alice" {
		t.Errorf("UserID = %q", got.UserID)
	}
	gl := got.Lessons["l1"]
	if gl == nil || !gl.Completed || gl.QuizBest != 4 || gl.QuizTotal != 5 || gl.Notes != "мой конспект" {
		t.Fatalf("lesson round-trip mismatch: %#v", gl)
	}
	if sp := gl.Sections["s1"]; sp == nil || sp.ReadSeconds != 12 || !sp.Read {
		t.Fatalf("section round-trip mismatch: %#v", sp)
	}
	if got.Activity[day(0)] != 1 {
		t.Errorf("activity not persisted: %#v", got.Activity)
	}
}

func TestGetMissingReturnsBlank(t *testing.T) {
	s := NewStore(t.TempDir())
	u := s.Get("nobody")
	if u == nil || u.UserID != "nobody" || u.Lessons == nil || u.Activity == nil {
		t.Fatalf("expected a blank user, got %#v", u)
	}
	if len(u.Lessons) != 0 {
		t.Errorf("blank user has lessons: %#v", u.Lessons)
	}
}

func TestGetCorruptFileReturnsBlank(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir)
	if err := os.WriteFile(filepath.Join(dir, "bad.json"), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	u := s.Get("bad")
	if u == nil || u.UserID != "bad" || len(u.Lessons) != 0 {
		t.Fatalf("corrupt file should yield a blank user, got %#v", u)
	}
}

func TestSanitizePreventsTraversal(t *testing.T) {
	s := NewStore(t.TempDir())
	for _, id := range []string{"../evil", "../../etc/passwd", "a/b", ".."} {
		p := s.path(id)
		if strings.Contains(p, "..") || strings.Contains(p, string(filepath.Separator)+"etc"+string(filepath.Separator)) {
			t.Errorf("path(%q) = %q escapes the data dir", id, p)
		}
		if filepath.Dir(p) != s.dir {
			t.Errorf("path(%q) = %q is not directly under the data dir", id, p)
		}
	}
	if p := s.path(""); filepath.Base(p) != "anon.json" {
		t.Errorf("empty id path = %q, want anon.json", p)
	}
}

func TestSaveIsAtomicAndValidJSON(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir)
	u := NewUser("bob")
	u.Lesson("l1")
	if err := s.Save(u); err != nil {
		t.Fatal(err)
	}
	// No leftover temp file.
	if _, err := os.Stat(filepath.Join(dir, "bob.json.tmp")); !os.IsNotExist(err) {
		t.Errorf("temporary file was not cleaned up")
	}
	data, err := os.ReadFile(filepath.Join(dir, "bob.json"))
	if err != nil {
		t.Fatal(err)
	}
	var parsed User
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("saved file is not valid JSON: %v", err)
	}
	if parsed.UserID != "bob" {
		t.Errorf("saved UserID = %q", parsed.UserID)
	}
}
