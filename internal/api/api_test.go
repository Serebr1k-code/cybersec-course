package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"learningtree/internal/content"
	"learningtree/internal/progress"
)

const fixtureBasics = `---
id: web-fixture
title: "Fixture Basics"
category: web
parent:
difficulty: beginner
order: 1
tags: [fixture, testing]
prerequisites: []
useful_for:
  - "unit tests"
estimated_minutes: 5
summary: "a fixture lesson used by the api tests"
---

Вступление без заголовка.

## Теория

Немного теории для проверки разбиения на секции и подсчёта слов.

## Квиз

**1. Сколько будет 2 + 2?**
- A) 3
- [x] B) 4
- C) 5

## Где пригодится

- Юнит-тесты
`

const fixtureChild = `---
id: web-fixture-child
title: "Fixture Child"
category: web
parent: web-fixture
difficulty: easy
order: 2
tags: [child]
waystone: true
waystone_tasks: [web-fixture, crypto-fixture-rsa]
summary: "child fixture lesson"
---

## Введение

Дочерний урок.
`

const fixtureRSA = `---
id: crypto-fixture-rsa
title: "Fixture RSA"
category: crypto
parent:
difficulty: medium
order: 1
tags: [rsa]
summary: "crypto fixture lesson"
---

## Введение

Криптографический фикстур.
`

func writeFixture(t *testing.T, dir, rel, body string) {
	t.Helper()
	full := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	contentDir := t.TempDir()
	writeFixture(t, contentDir, "web/fixture-basics.md", fixtureBasics)
	writeFixture(t, contentDir, "web/fixture-child.md", fixtureChild)
	writeFixture(t, contentDir, "crypto/fixture-rsa.md", fixtureRSA)

	c := content.NewStore(contentDir)
	if err := c.Load(); err != nil {
		t.Fatalf("load content: %v", err)
	}
	p := progress.NewStore(t.TempDir())
	srv := New(c, p, t.TempDir())
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

func doReq(t *testing.T, ts *httptest.Server, method, path, user, body string) (*http.Response, []byte) {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = bytes.NewBufferString(body)
	}
	req, err := http.NewRequest(method, ts.URL+path, r)
	if err != nil {
		t.Fatal(err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if user != "" {
		req.AddCookie(&http.Cookie{Name: "lt_uid", Value: user})
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

func decodeMap(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("bad JSON response: %v\n%s", err, b)
	}
	return m
}

func TestHealth(t *testing.T) {
	ts := newTestServer(t)
	resp, body := doReq(t, ts, "GET", "/api/health", "", "")
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, body=%s", resp.StatusCode, body)
	}
	if got := decodeMap(t, body)["status"]; got != "ok" {
		t.Errorf("status field = %v", got)
	}
	if ct := resp.Header.Get("Content-Type"); ct == "" {
		t.Errorf("missing Content-Type")
	}
}

func TestTree(t *testing.T) {
	ts := newTestServer(t)
	resp, body := doReq(t, ts, "GET", "/api/tree", "", "")
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	m := decodeMap(t, body)
	if got := int(m["total"].(float64)); got != 3 {
		t.Errorf("total = %d, want 3", got)
	}
	cats := m["categories"].([]any)
	bySlug := map[string]int{}
	for _, c := range cats {
		cm := c.(map[string]any)
		bySlug[cm["slug"].(string)] = int(cm["count"].(float64))
	}
	if bySlug["web"] != 2 || bySlug["crypto"] != 1 {
		t.Errorf("category counts = %v", bySlug)
	}
	// /api/tree must carry the waystone gate fields so the frontend can lock a
	// branch without a second request.
	nodes := m["nodes"].([]any)
	var gate map[string]any
	for _, n := range nodes {
		nm := n.(map[string]any)
		if nm["id"] == "web-fixture-child" {
			gate = nm
		}
	}
	if gate == nil {
		t.Fatal("web-fixture-child not in /api/tree")
	}
	if gate["waystone"] != true {
		t.Errorf("waystone = %v, want true", gate["waystone"])
	}
	tasks, _ := gate["waystone_tasks"].([]any)
	if len(tasks) != 2 || tasks[0] != "web-fixture" || tasks[1] != "crypto-fixture-rsa" {
		t.Errorf("waystone_tasks = %v", gate["waystone_tasks"])
	}
}

func TestLessons(t *testing.T) {
	ts := newTestServer(t)
	resp, body := doReq(t, ts, "GET", "/api/lessons", "", "")
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	m := decodeMap(t, body)
	if got := int(m["count"].(float64)); got != 3 {
		t.Errorf("count = %d, want 3", got)
	}
	if got := len(m["lessons"].([]any)); got != 3 {
		t.Errorf("lessons length = %d, want 3", got)
	}
}

func TestLessonByID(t *testing.T) {
	ts := newTestServer(t)

	resp, body := doReq(t, ts, "GET", "/api/lessons/web-fixture", "", "")
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, body=%s", resp.StatusCode, body)
	}
	m := decodeMap(t, body)
	if m["id"] != "web-fixture" {
		t.Errorf("id = %v", m["id"])
	}
	secs := m["sections"].([]any)
	if len(secs) == 0 {
		t.Fatalf("no sections returned")
	}
	// The quiz must have been parsed out of the "## Квиз" section.
	quiz := m["quiz"].([]any)
	if len(quiz) != 1 {
		t.Fatalf("parsed quiz length = %d, want 1: %#v", len(quiz), quiz)
	}
	q := quiz[0].(map[string]any)
	if int(q["answer"].(float64)) != 1 {
		t.Errorf("quiz answer = %v, want 1", q["answer"])
	}
	if q["question"] == "" || q["question"] == nil {
		t.Errorf("quiz question text is empty")
	}

	// Unknown lesson -> 404.
	resp, body = doReq(t, ts, "GET", "/api/lessons/does-not-exist", "", "")
	if resp.StatusCode != 404 {
		t.Errorf("unknown lesson status = %d, want 404 (body=%s)", resp.StatusCode, body)
	}
}

func TestSearchEndpoint(t *testing.T) {
	ts := newTestServer(t)
	resp, body := doReq(t, ts, "GET", "/api/search?q=fixture", "", "")
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	m := decodeMap(t, body)
	results, _ := m["results"].([]any)
	if len(results) == 0 {
		t.Fatalf("expected search hits for 'fixture'")
	}

	resp, body = doReq(t, ts, "GET", "/api/search?q=", "", "")
	if resp.StatusCode != 200 {
		t.Fatalf("empty query status = %d", resp.StatusCode)
	}
	if got := decodeMap(t, body)["results"]; got != nil {
		t.Errorf("empty query results = %v, want nil", got)
	}
}

// lessonSection returns the section id and required seconds of the section at
// index i of the given lesson.
func lessonSection(t *testing.T, ts *httptest.Server, lessonID string, i int) (string, int) {
	t.Helper()
	_, body := doReq(t, ts, "GET", "/api/lessons/"+lessonID, "", "")
	m := decodeMap(t, body)
	secs := m["sections"].([]any)
	if i >= len(secs) {
		t.Fatalf("lesson %s has %d sections, wanted index %d", lessonID, len(secs), i)
	}
	s := secs[i].(map[string]any)
	return s["id"].(string), int(s["required_seconds"].(float64))
}

func TestSectionProgressClamping(t *testing.T) {
	ts := newTestServer(t)
	secID, required := lessonSection(t, ts, "web-fixture", 1)

	// An absurd reported time is clamped to 3x the expected reading time.
	body := `{"lesson_id":"web-fixture","section_id":"` + secID + `","seconds":1000000}`
	resp, respBody := doReq(t, ts, "POST", "/api/progress/section", "alice", body)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, body=%s", resp.StatusCode, respBody)
	}
	m := decodeMap(t, respBody)
	if got := int(m["read_seconds"].(float64)); got != required*3 {
		t.Errorf("read_seconds = %d, want %d (3x clamp)", got, required*3)
	}
	if m["read"] != true {
		t.Errorf("read = %v, want true", m["read"])
	}
	if got := int(m["required"].(float64)); got != required {
		t.Errorf("required = %d, want %d", got, required)
	}

	// A negative value is clamped to zero and does not mark the section read.
	body = `{"lesson_id":"web-fixture","section_id":"` + secID + `","seconds":-50}`
	_, respBody = doReq(t, ts, "POST", "/api/progress/section", "bob", body)
	m = decodeMap(t, respBody)
	if got := int(m["read_seconds"].(float64)); got != 0 {
		t.Errorf("negative read_seconds = %d, want 0", got)
	}
	if m["read"] == true {
		t.Errorf("section should not be read after negative time")
	}
}

func TestSectionProgressValidation(t *testing.T) {
	ts := newTestServer(t)

	cases := []struct {
		name string
		body string
		want int
	}{
		{"missing lesson", `{"section_id":"x"}`, 400},
		{"missing section", `{"lesson_id":"web-fixture"}`, 400},
		{"invalid json", `{`, 400},
		{"unknown lesson", `{"lesson_id":"nope","section_id":"s"}`, 404},
		{"unknown section", `{"lesson_id":"web-fixture","section_id":"nope"}`, 404},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, _ := doReq(t, ts, "POST", "/api/progress/section", "u", tc.body)
			if resp.StatusCode != tc.want {
				t.Errorf("status = %d, want %d", resp.StatusCode, tc.want)
			}
		})
	}
}

func TestSectionProgressCompletesLesson(t *testing.T) {
	ts := newTestServer(t)
	_, body := doReq(t, ts, "GET", "/api/lessons/web-fixture", "", "")
	m := decodeMap(t, body)
	secs := m["sections"].([]any)

	for _, s := range secs {
		sm := s.(map[string]any)
		reqBody, _ := json.Marshal(map[string]any{
			"lesson_id": "web-fixture", "section_id": sm["id"], "seconds": 100000,
		})
		_, respBody := doReq(t, ts, "POST", "/api/progress/section", "completer", string(reqBody))
		rm := decodeMap(t, respBody)
		if rm["completed"] == true {
			t.Logf("lesson completed after reading section %v", sm["id"])
		}
	}
	// Fetch progress and confirm the lesson is completed.
	_, pb := doReq(t, ts, "GET", "/api/progress", "completer", "")
	pm := decodeMap(t, pb)
	user := pm["user"].(map[string]any)
	lessons := user["lessons"].(map[string]any)
	lp := lessons["web-fixture"].(map[string]any)
	if lp["completed"] != true {
		t.Errorf("lesson not completed after reading every section: %#v", lp)
	}
}

func TestCompleteToggle(t *testing.T) {
	ts := newTestServer(t)
	// Discover the fixture's section count so the XP expectations are derived.
	_, lb := doReq(t, ts, "GET", "/api/lessons/web-fixture", "", "")
	lm := decodeMap(t, lb)
	nSecs := len(lm["sections"].([]any))
	if nSecs == 0 {
		t.Fatal("fixture lesson has no sections")
	}

	// No `completed` field => mark complete (backwards compatible).
	resp, body := doReq(t, ts, "POST", "/api/progress/complete", "toggler", `{"lesson_id":"web-fixture"}`)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, body=%s", resp.StatusCode, body)
	}
	m := decodeMap(t, body)
	if m["completed"] != true {
		t.Fatalf("default complete: completed = %v", m["completed"])
	}
	// Marking complete fills EVERY section (100% ring fill), not just the flag.
	sections := m["sections"].(map[string]any)
	if len(sections) != nSecs {
		t.Fatalf("complete: %d sections, want %d (%#v)", len(sections), nSecs, sections)
	}
	for id, sv := range sections {
		sp := sv.(map[string]any)
		if sp["read"] != true {
			t.Fatalf("complete: section %s not read: %#v", id, sp)
		}
	}
	// +5 per read section + 40 for completion.
	xpMarked := int(m["xp"].(float64))
	if want := nSecs*5 + 40; xpMarked != want {
		t.Fatalf("complete xp = %d, want %d", xpMarked, want)
	}

	// Explicit false unmarks AND clears the reading progress.
	_, body = doReq(t, ts, "POST", "/api/progress/complete", "toggler", `{"lesson_id":"web-fixture","completed":false}`)
	m = decodeMap(t, body)
	if m["completed"] != false {
		t.Fatalf("unmark: completed = %v", m["completed"])
	}
	if s := m["sections"].(map[string]any); len(s) != 0 {
		t.Fatalf("unmark: sections not cleared: %#v", s)
	}
	if xpUnmarked := int(m["xp"].(float64)); xpUnmarked != 0 {
		t.Fatalf("unmark xp = %d, want 0", xpUnmarked)
	}

	// The reset must persist (no stale read sections, no stale flag).
	_, pb := doReq(t, ts, "GET", "/api/progress", "toggler", "")
	pm := decodeMap(t, pb)
	lp := pm["user"].(map[string]any)["lessons"].(map[string]any)["web-fixture"].(map[string]any)
	if lp["completed"] != false {
		t.Fatalf("unmark not persisted: %#v", lp)
	}
	if s, ok := lp["sections"].(map[string]any); ok && len(s) != 0 {
		t.Fatalf("unmark sections not persisted: %#v", s)
	}

	// Explicit true re-marks and re-fills every section.
	_, body = doReq(t, ts, "POST", "/api/progress/complete", "toggler", `{"lesson_id":"web-fixture","completed":true}`)
	if m = decodeMap(t, body); m["completed"] != true {
		t.Fatalf("re-mark: completed = %v", m["completed"])
	}
	if s := m["sections"].(map[string]any); len(s) != nSecs {
		t.Fatalf("re-mark: %d sections, want %d", len(s), nSecs)
	}
}

func TestQuizProgress(t *testing.T) {
	ts := newTestServer(t)
	body := `{"lesson_id":"web-fixture","score":1,"total":1}`
	resp, respBody := doReq(t, ts, "POST", "/api/progress/quiz", "quizer", body)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, body=%s", resp.StatusCode, respBody)
	}
	m := decodeMap(t, respBody)
	if int(m["quiz_best"].(float64)) != 1 || int(m["quiz_total"].(float64)) != 1 {
		t.Errorf("quiz result = %v", m)
	}
	if int(m["xp"].(float64)) < 10 {
		t.Errorf("xp = %v, want >= 10 for a perfect quiz", m["xp"])
	}

	// A lower later score must not overwrite the best.
	_, _ = doReq(t, ts, "POST", "/api/progress/quiz", "quizer", `{"lesson_id":"web-fixture","score":0,"total":1}`)
	_, pb := doReq(t, ts, "GET", "/api/progress", "quizer", "")
	pm := decodeMap(t, pb)
	user := pm["user"].(map[string]any)
	lp := user["lessons"].(map[string]any)["web-fixture"].(map[string]any)
	if int(lp["quiz_best"].(float64)) != 1 {
		t.Errorf("quiz_best = %v, want 1 (best kept)", lp["quiz_best"])
	}
}

func TestQuizValidation(t *testing.T) {
	ts := newTestServer(t)
	resp, _ := doReq(t, ts, "POST", "/api/progress/quiz", "u", `{"score":1,"total":1}`)
	if resp.StatusCode != 400 {
		t.Errorf("missing lesson_id status = %d, want 400", resp.StatusCode)
	}
}

func TestNotes(t *testing.T) {
	ts := newTestServer(t)
	resp, respBody := doReq(t, ts, "POST", "/api/notes", "noter", `{"lesson_id":"web-fixture","text":"привет"} `)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, body=%s", resp.StatusCode, respBody)
	}
	_, pb := doReq(t, ts, "GET", "/api/progress", "noter", "")
	pm := decodeMap(t, pb)
	lp := pm["user"].(map[string]any)["lessons"].(map[string]any)["web-fixture"].(map[string]any)
	if lp["notes"] != "привет" {
		t.Errorf("notes = %v, want привет", lp["notes"])
	}

	resp, _ = doReq(t, ts, "POST", "/api/notes", "u", `{"text":"no lesson"}`)
	if resp.StatusCode != 400 {
		t.Errorf("missing lesson_id status = %d, want 400", resp.StatusCode)
	}
}

func TestExportImportRoundTrip(t *testing.T) {
	ts := newTestServer(t)

	// Give alice some progress.
	_, _ = doReq(t, ts, "POST", "/api/notes", "alice", `{"lesson_id":"web-fixture","text":"alice-note"}`)
	_, _ = doReq(t, ts, "POST", "/api/progress/quiz", "alice", `{"lesson_id":"web-fixture","score":1,"total":1}`)

	// Export alice's profile.
	resp, exported := doReq(t, ts, "GET", "/api/export", "alice", "")
	if resp.StatusCode != 200 {
		t.Fatalf("export status = %d", resp.StatusCode)
	}
	if cd := resp.Header.Get("Content-Disposition"); cd == "" {
		t.Errorf("export missing Content-Disposition header")
	}

	// Import it as bob.
	resp, impBody := doReq(t, ts, "POST", "/api/import", "bob", string(exported))
	if resp.StatusCode != 200 {
		t.Fatalf("import status = %d, body=%s", resp.StatusCode, impBody)
	}

	// Bob must now have alice's note, under his own user id.
	_, pb := doReq(t, ts, "GET", "/api/progress", "bob", "")
	pm := decodeMap(t, pb)
	user := pm["user"].(map[string]any)
	if user["user_id"] != "bob" {
		t.Errorf("imported user_id = %v, want bob", user["user_id"])
	}
	lp := user["lessons"].(map[string]any)["web-fixture"].(map[string]any)
	if lp["notes"] != "alice-note" {
		t.Errorf("imported notes = %v, want alice-note", lp["notes"])
	}
}

func TestImportInvalidJSON(t *testing.T) {
	ts := newTestServer(t)
	resp, _ := doReq(t, ts, "POST", "/api/import", "u", `{not json`)
	if resp.StatusCode != 400 {
		t.Errorf("invalid import status = %d, want 400", resp.StatusCode)
	}
}

func TestReloadEndpoint(t *testing.T) {
	ts := newTestServer(t)
	resp, body := doReq(t, ts, "POST", "/api/reload", "", "")
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, body=%s", resp.StatusCode, body)
	}
	m := decodeMap(t, body)
	if m["ok"] != true || int(m["total"].(float64)) != 3 {
		t.Errorf("reload response = %v", m)
	}
}

func TestStaticFallbackAndAPINotFound(t *testing.T) {
	ts := newTestServer(t)
	// Unknown API path -> JSON 404.
	resp, body := doReq(t, ts, "GET", "/api/unknown-endpoint", "", "")
	if resp.StatusCode != 404 {
		t.Errorf("unknown api path status = %d, want 404", resp.StatusCode)
	}
	if !bytes.Contains(body, []byte("not found")) {
		t.Errorf("expected JSON error body, got %s", body)
	}
	// Non-API path with no built frontend -> informational JSON.
	resp, body = doReq(t, ts, "GET", "/some/spa/route", "", "")
	if resp.StatusCode != 200 {
		t.Errorf("static fallback status = %d, want 200", resp.StatusCode)
	}
	if !bytes.Contains(body, []byte("API is running")) {
		t.Errorf("unexpected static fallback body: %s", body)
	}
}

// TestStaticPWAAssetHeaders checks that the PWA entry points are served with the
// right MIME types and are never cached, so a new deploy / service-worker
// update is always picked up.
func TestStaticPWAAssetHeaders(t *testing.T) {
	staticDir := t.TempDir()
	writeFixture(t, staticDir, "manifest.webmanifest", `{"name":"CTF Learning Tree"}`)
	writeFixture(t, staticDir, "sw.js", "self.addEventListener('install', () => {})")
	writeFixture(t, staticDir, "index.html", "<!doctype html><title>CTF Learning Tree</title>")

	contentDir := t.TempDir()
	writeFixture(t, contentDir, "web/fixture-basics.md", fixtureBasics)
	c := content.NewStore(contentDir)
	if err := c.Load(); err != nil {
		t.Fatalf("load content: %v", err)
	}
	ts := httptest.NewServer(New(c, progress.NewStore(t.TempDir()), staticDir).Handler())
	t.Cleanup(ts.Close)

	cases := []struct {
		path      string
		wantType  string
		wantCache string
	}{
		{"/manifest.webmanifest", "application/manifest+json", "no-cache"},
		{"/sw.js", "application/javascript; charset=utf-8", "no-cache"},
		{"/index.html", "text/html; charset=utf-8", "no-cache"},
	}
	for _, tc := range cases {
		resp, body := doReq(t, ts, "GET", tc.path, "", "")
		if resp.StatusCode != 200 {
			t.Errorf("%s status = %d, want 200", tc.path, resp.StatusCode)
		}
		if got := resp.Header.Get("Content-Type"); got != tc.wantType {
			t.Errorf("%s Content-Type = %q, want %q", tc.path, got, tc.wantType)
		}
		if got := resp.Header.Get("Cache-Control"); got != tc.wantCache {
			t.Errorf("%s Cache-Control = %q, want %q", tc.path, got, tc.wantCache)
		}
		if len(body) == 0 {
			t.Errorf("%s returned an empty body", tc.path)
		}
	}
}

func TestAchievementsCatalogue(t *testing.T) {
	ts := newTestServer(t)

	// Give the user real progress: complete a lesson, a perfect quiz, a note.
	_, _ = doReq(t, ts, "POST", "/api/progress/complete", "ach-user", `{"lesson_id":"web-fixture"}`)
	_, _ = doReq(t, ts, "POST", "/api/progress/quiz", "ach-user", `{"lesson_id":"web-fixture","score":1,"total":1}`)
	_, _ = doReq(t, ts, "POST", "/api/notes", "ach-user", `{"lesson_id":"web-fixture","text":"note"}`)

	_, pb := doReq(t, ts, "GET", "/api/progress", "ach-user", "")
	pm := decodeMap(t, pb)

	ach, ok := pm["achievements"].([]any)
	if !ok {
		t.Fatalf("achievements missing or wrong type: %#v", pm["achievements"])
	}
	if len(ach) < 50 {
		t.Fatalf("achievements = %d, want >= 50", len(ach))
	}

	seen := map[string]bool{}
	unlocked := map[string]bool{}
	cats, diffs := 0, 0
	for _, a := range ach {
		am, ok := a.(map[string]any)
		if !ok {
			t.Fatalf("achievement not an object: %#v", a)
		}
		id, _ := am["id"].(string)
		if id == "" {
			t.Fatalf("achievement without id: %#v", am)
		}
		if seen[id] {
			t.Errorf("duplicate achievement id %q", id)
		}
		seen[id] = true
		for _, f := range []string{"title", "desc", "icon", "theme"} {
			if s, _ := am[f].(string); s == "" {
				t.Errorf("achievement %s missing field %q", id, f)
			}
		}
		if _, ok := am["unlocked"].(bool); !ok {
			t.Errorf("achievement %s: unlocked not a bool", id)
		}
		if _, ok := am["progress"].(float64); !ok {
			t.Errorf("achievement %s: progress not a number", id)
		}
		if u, _ := am["unlocked"].(bool); u {
			unlocked[id] = true
		}
		if len(id) > 4 && id[:4] == "cat-" {
			cats++
		}
		if len(id) > 5 && id[:5] == "diff-" {
			diffs++
		}
	}
	if cats != 12 {
		t.Errorf("category achievements = %d, want 12", cats)
	}
	if diffs != 5 {
		t.Errorf("difficulty achievements = %d, want 5", diffs)
	}
	for _, want := range []string{"complete-1", "quiz-first", "quiz-perfect-1"} {
		if !unlocked[want] {
			t.Errorf("achievement %q should be unlocked after completing the fixture lesson", want)
		}
	}
	if unlocked["reader-250"] {
		t.Errorf("achievement reader-250 must not unlock with one lesson")
	}
}

func TestStatsPayload(t *testing.T) {
	ts := newTestServer(t)
	// One perfect quiz + one failed quiz on the same lesson.
	_, _ = doReq(t, ts, "POST", "/api/progress/quiz", "st-user", `{"lesson_id":"web-fixture","score":0,"total":1}`)
	_, _ = doReq(t, ts, "POST", "/api/progress/quiz", "st-user", `{"lesson_id":"web-fixture","score":1,"total":1}`)

	_, pb := doReq(t, ts, "GET", "/api/progress", "st-user", "")
	pm := decodeMap(t, pb)
	st, ok := pm["stats"].(map[string]any)
	if !ok {
		t.Fatalf("stats missing or wrong type: %#v", pm["stats"])
	}
	quiz, ok := st["quiz"].(map[string]any)
	if !ok {
		t.Fatalf("stats.quiz missing: %#v", st["quiz"])
	}
	// 1 question answered, 1 correct => 100% accuracy; a failed attempt recorded.
	if got := int(quiz["answered"].(float64)); got != 1 {
		t.Errorf("quiz.answered = %d, want 1", got)
	}
	if got := int(quiz["accuracy"].(float64)); got != 100 {
		t.Errorf("quiz.accuracy = %d, want 100", got)
	}
	if got := int(quiz["attempts"].(float64)); got != 2 {
		t.Errorf("quiz.attempts = %d, want 2", got)
	}
	if got := int(quiz["fails"].(float64)); got != 1 {
		t.Errorf("quiz.fails = %d, want 1", got)
	}
	if _, ok := st["categories"].([]any); !ok {
		t.Errorf("stats.categories missing")
	}
	if _, ok := st["difficulties"].([]any); !ok {
		t.Errorf("stats.difficulties missing")
	}
	if got := int(st["lessons_total"].(float64)); got != 3 {
		t.Errorf("stats.lessons_total = %d, want 3", got)
	}
	if _, ok := st["recent"].([]any); !ok {
		t.Errorf("stats.recent missing")
	}
}
