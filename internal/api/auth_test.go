package api

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"learningtree/internal/auth"
	"learningtree/internal/content"
	"learningtree/internal/progress"
)

// TestMain lowers the PBKDF2 work factor so the account tests stay fast.
func TestMain(m *testing.M) {
	old := auth.Iterations
	auth.Iterations = 2000
	code := m.Run()
	auth.Iterations = old
	os.Exit(code)
}

func newAuthTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	contentDir := t.TempDir()
	writeFixture(t, contentDir, "web/fixture-basics.md", fixtureBasics)
	writeFixture(t, contentDir, "web/fixture-child.md", fixtureChild)
	writeFixture(t, contentDir, "crypto/fixture-rsa.md", fixtureRSA)

	c := content.NewStore(contentDir)
	if err := c.Load(); err != nil {
		t.Fatalf("load content: %v", err)
	}
	dataDir := t.TempDir()
	p := progress.NewStore(dataDir)
	a := auth.NewStore(dataDir)
	sess := auth.NewSessions([]byte("test-secret-key-0123456789abcdef"), time.Hour)
	srv := New(c, p, t.TempDir(), WithAuth(a, sess))
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

type reqOpts struct {
	cookies []*http.Cookie
	bearer  string
	body    string
}

func doAuth(t *testing.T, ts *httptest.Server, method, path string, o reqOpts) (*http.Response, []byte) {
	t.Helper()
	var r io.Reader
	if o.body != "" {
		r = bytes.NewBufferString(o.body)
	}
	req, err := http.NewRequest(method, ts.URL+path, r)
	if err != nil {
		t.Fatal(err)
	}
	if o.body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if o.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+o.bearer)
	}
	for _, c := range o.cookies {
		req.AddCookie(c)
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

func sessionCookie(resp *http.Response) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookieName {
			return c
		}
	}
	return nil
}

func TestAuthMeAnonymous(t *testing.T) {
	ts := newAuthTestServer(t)
	resp, body := doAuth(t, ts, "GET", "/api/auth/me", reqOpts{})
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if u := decodeMap(t, body)["user"]; u != nil {
		t.Errorf("anonymous me = %v, want nil", u)
	}
}

func TestAuthRegisterLoginLogoutFlow(t *testing.T) {
	ts := newAuthTestServer(t)

	// --- register -----------------------------------------------------------
	resp, body := doAuth(t, ts, "POST", "/api/auth/register",
		reqOpts{body: `{"username":"dave","password":"hunter2!"}`})
	if resp.StatusCode != 200 {
		t.Fatalf("register status = %d, body=%s", resp.StatusCode, body)
	}
	m := decodeMap(t, body)
	user, _ := m["user"].(map[string]any)
	if user == nil || user["username"] != "dave" || user["id"] == "" {
		t.Fatalf("register user = %#v", m["user"])
	}
	token, _ := m["token"].(string)
	if token == "" {
		t.Fatal("register returned empty token")
	}
	sc := sessionCookie(resp)
	if sc == nil {
		t.Fatal("register did not set a session cookie")
	}
	if !sc.HttpOnly {
		t.Error("session cookie is not HttpOnly")
	}

	// --- me with the cookie -------------------------------------------------
	resp, body = doAuth(t, ts, "GET", "/api/auth/me", reqOpts{cookies: []*http.Cookie{sc}})
	if u := decodeMap(t, body)["user"].(map[string]any); u["username"] != "dave" {
		t.Errorf("me = %#v", u)
	}

	// --- progress is keyed by the account ----------------------------------
	_, pb := doAuth(t, ts, "GET", "/api/progress", reqOpts{cookies: []*http.Cookie{sc}})
	pm := decodeMap(t, pb)
	uid := pm["user"].(map[string]any)["user_id"].(string)
	if !strings.HasPrefix(uid, "u_") {
		t.Errorf("account progress key = %q, want u_* prefix", uid)
	}

	// --- the Bearer token reaches the same account -------------------------
	_, pb2 := doAuth(t, ts, "GET", "/api/progress", reqOpts{bearer: token})
	uid2 := decodeMap(t, pb2)["user"].(map[string]any)["user_id"].(string)
	if uid2 != uid {
		t.Errorf("bearer progress key = %q, want %q", uid2, uid)
	}

	// --- logout clears the cookie ------------------------------------------
	resp, _ = doAuth(t, ts, "POST", "/api/auth/logout", reqOpts{cookies: []*http.Cookie{sc}})
	if c := sessionCookie(resp); c == nil || c.MaxAge >= 0 {
		t.Errorf("logout did not clear session cookie: %#v", c)
	}

	// --- login --------------------------------------------------------------
	resp, body = doAuth(t, ts, "POST", "/api/auth/login",
		reqOpts{body: `{"username":"dave","password":"hunter2!"}`})
	if resp.StatusCode != 200 {
		t.Fatalf("login status = %d, body=%s", resp.StatusCode, body)
	}
	if sessionCookie(resp) == nil {
		t.Error("login did not set a session cookie")
	}
}

func TestAuthRegisterValidationAndDuplicates(t *testing.T) {
	ts := newAuthTestServer(t)

	resp, _ := doAuth(t, ts, "POST", "/api/auth/register", reqOpts{body: `{"username":"x","password":"hunter2!"}`})
	if resp.StatusCode != 400 {
		t.Errorf("short username status = %d, want 400", resp.StatusCode)
	}
	resp, _ = doAuth(t, ts, "POST", "/api/auth/register", reqOpts{body: `{"username":"validname","password":"123"}`})
	if resp.StatusCode != 400 {
		t.Errorf("weak password status = %d, want 400", resp.StatusCode)
	}
	resp, _ = doAuth(t, ts, "POST", "/api/auth/register", reqOpts{body: `{`})
	if resp.StatusCode != 400 {
		t.Errorf("invalid json status = %d, want 400", resp.StatusCode)
	}

	resp, _ = doAuth(t, ts, "POST", "/api/auth/register", reqOpts{body: `{"username":"validname","password":"hunter2!"}`})
	if resp.StatusCode != 200 {
		t.Fatalf("valid register status = %d", resp.StatusCode)
	}
	resp, _ = doAuth(t, ts, "POST", "/api/auth/register", reqOpts{body: `{"username":"VALIDNAME","password":"hunter2!"}`})
	if resp.StatusCode != 409 {
		t.Errorf("duplicate register status = %d, want 409", resp.StatusCode)
	}

	resp, _ = doAuth(t, ts, "POST", "/api/auth/login", reqOpts{body: `{"username":"validname","password":"nope"}`})
	if resp.StatusCode != 401 {
		t.Errorf("wrong password status = %d, want 401", resp.StatusCode)
	}
	resp, _ = doAuth(t, ts, "POST", "/api/auth/login", reqOpts{body: `{"username":"ghost","password":"whatever"}`})
	if resp.StatusCode != 401 {
		t.Errorf("unknown user status = %d, want 401", resp.StatusCode)
	}
}

func TestAuthMergesAnonymousProgress(t *testing.T) {
	ts := newAuthTestServer(t)
	anon := &http.Cookie{Name: anonCookieName, Value: "anonmerge01"}

	// The learner does some work while logged out.
	resp, _ := doAuth(t, ts, "POST", "/api/notes",
		reqOpts{cookies: []*http.Cookie{anon}, body: `{"lesson_id":"web-fixture","text":"anon-note"}`})
	if resp.StatusCode != 200 {
		t.Fatalf("anon notes status = %d", resp.StatusCode)
	}
	doAuth(t, ts, "POST", "/api/progress/quiz",
		reqOpts{cookies: []*http.Cookie{anon}, body: `{"lesson_id":"web-fixture","score":1,"total":1}`})

	// Register while carrying the anonymous cookie -> progress must be folded in.
	resp, body := doAuth(t, ts, "POST", "/api/auth/register",
		reqOpts{cookies: []*http.Cookie{anon}, body: `{"username":"mergeuser","password":"hunter2!"}`})
	if resp.StatusCode != 200 {
		t.Fatalf("register status = %d, body=%s", resp.StatusCode, body)
	}
	sc := sessionCookie(resp)
	if sc == nil {
		t.Fatal("no session cookie after register")
	}

	_, pb := doAuth(t, ts, "GET", "/api/progress", reqOpts{cookies: []*http.Cookie{sc}})
	lp := decodeMap(t, pb)["user"].(map[string]any)["lessons"].(map[string]any)["web-fixture"].(map[string]any)
	if lp["notes"] != "anon-note" {
		t.Errorf("merged notes = %v, want anon-note", lp["notes"])
	}
	if int(lp["quiz_best"].(float64)) != 1 {
		t.Errorf("merged quiz_best = %v, want 1", lp["quiz_best"])
	}
}

// TestAuthDisabledByDefault ensures a server built without WithAuth still runs
// in anonymous mode (existing deployments keep working).
func TestAuthDisabledByDefault(t *testing.T) {
	ts := newTestServer(t)
	resp, _ := doAuth(t, ts, "GET", "/api/auth/me", reqOpts{})
	if resp.StatusCode != 200 {
		t.Fatalf("me status = %d, want 200", resp.StatusCode)
	}
	resp, _ = doAuth(t, ts, "POST", "/api/auth/register",
		reqOpts{body: `{"username":"nobody","password":"hunter2!"}`})
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("register on anonymous server = %d, want 503", resp.StatusCode)
	}
	// Anonymous progress still works.
	resp, body := doAuth(t, ts, "GET", "/api/progress", reqOpts{cookies: []*http.Cookie{{Name: anonCookieName, Value: "legacy1"}}})
	if resp.StatusCode != 200 {
		t.Fatalf("anon progress status = %d", resp.StatusCode)
	}
	if uid := decodeMap(t, body)["user"].(map[string]any)["user_id"].(string); uid != "legacy1" {
		t.Errorf("anon user_id = %q, want legacy1", uid)
	}
}
