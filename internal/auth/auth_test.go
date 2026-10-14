package auth

import (
	"encoding/base64"
	"encoding/hex"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// speed up hashing in tests
func fast() func() {
	old := Iterations
	Iterations = 1000
	return func() { Iterations = old }
}

func TestPBKDF2KnownVectors(t *testing.T) {
	// RFC 7914 / common PBKDF2-HMAC-SHA256 test vectors.
	cases := []struct {
		pass, salt string
		iter       int
		want       string
	}{
		{"password", "salt", 1, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"},
		{"password", "salt", 2, "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"},
		{"password", "salt", 4096, "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"},
	}
	for _, tc := range cases {
		got := hex.EncodeToString(pbkdf2Key([]byte(tc.pass), []byte(tc.salt), tc.iter, 32))
		if got != tc.want {
			t.Errorf("pbkdf2(%q,%q,%d) = %s, want %s", tc.pass, tc.salt, tc.iter, got, tc.want)
		}
	}
}

func TestRegisterAndAuthenticate(t *testing.T) {
	defer fast()()
	s := NewStore(t.TempDir())

	u, err := s.Register("Alice", "hunter2!")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if u.ID == "" || u.Username != "Alice" {
		t.Fatalf("bad user: %#v", u)
	}
	if u.Salt == "" || u.Hash == "" {
		t.Fatalf("password material not stored: %#v", u)
	}
	if u.Hash == "hunter2!" {
		t.Fatal("password stored in plaintext")
	}

	got, err := s.Authenticate("alice", "hunter2!") // case-insensitive username
	if err != nil || got.ID != u.ID {
		t.Fatalf("authenticate: %v, %#v", err, got)
	}

	if _, err := s.Authenticate("alice", "wrong"); err == nil {
		t.Fatal("wrong password accepted")
	}
	if _, err := s.Authenticate("nobody", "hunter2!"); err == nil {
		t.Fatal("unknown user accepted")
	}
}

func TestRegisterValidation(t *testing.T) {
	defer fast()()
	s := NewStore(t.TempDir())

	if _, err := s.Register("ab", "hunter2!"); err != ErrBadUsername {
		t.Errorf("short username err = %v, want ErrBadUsername", err)
	}
	if _, err := s.Register("has space", "hunter2!"); err != ErrBadUsername {
		t.Errorf("bad charset err = %v, want ErrBadUsername", err)
	}
	if _, err := s.Register("bob", "123"); err != ErrWeakPassword {
		t.Errorf("weak password err = %v, want ErrWeakPassword", err)
	}
	if _, err := s.Register("bob", "hunter2!"); err != nil {
		t.Fatalf("valid register: %v", err)
	}
	if _, err := s.Register("BOB", "another1"); err != ErrUserExists {
		t.Errorf("duplicate (case-insensitive) err = %v, want ErrUserExists", err)
	}
}

func TestStorePersistsAcrossReload(t *testing.T) {
	defer fast()()
	dir := t.TempDir()
	s := NewStore(dir)
	u, err := s.Register("carol", "s3cret!")
	if err != nil {
		t.Fatal(err)
	}

	reopened := NewStore(dir)
	got, err := reopened.Authenticate("carol", "s3cret!")
	if err != nil || got.ID != u.ID {
		t.Fatalf("reload authenticate: %v %#v", err, got)
	}
	byID, ok := reopened.ByID(u.ID)
	if !ok || byID.Username != "carol" {
		t.Fatalf("ByID after reload: %v %#v", ok, byID)
	}
	if reopened.Count() != 1 {
		t.Errorf("Count = %d, want 1", reopened.Count())
	}
}

func TestSessionRoundTrip(t *testing.T) {
	sess := NewSessions([]byte("test-secret-key-0123456789abcdef"), time.Hour)
	tok := sess.Issue("abc123")
	if tok == "" {
		t.Fatal("empty token")
	}
	uid, ok := sess.Verify(tok)
	if !ok || uid != "abc123" {
		t.Fatalf("verify = %q,%v", uid, ok)
	}

	// A token signed with a different secret must not verify.
	other := NewSessions([]byte("a-different-secret-0123456789abcd"), time.Hour)
	if _, ok := other.Verify(tok); ok {
		t.Fatal("token verified under the wrong secret")
	}

	// Tampered payload/signature is rejected.
	if _, ok := sess.Verify(tok + "x"); ok {
		t.Fatal("tampered token verified")
	}
	if _, ok := sess.Verify("garbage"); ok {
		t.Fatal("garbage token verified")
	}
}

func TestSessionExpiry(t *testing.T) {
	sess := NewSessions([]byte("secret-key-0123456789abcdefghij"), time.Hour)

	// Craft a correctly-signed token whose expiry is in the past (same package,
	// so we can reuse the unexported signer).
	payload := []byte("u1|" + strconv.FormatInt(time.Now().Add(-time.Hour).Unix(), 10))
	expired := base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(sess.sign(payload))
	if _, ok := sess.Verify(expired); ok {
		t.Fatal("expired token verified")
	}

	// A freshly issued token is still valid.
	if _, ok := sess.Verify(sess.Issue("u1")); !ok {
		t.Fatal("fresh token did not verify")
	}
}

func TestLoadOrCreateSecret(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.key")
	a, err := LoadOrCreateSecret(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(a) < 16 {
		t.Fatalf("secret too short: %d", len(a))
	}
	b, err := LoadOrCreateSecret(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatal("secret not stable across reload")
	}
}
