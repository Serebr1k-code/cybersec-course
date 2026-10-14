// Package auth provides lightweight server-side user accounts: registration,
// login, PBKDF2 password hashing and signed session tokens. It is stdlib-only
// (no external modules) so the backend stays a single static binary.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Errors returned by the store / credential checks.
var (
	ErrUserExists     = errors.New("username already taken")
	ErrUserNotFound   = errors.New("user not found")
	ErrBadCredentials = errors.New("invalid username or password")
	ErrWeakPassword   = errors.New("password must be at least 6 characters")
	ErrBadUsername    = errors.New("username must be 3-32 chars: letters, digits, . _ -")
)

// Iterations is the PBKDF2 work factor. It is a variable so tests can lower it;
// production keeps the strong default.
var Iterations = 120000

const (
	keyLen    = 32
	saltLen   = 16
	filePerms = 0o600
)

// User is one registered account. Password material is stored as a salted
// PBKDF2-HMAC-SHA256 digest; the plaintext is never persisted.
type User struct {
	ID        string `json:"id"`
	Username  string `json:"username"`
	Salt      string `json:"salt"`
	Hash      string `json:"hash"`
	CreatedAt int64  `json:"created_at"`
}

// Public returns the safe-to-serialize view of a user (no password material).
func (u *User) Public() map[string]any {
	return map[string]any{
		"id":         u.ID,
		"username":   u.Username,
		"created_at": u.CreatedAt,
	}
}

// Store persists accounts in a single JSON file guarded by a mutex.
type Store struct {
	path  string
	mu    sync.Mutex
	users map[string]*User // key: lowercased username
}

type fileData struct {
	Users []*User `json:"users"`
}

// NewStore loads (or lazily creates) the user database at dir/users.json.
func NewStore(dir string) *Store {
	_ = os.MkdirAll(dir, 0o755)
	s := &Store{path: filepath.Join(dir, "users.json"), users: map[string]*User{}}
	s.load()
	return s
}

func (s *Store) load() {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return
	}
	var fd fileData
	if err := json.Unmarshal(data, &fd); err != nil {
		return
	}
	for _, u := range fd.Users {
		if u == nil || u.Username == "" {
			continue
		}
		s.users[strings.ToLower(u.Username)] = u
	}
}

// save writes the database atomically. Caller must hold s.mu.
func (s *Store) saveLocked() error {
	fd := fileData{Users: make([]*User, 0, len(s.users))}
	for _, u := range s.users {
		fd.Users = append(fd.Users, u)
	}
	data, err := json.MarshalIndent(fd, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, filePerms); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// validUsername enforces a conservative, path-safe username alphabet.
func validUsername(name string) bool {
	if len(name) < 3 || len(name) > 32 {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}

// Register creates a new account, hashing the password with a fresh salt.
func (s *Store) Register(username, password string) (*User, error) {
	username = strings.TrimSpace(username)
	if !validUsername(username) {
		return nil, ErrBadUsername
	}
	if len(password) < 6 {
		return nil, ErrWeakPassword
	}
	key := strings.ToLower(username)

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[key]; ok {
		return nil, ErrUserExists
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	u := &User{
		ID:        newID(),
		Username:  username,
		Salt:      hex.EncodeToString(salt),
		Hash:      hex.EncodeToString(pbkdf2Key([]byte(password), salt, Iterations, keyLen)),
		CreatedAt: time.Now().Unix(),
	}
	s.users[key] = u
	if err := s.saveLocked(); err != nil {
		delete(s.users, key)
		return nil, err
	}
	return u, nil
}

// Authenticate verifies a username/password pair in constant time.
func (s *Store) Authenticate(username, password string) (*User, error) {
	key := strings.ToLower(strings.TrimSpace(username))
	s.mu.Lock()
	u := s.users[key]
	s.mu.Unlock()
	if u == nil {
		// Still burn a hash so a missing user is not distinguishable by timing.
		pbkdf2Key([]byte(password), []byte("dummy-salt-16byt"), Iterations, keyLen)
		return nil, ErrBadCredentials
	}
	salt, err := hex.DecodeString(u.Salt)
	if err != nil {
		return nil, ErrBadCredentials
	}
	want, err := hex.DecodeString(u.Hash)
	if err != nil {
		return nil, ErrBadCredentials
	}
	got := pbkdf2Key([]byte(password), salt, Iterations, keyLen)
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return nil, ErrBadCredentials
	}
	return u, nil
}

// ByID looks up a user by its opaque id.
func (s *Store) ByID(id string) (*User, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.users {
		if u.ID == id {
			return u, true
		}
	}
	return nil, false
}

// Count returns the number of registered accounts.
func (s *Store) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.users)
}

func newID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// pbkdf2Key derives a key from password+salt using PBKDF2-HMAC-SHA256. It is a
// self-contained implementation of RFC 2898 so the project needs no external
// dependency (golang.org/x/crypto is deliberately not vendored).
func pbkdf2Key(password, salt []byte, iter, keyLen int) []byte {
	prf := hmac.New(sha256.New, password)
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen

	var buf [4]byte
	dk := make([]byte, 0, numBlocks*hashLen)
	u := make([]byte, hashLen)
	for block := 1; block <= numBlocks; block++ {
		prf.Reset()
		prf.Write(salt)
		buf[0] = byte(block >> 24)
		buf[1] = byte(block >> 16)
		buf[2] = byte(block >> 8)
		buf[3] = byte(block)
		prf.Write(buf[:4])
		dk = prf.Sum(dk)
		t := dk[len(dk)-hashLen:]
		copy(u, t)

		for n := 2; n <= iter; n++ {
			prf.Reset()
			prf.Write(u)
			u = u[:0]
			u = prf.Sum(u)
			for x := range u {
				t[x] ^= u[x]
			}
		}
	}
	return dk[:keyLen]
}
