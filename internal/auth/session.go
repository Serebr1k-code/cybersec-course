package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// DefaultSessionTTL is how long a login lasts before it must be renewed.
const DefaultSessionTTL = 30 * 24 * time.Hour

// Sessions issues and verifies stateless, signed session tokens. A token is
// "<base64url(payload)>.<base64url(hmac-sha256(payload))>" where the payload is
// "<userID>|<expiryUnix>". Verification is constant-time and checks expiry, so
// the token can be handed to the client as an httpOnly cookie AND/OR a Bearer
// header without any server-side session table.
type Sessions struct {
	secret []byte
	ttl    time.Duration
}

// NewSessions builds a token signer from a raw HMAC secret.
func NewSessions(secret []byte, ttl time.Duration) *Sessions {
	if ttl <= 0 {
		ttl = DefaultSessionTTL
	}
	return &Sessions{secret: secret, ttl: ttl}
}

// TTL returns the configured session lifetime.
func (s *Sessions) TTL() time.Duration { return s.ttl }

func (s *Sessions) sign(payload []byte) []byte {
	mac := hmac.New(sha256.New, s.secret)
	mac.Write(payload)
	return mac.Sum(nil)
}

// Issue returns a signed token for userID, valid for the configured TTL.
func (s *Sessions) Issue(userID string) string {
	exp := time.Now().Add(s.ttl).Unix()
	payload := []byte(userID + "|" + strconv.FormatInt(exp, 10))
	sig := s.sign(payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(sig)
}

// Verify validates a token and returns the embedded user id. Expired or
// tampered tokens yield ok=false.
func (s *Sessions) Verify(token string) (userID string, ok bool) {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return "", false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", false
	}
	if subtle.ConstantTimeCompare(sig, s.sign(payload)) != 1 {
		return "", false
	}
	i := strings.LastIndexByte(string(payload), '|')
	if i <= 0 {
		return "", false
	}
	id := string(payload[:i])
	exp, err := strconv.ParseInt(string(payload[i+1:]), 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return "", false
	}
	return id, true
}

// LoadOrCreateSecret reads a hex-encoded 32-byte HMAC secret from path, creating
// it (mode 0600) on first use. Persisting it keeps sessions valid across restarts
// instead of silently logging everyone out on every deploy.
func LoadOrCreateSecret(path string) ([]byte, error) {
	if data, err := os.ReadFile(path); err == nil {
		if b, err := hex.DecodeString(strings.TrimSpace(string(data))); err == nil && len(b) >= 16 {
			return b, nil
		}
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(secret)), 0o600); err != nil {
		return nil, err
	}
	return secret, nil
}
