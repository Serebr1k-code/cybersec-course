package api

import (
	"errors"
	"net/http"
	"strings"

	"learningtree/internal/auth"
	"learningtree/internal/progress"
)

// Cookie / header names used for the session and the legacy anonymous id.
const (
	sessionCookieName = "lt_session"
	anonCookieName    = "lt_uid"
)

// progressKeyForUser namespaces an authenticated account's progress document so
// it can never collide with a raw anonymous cookie id.
func progressKeyForUser(id string) string { return "u_" + id }

// bearerToken extracts a token from "Authorization: Bearer <t>".
func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

// requestToken returns the session token from the Bearer header, falling back to
// the httpOnly session cookie.
func requestToken(r *http.Request) string {
	if t := bearerToken(r); t != "" {
		return t
	}
	if c, err := r.Cookie(sessionCookieName); err == nil {
		return c.Value
	}
	return ""
}

// currentUser resolves the authenticated account for a request, if any.
func (s *Server) currentUser(r *http.Request) (*auth.User, bool) {
	if s.Auth == nil || s.Sessions == nil {
		return nil, false
	}
	tok := requestToken(r)
	if tok == "" {
		return nil, false
	}
	uid, ok := s.Sessions.Verify(tok)
	if !ok {
		return nil, false
	}
	return s.Auth.ByID(uid)
}

// setSessionCookie writes the signed session cookie. Secure is set only when the
// request itself arrived over TLS, so local plain-HTTP development still works.
func (s *Server) setSessionCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(s.Sessions.TTL().Seconds()),
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

type authReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// startSession issues a token, sets the cookie and folds any anonymous progress
// (the lt_uid cookie) into the account. Returns the token for the JSON body so
// the SPA can also authenticate with a Bearer header.
func (s *Server) startSession(w http.ResponseWriter, r *http.Request, u *auth.User) string {
	token := s.Sessions.Issue(u.ID)
	s.setSessionCookie(w, r, token)
	if c, err := r.Cookie(anonCookieName); err == nil && c.Value != "" {
		s.mergeProgress(c.Value, progressKeyForUser(u.ID))
	}
	return token
}

// mergeProgress unions the anonymous profile into the account profile, taking
// the best of each field so nothing the learner did while logged out is lost.
func (s *Server) mergeProgress(anonID, acctKey string) {
	if anonID == "" || anonID == acctKey {
		return
	}
	anon := s.Progress.Get(anonID)
	if len(anon.Lessons) == 0 && len(anon.Activity) == 0 && len(anon.Hours) == 0 {
		return
	}
	acct := s.Progress.Get(acctKey)
	for id, al := range anon.Lessons {
		if al == nil {
			continue
		}
		cl := acct.Lesson(id)
		for sid, as := range al.Sections {
			if as == nil {
				continue
			}
			cs := cl.Sections[sid]
			if cs == nil {
				cs = &progress.SectionProgress{}
				cl.Sections[sid] = cs
			}
			if as.ReadSeconds > cs.ReadSeconds {
				cs.ReadSeconds = as.ReadSeconds
			}
			cs.Read = cs.Read || as.Read
			if as.UpdatedAt > cs.UpdatedAt {
				cs.UpdatedAt = as.UpdatedAt
			}
		}
		if al.Completed {
			cl.Completed = true
		}
		if al.QuizBest > cl.QuizBest {
			cl.QuizBest = al.QuizBest
		}
		if al.QuizTotal > cl.QuizTotal {
			cl.QuizTotal = al.QuizTotal
		}
		cl.QuizAttempts += al.QuizAttempts
		cl.QuizFails += al.QuizFails
		if strings.TrimSpace(cl.Notes) == "" && strings.TrimSpace(al.Notes) != "" {
			cl.Notes = al.Notes
		}
		if al.UpdatedAt > cl.UpdatedAt {
			cl.UpdatedAt = al.UpdatedAt
		}
	}
	for d, n := range anon.Activity {
		acct.Activity[d] += n
	}
	for h, n := range anon.Hours {
		acct.Hours[h] += n
	}
	acct.ComputeXP()
	_ = s.Progress.Save(acct)
}

// handleRegister creates an account and logs the caller in.
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if s.Auth == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "auth disabled"})
		return
	}
	var req authReq
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	u, err := s.Auth.Register(req.Username, req.Password)
	if err != nil {
		code := http.StatusBadRequest
		if errors.Is(err, auth.ErrUserExists) {
			code = http.StatusConflict
		}
		writeJSON(w, code, map[string]string{"error": err.Error()})
		return
	}
	token := s.startSession(w, r, u)
	writeJSON(w, http.StatusOK, map[string]any{"user": u.Public(), "token": token})
}

// handleLogin verifies credentials and logs the caller in.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if s.Auth == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "auth disabled"})
		return
	}
	var req authReq
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	u, err := s.Auth.Authenticate(req.Username, req.Password)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid username or password"})
		return
	}
	token := s.startSession(w, r, u)
	writeJSON(w, http.StatusOK, map[string]any{"user": u.Public(), "token": token})
}

// handleLogout clears the session cookie.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.clearSessionCookie(w, r)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleMe reports the current session (or user:null when logged out).
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	u, ok := s.currentUser(r)
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{"user": nil})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": u.Public()})
}
