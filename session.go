package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
)

const sessionCookieName = "sess"

type Session struct {
	EditMode  bool    `json:"e,omitempty"`
	CSRFToken string  `json:"c"`
	Flashes   []Flash `json:"f,omitempty"`
}

type Flash struct {
	Category string `json:"cat"`
	Message  string `json:"msg"`
}

func newSession() Session {
	b := make([]byte, 16)
	rand.Read(b) //nolint:errcheck
	return Session{CSRFToken: base64.RawURLEncoding.EncodeToString(b)}
}

func getSession(r *http.Request, key []byte) Session {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return newSession()
	}
	data, ok := verifyMAC(key, c.Value)
	if !ok {
		return newSession()
	}
	var s Session
	if err := json.Unmarshal(data, &s); err != nil {
		return newSession()
	}
	if s.CSRFToken == "" {
		b := make([]byte, 16)
		rand.Read(b) //nolint:errcheck
		s.CSRFToken = base64.RawURLEncoding.EncodeToString(b)
	}
	return s
}

func saveSession(w http.ResponseWriter, key []byte, s Session) {
	data, _ := json.Marshal(s)
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // #nosec G124 -- Secure omitted intentionally; app supports HTTP deployments
		Name:     sessionCookieName,
		Value:    signMAC(key, data),
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Session) addFlash(category, message string) {
	s.Flashes = append(s.Flashes, Flash{Category: category, Message: message})
}

func (s *Session) popFlashes() []Flash {
	f := s.Flashes
	s.Flashes = nil
	return f
}

func (s *Session) validCSRF(token string) bool {
	if token == "" || s.CSRFToken == "" {
		return false
	}
	return hmac.Equal([]byte(token), []byte(s.CSRFToken))
}

// signMAC returns base64url(data).base64url(hmac-sha256(key, data))
func signMAC(key, data []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return base64.RawURLEncoding.EncodeToString(data) + "." +
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func verifyMAC(key []byte, value string) ([]byte, bool) {
	i := strings.LastIndex(value, ".")
	if i < 0 {
		return nil, false
	}
	data, err1 := base64.RawURLEncoding.DecodeString(value[:i])
	sig, err2 := base64.RawURLEncoding.DecodeString(value[i+1:])
	if err1 != nil || err2 != nil {
		return nil, false
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return nil, false
	}
	return data, true
}
