package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestSignVerifyMAC_RoundTrip(t *testing.T) {
	key := []byte("test-key")
	data := []byte(`{"e":true,"c":"csrf"}`)

	signed := signMAC(key, data)
	got, ok := verifyMAC(key, signed)
	if !ok {
		t.Fatal("verifyMAC returned false for valid signed value")
	}
	if string(got) != string(data) {
		t.Fatalf("got %q, want %q", got, data)
	}
}

func TestVerifyMAC_WrongKey(t *testing.T) {
	signed := signMAC([]byte("key-a"), []byte("payload"))
	_, ok := verifyMAC([]byte("key-b"), signed)
	if ok {
		t.Fatal("verifyMAC should reject wrong key")
	}
}

func TestVerifyMAC_TamperedData(t *testing.T) {
	key := []byte("test-key")
	signed := signMAC(key, []byte("original"))
	dot := strings.LastIndex(signed, ".")
	_, ok := verifyMAC(key, signed[:dot]+"AAAA"+signed[dot:])
	if ok {
		t.Fatal("verifyMAC should reject tampered data")
	}
}

func TestVerifyMAC_NoDot(t *testing.T) {
	_, ok := verifyMAC([]byte("key"), "nodot")
	if ok {
		t.Fatal("verifyMAC should reject value without dot separator")
	}
}

func TestValidCSRF(t *testing.T) {
	tests := []struct {
		name   string
		token  string
		stored string
		want   bool
	}{
		{"match", "abc123", "abc123", true},
		{"mismatch", "abc123", "xyz789", false},
		{"empty_token", "", "abc123", false},
		{"empty_stored", "abc123", "", false},
		{"both_empty", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Session{CSRFToken: tt.stored}
			if got := s.validCSRF(tt.token); got != tt.want {
				t.Fatalf("validCSRF(%q) = %v, want %v", tt.token, got, tt.want)
			}
		})
	}
}

func TestAddPopFlashes(t *testing.T) {
	s := Session{}
	s.addFlash("info", "hello")
	s.addFlash("error", "world")

	got := s.popFlashes()
	if len(got) != 2 {
		t.Fatalf("want 2 flashes, got %d", len(got))
	}
	if got[0].Category != "info" || got[0].Message != "hello" {
		t.Errorf("first flash = %+v, want {info hello}", got[0])
	}
	if len(s.Flashes) != 0 {
		t.Fatal("popFlashes should clear the slice")
	}
	if s.popFlashes() != nil {
		t.Fatal("second pop should return nil")
	}
}

func TestGetSession_NoCookie(t *testing.T) {
	r, _ := http.NewRequest("GET", "/", nil)
	s := getSession(r, []byte("key"))
	if s.CSRFToken == "" {
		t.Fatal("new session must have a CSRF token")
	}
	if s.EditMode {
		t.Fatal("new session must not be in edit mode")
	}
}

func TestGetSession_ValidCookie(t *testing.T) {
	key := []byte("test-key")
	sess := Session{EditMode: true, CSRFToken: "stored-csrf"}
	data, _ := json.Marshal(sess)

	r, _ := http.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: signMAC(key, data)})

	got := getSession(r, key)
	if !got.EditMode {
		t.Fatal("expected EditMode=true from cookie")
	}
	if got.CSRFToken != "stored-csrf" {
		t.Fatalf("expected CSRFToken=stored-csrf, got %q", got.CSRFToken)
	}
}

func TestGetSession_TamperedCookie(t *testing.T) {
	key := []byte("test-key")
	r, _ := http.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "tampered.value"})

	got := getSession(r, key)
	if got.EditMode {
		t.Fatal("tampered cookie should yield a fresh session")
	}
}

func TestGetSession_EmptyCSRFInSession(t *testing.T) {
	key := []byte("test-key")
	// valid session but CSRFToken is empty — should be regenerated
	sess := Session{EditMode: true}
	data, _ := json.Marshal(sess)

	r, _ := http.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: signMAC(key, data)})

	got := getSession(r, key)
	if !got.EditMode {
		t.Fatal("should preserve EditMode from session")
	}
	if got.CSRFToken == "" {
		t.Fatal("should generate CSRF token when missing from session")
	}
}
