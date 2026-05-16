package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// testApp creates an isolated App backed by a temp SQLite database.
func testApp(t *testing.T) *App {
	t.Helper()
	cfg := Config{
		AppName:      "Test MFA",
		SecretKey:    []byte("test-secret-key-32bytes-padding!!"),
		RegisterAble: true,
		MaxUploadMB:  5,
		TableName:    "mfa_tokens",
		SQLitePath:   filepath.Join(t.TempDir(), "test.db"),
	}
	db, err := initDB(cfg)
	if err != nil {
		t.Fatalf("initDB: %v", err)
	}
	t.Cleanup(func() { db.Close() }) //nolint:errcheck

	app := &App{cfg: cfg, db: db}
	if err := app.loadTemplates(); err != nil {
		t.Fatalf("loadTemplates: %v", err)
	}
	return app
}

// signedCookie returns a signed session cookie for use in test requests.
func signedCookie(key []byte, s Session) *http.Cookie {
	data, _ := json.Marshal(s)
	return &http.Cookie{Name: sessionCookieName, Value: signMAC(key, data)}
}

// responseSession reads the session written to w's Set-Cookie header.
func responseSession(t *testing.T, key []byte, w *httptest.ResponseRecorder) Session {
	t.Helper()
	r := &http.Request{Header: http.Header{}}
	for _, c := range w.Result().Cookies() {
		r.AddCookie(c)
	}
	return getSession(r, key)
}

// multipartRequest builds a POST /register request with multipart/form-data body.
func multipartRequest(t *testing.T, fields map[string]string) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for k, v := range fields {
		if err := mw.WriteField(k, v); err != nil {
			t.Fatalf("multipart write field %q: %v", k, err)
		}
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("multipart close: %v", err)
	}
	r := httptest.NewRequest("POST", "/register", &buf)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	return r
}

// --- Pure function tests ---

func TestGroupTokens(t *testing.T) {
	tokens := []Token{
		{Name: "GitHub"},
		{Name: "AWS"},
		{Name: "Azure"},
		{Name: "Cloudflare"},
	}
	groups := groupTokens(tokens)

	if len(groups) != 3 { // A, C, G
		t.Fatalf("want 3 letter groups, got %d", len(groups))
	}
	if groups[0].Letter != "A" {
		t.Fatalf("first group should be A, got %q", groups[0].Letter)
	}
	if len(groups[0].Tokens) != 2 {
		t.Fatalf("group A should have 2 tokens (AWS, Azure), got %d", len(groups[0].Tokens))
	}
}

func TestGroupTokens_EmptyName(t *testing.T) {
	tokens := []Token{{Name: "GitHub"}, {Name: ""}}
	groups := groupTokens(tokens)
	if len(groups) != 1 {
		t.Fatalf("empty-name token should be skipped, want 1 group got %d", len(groups))
	}
}

func TestExtractSecretFromURI(t *testing.T) {
	tests := []struct {
		uri  string
		want string
	}{
		{"otpauth://totp/Example:user@host?secret=JBSWY3DPEHPK3PXP&issuer=Ex", "JBSWY3DPEHPK3PXP"},
		{"otpauth://totp/Example?secret=", ""},
		{"otpauth://hotp/Example?secret=JBSWY3DPEHPK3PXP", ""},
		{"https://example.com?secret=JBSWY3DPEHPK3PXP", ""},
		{"", ""},
		{"otpauth://totp/", ""},
	}
	for _, tt := range tests {
		got := extractSecretFromURI(tt.uri)
		if got != tt.want {
			t.Errorf("extractSecretFromURI(%q) = %q, want %q", tt.uri, got, tt.want)
		}
	}
}

func TestSanitizeSecret(t *testing.T) {
	const knownValid = "JBSWY3DPEHPK3PXP"
	tests := []struct {
		input string
		empty bool
	}{
		{knownValid, false},
		{strings.ToLower(knownValid), false},  // lowercase normalized
		{"JBS WY3D PEHP K3PX P", false},       // spaces stripped
		{"INVALID!@#$", true},
		{"", true},
	}
	for _, tt := range tests {
		got := sanitizeSecret(tt.input)
		if tt.empty && got != "" {
			t.Errorf("sanitizeSecret(%q) = %q, want empty", tt.input, got)
		}
		if !tt.empty && got == "" {
			t.Errorf("sanitizeSecret(%q) = empty, want non-empty", tt.input)
		}
	}
}

// --- Handler integration tests ---

func TestHealthz(t *testing.T) {
	app := testApp(t)
	r := httptest.NewRequest("GET", "/healthz", nil)
	w := httptest.NewRecorder()
	app.healthz(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	var body map[string]string
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body["status"] != "ok" {
		t.Fatalf("want status=ok, got %q", body["status"])
	}
}

func TestGetNewCodes(t *testing.T) {
	app := testApp(t)
	if err := app.db.createToken("GitHub", randomBase32Secret()); err != nil {
		t.Fatalf("seed token: %v", err)
	}

	r := httptest.NewRequest("GET", "/get_new_codes", nil)
	w := httptest.NewRecorder()
	app.getNewCodes(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	var body struct {
		Codes map[string]string `json:"codes"`
	}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if _, ok := body.Codes["GitHub"]; !ok {
		t.Fatal("response should contain code for GitHub")
	}
}

func TestGetNewCodes_InactiveExcluded(t *testing.T) {
	app := testApp(t)
	if err := app.db.createToken("Active", randomBase32Secret()); err != nil {
		t.Fatalf("seed active: %v", err)
	}
	// create then deactivate
	if err := app.db.createToken("Inactive", randomBase32Secret()); err != nil {
		t.Fatalf("seed inactive: %v", err)
	}
	tokens, _ := app.db.allTokens()
	for _, tok := range tokens {
		if tok.Name == "Inactive" {
			app.db.updateTokens([]TokenUpdate{{ID: tok.ID, Name: tok.Name, Active: false}}) //nolint:errcheck
		}
	}

	r := httptest.NewRequest("GET", "/get_new_codes", nil)
	w := httptest.NewRecorder()
	app.getNewCodes(w, r)

	var body struct {
		Codes map[string]string `json:"codes"`
	}
	json.NewDecoder(w.Body).Decode(&body) //nolint:errcheck
	if _, ok := body.Codes["Inactive"]; ok {
		t.Fatal("inactive token should not appear in codes")
	}
}

func TestIndex(t *testing.T) {
	app := testApp(t)
	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	app.index(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
}

func TestRegisterGet_Enabled(t *testing.T) {
	app := testApp(t)
	r := httptest.NewRequest("GET", "/register", nil)
	w := httptest.NewRecorder()
	app.registerGet(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), `name="secret"`) {
		t.Fatal("register page should contain secret input")
	}
}

func TestRegisterGet_Disabled(t *testing.T) {
	app := testApp(t)
	app.cfg.RegisterAble = false
	r := httptest.NewRequest("GET", "/register", nil)
	w := httptest.NewRecorder()
	app.registerGet(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	if strings.Contains(w.Body.String(), `name="secret"`) {
		t.Fatal("disabled register page should not contain secret input")
	}
}

func TestRegisterPost_ValidSecret(t *testing.T) {
	app := testApp(t)
	csrf := "test-csrf"
	cookie := signedCookie(app.cfg.SecretKey, Session{CSRFToken: csrf})

	r := multipartRequest(t, map[string]string{
		"csrf_token": csrf,
		"name":       "GitHub",
		"secret":     randomBase32Secret(),
	})
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	app.registerPost(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("want 303, got %d", w.Code)
	}
	if w.Header().Get("Location") != "/" {
		t.Fatalf("want redirect to /, got %q", w.Header().Get("Location"))
	}
}

func TestRegisterPost_InvalidSecret(t *testing.T) {
	app := testApp(t)
	csrf := "test-csrf"
	cookie := signedCookie(app.cfg.SecretKey, Session{CSRFToken: csrf})

	r := multipartRequest(t, map[string]string{
		"csrf_token": csrf,
		"name":       "GitHub",
		"secret":     "NOTVALIDBASE32!!!",
	})
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	app.registerPost(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("want 303, got %d", w.Code)
	}
	sess := responseSession(t, app.cfg.SecretKey, w)
	if len(sess.Flashes) == 0 || sess.Flashes[0].Category != "error" {
		t.Fatal("expected error flash for invalid secret")
	}
}

func TestRegisterPost_DuplicateName(t *testing.T) {
	app := testApp(t)
	if err := app.db.createToken("GitHub", randomBase32Secret()); err != nil {
		t.Fatalf("seed: %v", err)
	}

	csrf := "test-csrf"
	cookie := signedCookie(app.cfg.SecretKey, Session{CSRFToken: csrf})
	r := multipartRequest(t, map[string]string{
		"csrf_token": csrf,
		"name":       "GitHub",
		"secret":     randomBase32Secret(),
	})
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	app.registerPost(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("want 303, got %d", w.Code)
	}
	sess := responseSession(t, app.cfg.SecretKey, w)
	if len(sess.Flashes) == 0 || sess.Flashes[0].Category != "error" {
		t.Fatal("expected error flash for duplicate name")
	}
}

func TestRegisterPost_NoCSRF(t *testing.T) {
	app := testApp(t)
	csrf := "real-csrf"
	cookie := signedCookie(app.cfg.SecretKey, Session{CSRFToken: csrf})

	r := multipartRequest(t, map[string]string{
		"name":   "GitHub",
		"secret": randomBase32Secret(),
		// no csrf_token
	})
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	app.registerPost(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("want 303, got %d", w.Code)
	}
	sess := responseSession(t, app.cfg.SecretKey, w)
	if len(sess.Flashes) == 0 || sess.Flashes[0].Category != "error" {
		t.Fatal("expected CSRF error flash")
	}
}

func TestRegisterPost_Disabled(t *testing.T) {
	app := testApp(t)
	app.cfg.RegisterAble = false
	r := httptest.NewRequest("POST", "/register", nil)
	w := httptest.NewRecorder()
	app.registerPost(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("want 303, got %d", w.Code)
	}
	if w.Header().Get("Location") != "/" {
		t.Fatalf("want redirect to /, got %q", w.Header().Get("Location"))
	}
}

func TestToggleEdit_WrongPassword(t *testing.T) {
	app := testApp(t)
	app.cfg.EditPass = "correct"
	csrf := "csrf-token"
	cookie := signedCookie(app.cfg.SecretKey, Session{CSRFToken: csrf})

	form := url.Values{"csrf_token": {csrf}, "palavra": {"wrong"}}
	r := httptest.NewRequest("POST", "/toggle_edit", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	app.toggleEdit(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("want 303, got %d", w.Code)
	}
	sess := responseSession(t, app.cfg.SecretKey, w)
	if sess.EditMode {
		t.Fatal("wrong password should not activate edit mode")
	}
}

func TestToggleEdit_CorrectPassword(t *testing.T) {
	app := testApp(t)
	app.cfg.EditPass = "correct"
	csrf := "csrf-token"
	cookie := signedCookie(app.cfg.SecretKey, Session{CSRFToken: csrf})

	form := url.Values{"csrf_token": {csrf}, "palavra": {"correct"}}
	r := httptest.NewRequest("POST", "/toggle_edit", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	app.toggleEdit(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("want 303, got %d", w.Code)
	}
	sess := responseSession(t, app.cfg.SecretKey, w)
	if !sess.EditMode {
		t.Fatal("correct password should activate edit mode")
	}
}

func TestToggleEdit_TurnOff(t *testing.T) {
	app := testApp(t)
	csrf := "csrf-token"
	cookie := signedCookie(app.cfg.SecretKey, Session{EditMode: true, CSRFToken: csrf})

	form := url.Values{"csrf_token": {csrf}}
	r := httptest.NewRequest("POST", "/toggle_edit", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	app.toggleEdit(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("want 303, got %d", w.Code)
	}
	sess := responseSession(t, app.cfg.SecretKey, w)
	if sess.EditMode {
		t.Fatal("toggle off should deactivate edit mode")
	}
}

func TestToggleEdit_NoCSRF(t *testing.T) {
	app := testApp(t)
	form := url.Values{"palavra": {"anything"}}
	r := httptest.NewRequest("POST", "/toggle_edit", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	app.toggleEdit(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("want 303, got %d", w.Code)
	}
	sess := responseSession(t, app.cfg.SecretKey, w)
	if len(sess.Flashes) == 0 || sess.Flashes[0].Category != "error" {
		t.Fatal("expected CSRF error flash")
	}
}

func TestDeleteToken_NotInEditMode(t *testing.T) {
	app := testApp(t)
	csrf := "csrf-token"
	cookie := signedCookie(app.cfg.SecretKey, Session{CSRFToken: csrf, EditMode: false})

	form := url.Values{"csrf_token": {csrf}}
	r := httptest.NewRequest("POST", "/delete/1", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue("id", "1")
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	app.deleteToken(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("want 303, got %d", w.Code)
	}
	sess := responseSession(t, app.cfg.SecretKey, w)
	if len(sess.Flashes) == 0 || sess.Flashes[0].Category != "error" {
		t.Fatal("expected access denied error flash")
	}
}

func TestDeleteToken_InEditMode(t *testing.T) {
	app := testApp(t)
	if err := app.db.createToken("GitHub", randomBase32Secret()); err != nil {
		t.Fatalf("seed: %v", err)
	}
	tokens, _ := app.db.allTokens()
	id := tokens[0].ID

	csrf := "csrf-token"
	cookie := signedCookie(app.cfg.SecretKey, Session{EditMode: true, CSRFToken: csrf})

	idStr := strconv.FormatInt(id, 10)
	form := url.Values{"csrf_token": {csrf}}
	r := httptest.NewRequest("POST", "/delete/"+idStr, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue("id", idStr)
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	app.deleteToken(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("want 303, got %d", w.Code)
	}
	sess := responseSession(t, app.cfg.SecretKey, w)
	if len(sess.Flashes) == 0 || sess.Flashes[0].Category != "success" {
		t.Fatalf("expected success flash, got %+v", sess.Flashes)
	}
	remaining, _ := app.db.allTokens()
	if len(remaining) != 0 {
		t.Fatal("token should have been deleted")
	}
}

func TestDeleteToken_NotFound(t *testing.T) {
	app := testApp(t)
	csrf := "csrf-token"
	cookie := signedCookie(app.cfg.SecretKey, Session{EditMode: true, CSRFToken: csrf})

	form := url.Values{"csrf_token": {csrf}}
	r := httptest.NewRequest("POST", "/delete/9999", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetPathValue("id", "9999")
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	app.deleteToken(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("want 303, got %d", w.Code)
	}
}

func TestIndexPost_NotInEditMode(t *testing.T) {
	app := testApp(t)
	csrf := "csrf-token"
	cookie := signedCookie(app.cfg.SecretKey, Session{CSRFToken: csrf, EditMode: false})

	form := url.Values{"csrf_token": {csrf}}
	r := httptest.NewRequest("POST", "/", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	app.indexPost(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("want 303, got %d", w.Code)
	}
	sess := responseSession(t, app.cfg.SecretKey, w)
	if len(sess.Flashes) == 0 || sess.Flashes[0].Category != "error" {
		t.Fatal("expected error flash when not in edit mode")
	}
}

func TestIndexPost_UpdateTokens(t *testing.T) {
	app := testApp(t)
	if err := app.db.createToken("OldName", randomBase32Secret()); err != nil {
		t.Fatalf("seed: %v", err)
	}
	tokens, _ := app.db.allTokens()
	id := tokens[0].ID

	csrf := "csrf-token"
	cookie := signedCookie(app.cfg.SecretKey, Session{EditMode: true, CSRFToken: csrf})

	form := url.Values{
		"csrf_token":                  {csrf},
		fmt.Sprintf("name_%d", id):   {"NewName"},
		fmt.Sprintf("ativo_%d", id):  {"on"},
	}
	r := httptest.NewRequest("POST", "/", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	app.indexPost(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("want 303, got %d", w.Code)
	}
	sess := responseSession(t, app.cfg.SecretKey, w)
	if len(sess.Flashes) == 0 || sess.Flashes[0].Category != "success" {
		t.Fatalf("expected success flash, got %+v", sess.Flashes)
	}
	updated, _ := app.db.allTokens()
	if updated[0].Name != "NewName" {
		t.Fatalf("expected token renamed to NewName, got %q", updated[0].Name)
	}
}
