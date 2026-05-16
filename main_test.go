package main

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestSecurityHeaders(t *testing.T) {
	handler := securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if got := w.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
	}
	if got := w.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("X-Frame-Options = %q, want DENY", got)
	}
	if w.Header().Get("Content-Security-Policy") == "" {
		t.Error("Content-Security-Policy header not set")
	}
}

func TestEnvOr(t *testing.T) {
	const key = "TEST_ENVOR_KEY_MFA_APP"
	t.Setenv(key, "")

	if got := envOr(key, "default"); got != "default" {
		t.Fatalf("want default, got %q", got)
	}

	t.Setenv(key, "custom")
	if got := envOr(key, "default"); got != "custom" {
		t.Fatalf("want custom, got %q", got)
	}
}

func TestInitLogger(t *testing.T) {
	for _, level := range []string{"DEBUG", "WARN", "WARNING", "ERROR", "INFO", "invalid"} {
		t.Run(level, func(t *testing.T) {
			initLogger(level) // must not panic
		})
	}
}

func TestLoadConfig_Defaults(t *testing.T) {
	for _, key := range []string{
		"APP_NAME", "SECRET_KEY", "EDIT_PASS", "REGISTER_ABLE",
		"MAX_UPLOAD_MB", "DEMO_MODE", "LOG_LEVEL", "PORT",
		"DB_HOST", "DB_USER", "DB_PASSWORD", "DB_DATABASE",
		"TABLE_NAME", "SQLITE_PATH",
	} {
		t.Setenv(key, "")
	}

	cfg := loadConfig()

	if cfg.AppName != "MFA Tokens" {
		t.Errorf("AppName = %q, want MFA Tokens", cfg.AppName)
	}
	if len(cfg.SecretKey) == 0 {
		t.Error("SecretKey should be auto-generated when not set")
	}
	if cfg.MaxUploadMB != 5 {
		t.Errorf("MaxUploadMB = %d, want 5", cfg.MaxUploadMB)
	}
	if !cfg.RegisterAble {
		t.Error("RegisterAble should default to true")
	}
	if cfg.TableName != "mfa_tokens" {
		t.Errorf("TableName = %q, want mfa_tokens", cfg.TableName)
	}
}

func TestLoadConfig_WithValues(t *testing.T) {
	t.Setenv("APP_NAME", "My App")
	t.Setenv("SECRET_KEY", "my-secret-key")
	t.Setenv("REGISTER_ABLE", "false")
	t.Setenv("MAX_UPLOAD_MB", "10")
	t.Setenv("DEMO_MODE", "true")
	t.Setenv("TABLE_NAME", "my_tokens")

	cfg := loadConfig()

	if cfg.AppName != "My App" {
		t.Errorf("AppName = %q, want My App", cfg.AppName)
	}
	if string(cfg.SecretKey) != "my-secret-key" {
		t.Errorf("SecretKey = %q, want my-secret-key", cfg.SecretKey)
	}
	if cfg.RegisterAble {
		t.Error("RegisterAble should be false")
	}
	if cfg.MaxUploadMB != 10 {
		t.Errorf("MaxUploadMB = %d, want 10", cfg.MaxUploadMB)
	}
	if !cfg.DemoMode {
		t.Error("DemoMode should be true")
	}
	if cfg.TableName != "my_tokens" {
		t.Errorf("TableName = %q, want my_tokens", cfg.TableName)
	}
}

func TestInitDB_InvalidTableName(t *testing.T) {
	cfg := Config{
		TableName:  "invalid-name!",
		SQLitePath: filepath.Join(t.TempDir(), "test.db"),
	}
	_, err := initDB(cfg)
	if err == nil {
		t.Fatal("expected error for invalid table name")
	}
}

func TestSeedDemo(t *testing.T) {
	app := testApp(t)

	if err := app.db.seedDemo(app.cfg); err != nil {
		t.Fatalf("seedDemo: %v", err)
	}
	tokens, err := app.db.allTokens()
	if err != nil {
		t.Fatalf("allTokens: %v", err)
	}
	if len(tokens) != len(demoTokenNames) {
		t.Fatalf("want %d demo tokens, got %d", len(demoTokenNames), len(tokens))
	}

	// second call is a no-op when table is not empty
	if err := app.db.seedDemo(app.cfg); err != nil {
		t.Fatalf("second seedDemo: %v", err)
	}
	tokens2, _ := app.db.allTokens()
	if len(tokens2) != len(demoTokenNames) {
		t.Fatal("second seedDemo should not duplicate tokens")
	}
}
