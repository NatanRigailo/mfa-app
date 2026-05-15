package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type Config struct {
	AppName      string
	SecretKey    []byte
	EditPass     string
	RegisterAble bool
	MaxUploadMB  int64
	DemoMode     bool
	LogLevel     string
	Port         string
	DBHost       string
	DBUser       string
	DBPassword   string
	DBDatabase   string
	TableName    string
	SQLitePath   string
}

func loadConfig() Config {
	maxMB, _ := strconv.ParseInt(os.Getenv("MAX_UPLOAD_MB"), 10, 64)
	if maxMB <= 0 {
		maxMB = 5
	}

	secretKey := []byte(os.Getenv("SECRET_KEY"))
	if len(secretKey) == 0 {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			panic("failed to generate secret key")
		}
		secretKey = b
	}

	return Config{
		AppName:      envOr("APP_NAME", "MFA Tokens"),
		SecretKey:    secretKey,
		EditPass:     os.Getenv("EDIT_PASS"),
		RegisterAble: strings.ToLower(envOr("REGISTER_ABLE", "true")) != "false",
		MaxUploadMB:  maxMB,
		DemoMode:     os.Getenv("DEMO_MODE") == "true",
		LogLevel:     envOr("LOG_LEVEL", "INFO"),
		Port:         envOr("PORT", "5000"),
		DBHost:       os.Getenv("DB_HOST"),
		DBUser:       os.Getenv("DB_USER"),
		DBPassword:   os.Getenv("DB_PASSWORD"),
		DBDatabase:   os.Getenv("DB_DATABASE"),
		TableName:    envOr("TABLE_NAME", "mfa_tokens"),
		SQLitePath:   envOr("SQLITE_PATH", "/data/tokens.db"),
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

type App struct {
	cfg  Config
	db   *Database
	tmpl map[string]*template.Template
}

func (a *App) loadTemplates() error {
	a.tmpl = make(map[string]*template.Template)
	base := filepath.Join("templates", "base.html")
	for _, page := range []string{"index", "register", "register_disabled"} {
		t, err := template.ParseFiles(base, filepath.Join("templates", page+".html"))
		if err != nil {
			return fmt.Errorf("parse template %q: %w", page, err)
		}
		a.tmpl[page] = t
	}
	return nil
}

func (a *App) render(w http.ResponseWriter, page string, data any) {
	t, ok := a.tmpl[page]
	if !ok {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(w, "base.html", data); err != nil {
		slog.Error("template render error", "page", page, "err", err)
	}
}

func main() {
	cfg := loadConfig()
	initLogger(cfg.LogLevel)

	db, err := initDB(cfg)
	if err != nil {
		slog.Error("db init failed", "err", err)
		os.Exit(1)
	}
	defer db.Close()

	if cfg.DemoMode {
		if err := db.seedDemo(cfg); err != nil {
			slog.Warn("demo seed error", "err", err)
		}
	}

	app := &App{cfg: cfg, db: db}
	if err := app.loadTemplates(); err != nil {
		slog.Error("template load failed", "err", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	mux.HandleFunc("GET /healthz", app.healthz)
	mux.HandleFunc("GET /get_new_codes", app.getNewCodes)
	mux.HandleFunc("GET /register", app.registerGet)
	mux.HandleFunc("POST /register", app.registerPost)
	mux.HandleFunc("POST /toggle_edit", app.toggleEdit)
	mux.HandleFunc("POST /delete/{id}", app.deleteToken)
	mux.HandleFunc("GET /{$}", app.index)
	mux.HandleFunc("POST /{$}", app.indexPost)

	srv := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		slog.Info("listening", "port", cfg.Port)
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			slog.Error("server error", "err", err)
			os.Exit(1)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		slog.Error("shutdown error", "err", err)
	}
	slog.Info("server stopped")
}

func initLogger(level string) {
	var lvl slog.Level
	switch strings.ToUpper(level) {
	case "DEBUG":
		lvl = slog.LevelDebug
	case "WARN", "WARNING":
		lvl = slog.LevelWarn
	case "ERROR":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: lvl})))
}
