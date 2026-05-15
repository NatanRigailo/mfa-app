package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base32"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"

	_ "github.com/go-sql-driver/mysql"
	_ "modernc.org/sqlite"
)

var validTableName = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

type Token struct {
	ID     int64
	Name   string
	Secret string
	Active bool
}

type TokenUpdate struct {
	ID     int64
	Name   string
	Active bool
}

type Database struct {
	db        *sql.DB
	tableName string
}

func initDB(cfg Config) (*Database, error) {
	if !validTableName.MatchString(cfg.TableName) {
		return nil, fmt.Errorf("invalid TABLE_NAME: %q", cfg.TableName)
	}

	var driver, dsn string
	if cfg.DBHost != "" {
		driver = "mysql"
		password := url.QueryEscape(cfg.DBPassword)
		dsn = fmt.Sprintf("%s:%s@tcp(%s)/%s?parseTime=true&timeout=5s",
			cfg.DBUser, password, cfg.DBHost, cfg.DBDatabase)
		slog.Info("using MySQL", "host", cfg.DBHost, "db", cfg.DBDatabase)
	} else {
		driver = "sqlite"
		dsn = "file:/data/tokens.db?_busy_timeout=5000&_journal_mode=WAL"
		slog.Info("using SQLite", "path", "/data/tokens.db")
	}

	db, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("ping db: %w", err)
	}

	d := &Database{db: db, tableName: cfg.TableName}
	if err := d.createSchema(); err != nil {
		return nil, fmt.Errorf("create schema: %w", err)
	}
	return d, nil
}

func (d *Database) Close() { d.db.Close() }

func (d *Database) Ping() error { return d.db.Ping() }

func (d *Database) createSchema() error {
	_, err := d.db.Exec(fmt.Sprintf(`
		CREATE TABLE IF NOT EXISTS %s (
			id     INTEGER PRIMARY KEY AUTOINCREMENT,
			name   TEXT NOT NULL UNIQUE,
			secret TEXT NOT NULL UNIQUE,
			ativo  INTEGER NOT NULL DEFAULT 1
		)`, d.tableName))
	return err
}

func (d *Database) allTokens() ([]Token, error) {
	return d.queryTokens(fmt.Sprintf(
		`SELECT id, name, secret, ativo FROM %s ORDER BY name`, d.tableName,
	))
}

func (d *Database) activeTokens() ([]Token, error) {
	return d.queryTokens(fmt.Sprintf(
		`SELECT id, name, secret, ativo FROM %s WHERE ativo = 1 ORDER BY name`, d.tableName,
	))
}

func (d *Database) queryTokens(query string, args ...any) ([]Token, error) {
	rows, err := d.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tokens []Token
	for rows.Next() {
		var t Token
		var active int
		if err := rows.Scan(&t.ID, &t.Name, &t.Secret, &active); err != nil {
			return nil, err
		}
		t.Active = active != 0
		tokens = append(tokens, t)
	}
	return tokens, rows.Err()
}

func (d *Database) getToken(id int64) (*Token, error) {
	var t Token
	var active int
	err := d.db.QueryRow(fmt.Sprintf(
		`SELECT id, name, secret, ativo FROM %s WHERE id = ?`, d.tableName,
	), id).Scan(&t.ID, &t.Name, &t.Secret, &active)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	t.Active = active != 0
	return &t, nil
}

func (d *Database) tokenByName(name string) (*Token, error) {
	var t Token
	var active int
	err := d.db.QueryRow(fmt.Sprintf(
		`SELECT id, name, secret, ativo FROM %s WHERE name = ?`, d.tableName,
	), name).Scan(&t.ID, &t.Name, &t.Secret, &active)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	t.Active = active != 0
	return &t, nil
}

func (d *Database) createToken(name, secret string) error {
	_, err := d.db.Exec(fmt.Sprintf(
		`INSERT INTO %s (name, secret, ativo) VALUES (?, ?, 1)`, d.tableName,
	), name, secret)
	return err
}

func (d *Database) updateTokens(updates []TokenUpdate) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	for _, u := range updates {
		activeInt := 0
		if u.Active {
			activeInt = 1
		}
		if _, err := tx.Exec(fmt.Sprintf(
			`UPDATE %s SET name = ?, ativo = ? WHERE id = ?`, d.tableName,
		), u.Name, activeInt, u.ID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (d *Database) deleteToken(id int64) error {
	_, err := d.db.Exec(fmt.Sprintf(
		`DELETE FROM %s WHERE id = ?`, d.tableName,
	), id)
	return err
}

func (d *Database) nameExistsExcept(name string, exceptID int64) (bool, error) {
	var count int
	err := d.db.QueryRow(fmt.Sprintf(
		`SELECT COUNT(*) FROM %s WHERE name = ? AND id != ?`, d.tableName,
	), name, exceptID).Scan(&count)
	return count > 0, err
}

var demoTokenNames = []string{
	"AWS – Produção", "AWS – Staging", "GitHub", "Google Workspace",
	"Cloudflare", "Datadog", "Grafana", "Terraform Cloud",
	"Slack", "Linear", "Vercel", "PagerDuty",
}

func (d *Database) seedDemo(cfg Config) error {
	var count int
	if err := d.db.QueryRow(fmt.Sprintf(
		`SELECT COUNT(*) FROM %s`, d.tableName,
	)).Scan(&count); err != nil || count > 0 {
		return err
	}

	for _, name := range demoTokenNames {
		secret := randomBase32Secret()
		if err := d.createToken(name, secret); err != nil {
			slog.Warn("demo seed: create token failed", "name", name, "err", err)
		}
	}
	slog.Info("demo: seeded tokens", "count", len(demoTokenNames))
	return nil
}

func randomBase32Secret() string {
	b := make([]byte, 20)
	rand.Read(b) //nolint:errcheck
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
}
