package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base32"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"strings"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq" // registers the "postgres" driver with database/sql
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
	db          *sql.DB
	tableName   string
	driver      string
	placeholder func(n int) string
}

func questionMark(_ int) string { return "?" }

func dollarN(n int) string { return fmt.Sprintf("$%d", n) }

func (d *Database) ph(n int) string { return d.placeholder(n) }

func schemaSQL(driver, tableName string) string {
	switch driver {
	case "postgres":
		return fmt.Sprintf(`
			CREATE TABLE IF NOT EXISTS %s (
				id     BIGSERIAL PRIMARY KEY,
				name   TEXT NOT NULL UNIQUE,
				secret TEXT NOT NULL UNIQUE,
				ativo  INTEGER NOT NULL DEFAULT 1
			)`, tableName)
	case "mysql":
		return fmt.Sprintf(`
			CREATE TABLE IF NOT EXISTS %s (
				id     INT NOT NULL AUTO_INCREMENT,
				name   TEXT NOT NULL,
				secret TEXT NOT NULL,
				ativo  INTEGER NOT NULL DEFAULT 1,
				PRIMARY KEY (id),
				UNIQUE KEY uq_name (name(191)),
				UNIQUE KEY uq_secret (secret(191))
			) ENGINE=InnoDB`, tableName)
	default:
		return fmt.Sprintf(`
			CREATE TABLE IF NOT EXISTS %s (
				id     INTEGER PRIMARY KEY AUTOINCREMENT,
				name   TEXT NOT NULL UNIQUE,
				secret TEXT NOT NULL UNIQUE,
				ativo  INTEGER NOT NULL DEFAULT 1
			)`, tableName)
	}
}

func initDB(cfg Config) (*Database, error) {
	if !validTableName.MatchString(cfg.TableName) {
		return nil, fmt.Errorf("invalid TABLE_NAME: %q", cfg.TableName)
	}

	var driver, dsn string
	switch {
	case cfg.DBHost != "" && strings.ToLower(cfg.DBDriver) == "postgres":
		driver = "postgres"
		u := url.URL{
			Scheme: "postgres",
			User:   url.UserPassword(cfg.DBUser, cfg.DBPassword),
			Host:   cfg.DBHost,
			Path:   "/" + cfg.DBDatabase,
		}
		dsn = u.String()
		slog.Info("using PostgreSQL", "host", cfg.DBHost, "db", cfg.DBDatabase)
	case cfg.DBHost != "":
		driver = "mysql"
		password := url.QueryEscape(cfg.DBPassword)
		dsn = fmt.Sprintf("%s:%s@tcp(%s)/%s?parseTime=true&timeout=5s",
			cfg.DBUser, password, cfg.DBHost, cfg.DBDatabase)
		slog.Info("using MySQL", "host", cfg.DBHost, "db", cfg.DBDatabase)
	default:
		driver = "sqlite"
		dsn = cfg.SQLitePath
		slog.Info("using SQLite", "path", cfg.SQLitePath)
	}

	db, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("ping db: %w", err)
	}

	if driver == "sqlite" {
		if _, err := db.Exec(`PRAGMA journal_mode=WAL`); err != nil {
			return nil, fmt.Errorf("set journal_mode: %w", err)
		}
		if _, err := db.Exec(`PRAGMA busy_timeout=5000`); err != nil {
			return nil, fmt.Errorf("set busy_timeout: %w", err)
		}
	}

	ph := questionMark
	if driver == "postgres" {
		ph = dollarN
	}

	d := &Database{db: db, tableName: cfg.TableName, driver: driver, placeholder: ph}
	if err := d.createSchema(); err != nil {
		return nil, fmt.Errorf("create schema: %w", err)
	}
	return d, nil
}

func (d *Database) Close() error { return d.db.Close() }

func (d *Database) Ping() error { return d.db.Ping() }

func (d *Database) createSchema() error {
	_, err := d.db.Exec(schemaSQL(d.driver, d.tableName))
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
	defer rows.Close() //nolint:errcheck

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
		`SELECT id, name, secret, ativo FROM %s WHERE id = %s`, d.tableName, d.ph(1),
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
		`SELECT id, name, secret, ativo FROM %s WHERE name = %s`, d.tableName, d.ph(1),
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
		`INSERT INTO %s (name, secret, ativo) VALUES (%s, %s, 1)`, d.tableName, d.ph(1), d.ph(2),
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
			`UPDATE %s SET name = %s, ativo = %s WHERE id = %s`, d.tableName, d.ph(1), d.ph(2), d.ph(3),
		), u.Name, activeInt, u.ID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (d *Database) deleteToken(id int64) error {
	_, err := d.db.Exec(fmt.Sprintf(
		`DELETE FROM %s WHERE id = %s`, d.tableName, d.ph(1),
	), id)
	return err
}

func (d *Database) nameExistsExcept(name string, exceptID int64) (bool, error) {
	var count int
	err := d.db.QueryRow(fmt.Sprintf(
		`SELECT COUNT(*) FROM %s WHERE name = %s AND id != %s`, d.tableName, d.ph(1), d.ph(2),
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

type importEntry struct {
	name   string
	secret string
}

func (d *Database) importTokens(entries []importEntry) (imported, skipped int, err error) {
	tx, err := d.db.Begin()
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback() //nolint:errcheck

	for _, e := range entries {
		var count int
		if err := tx.QueryRow(fmt.Sprintf(
			`SELECT COUNT(*) FROM %s WHERE name = %s`, d.tableName, d.ph(1),
		), e.name).Scan(&count); err != nil {
			return imported, skipped, err
		}
		if count > 0 {
			skipped++
			continue
		}
		if _, err := tx.Exec(fmt.Sprintf(
			`INSERT INTO %s (name, secret, ativo) VALUES (%s, %s, 1)`, d.tableName, d.ph(1), d.ph(2),
		), e.name, e.secret); err != nil {
			return imported, skipped, err
		}
		imported++
	}
	return imported, skipped, tx.Commit()
}

func randomBase32Secret() string {
	b := make([]byte, 20)
	rand.Read(b) //nolint:errcheck
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
}
