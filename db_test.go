package main

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestQuestionMark(t *testing.T) {
	for _, n := range []int{1, 2, 99} {
		if got := questionMark(n); got != "?" {
			t.Errorf("questionMark(%d) = %q, want ?", n, got)
		}
	}
}

func TestDollarN(t *testing.T) {
	cases := []struct{ n int; want string }{{1, "$1"}, {2, "$2"}, {10, "$10"}}
	for _, c := range cases {
		if got := dollarN(c.n); got != c.want {
			t.Errorf("dollarN(%d) = %q, want %q", c.n, got, c.want)
		}
	}
}

func TestSchemaSQL(t *testing.T) {
	for _, driver := range []string{"sqlite", "mysql", "postgres"} {
		sql := schemaSQL(driver, "mfa_tokens")
		if !strings.Contains(sql, "mfa_tokens") {
			t.Errorf("driver=%s: schema missing table name", driver)
		}
		if !strings.Contains(sql, "CREATE TABLE IF NOT EXISTS") {
			t.Errorf("driver=%s: schema missing CREATE TABLE IF NOT EXISTS", driver)
		}
	}

	if got := schemaSQL("sqlite", "t"); !strings.Contains(got, "AUTOINCREMENT") {
		t.Error("sqlite schema missing AUTOINCREMENT")
	}
	if got := schemaSQL("mysql", "t"); !strings.Contains(got, "AUTO_INCREMENT") {
		t.Error("mysql schema missing AUTO_INCREMENT")
	}
	if got := schemaSQL("postgres", "t"); !strings.Contains(got, "BIGSERIAL") {
		t.Error("postgres schema missing BIGSERIAL")
	}
}

// openPostgresDSN opens a postgres connection directly from a raw DSN string,
// creates the schema, and returns a ready-to-use *Database.
func openPostgresDSN(dsn, tableName string) (*Database, error) {
	sqlDB, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}
	if err := sqlDB.Ping(); err != nil {
		sqlDB.Close() //nolint:errcheck
		return nil, err
	}
	d := &Database{db: sqlDB, tableName: tableName, driver: "postgres", placeholder: dollarN}
	if err := d.createSchema(); err != nil {
		sqlDB.Close() //nolint:errcheck
		return nil, err
	}
	return d, nil
}

func testDB(t *testing.T) *Database {
	t.Helper()
	cfg := Config{TableName: "mfa_tokens", SQLitePath: filepath.Join(t.TempDir(), "test.db")}
	db, err := initDB(cfg)
	if err != nil {
		t.Fatalf("initDB: %v", err)
	}
	t.Cleanup(func() { db.Close() }) //nolint:errcheck
	return db
}

func TestImportTokens(t *testing.T) {
	db := testDB(t)

	if err := db.createToken("existing", "JBSWY3DPEHPK3PXP"); err != nil {
		t.Fatalf("createToken: %v", err)
	}

	entries := []importEntry{
		{name: "existing", secret: "JBSWY3DPEHPK3PXP"}, // duplicate by name → skip
		{name: "new-one", secret: "MFRGGZDFMZTWQ2LK"},
		{name: "new-two", secret: "NBSWY3DPEHPK3PXP"},
	}

	imported, skipped, err := db.importTokens(entries)
	if err != nil {
		t.Fatalf("importTokens: %v", err)
	}
	if imported != 2 {
		t.Errorf("imported = %d, want 2", imported)
	}
	if skipped != 1 {
		t.Errorf("skipped = %d, want 1", skipped)
	}

	tokens, err := db.allTokens()
	if err != nil {
		t.Fatalf("allTokens: %v", err)
	}
	if len(tokens) != 3 {
		t.Errorf("total tokens = %d, want 3", len(tokens))
	}
}

func TestImportTokens_Empty(t *testing.T) {
	db := testDB(t)
	imported, skipped, err := db.importTokens(nil)
	if err != nil {
		t.Fatalf("importTokens: %v", err)
	}
	if imported != 0 || skipped != 0 {
		t.Errorf("want 0/0, got %d/%d", imported, skipped)
	}
}

func TestInitDB_PostgreSQL(t *testing.T) {
	dsn := os.Getenv("POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_TEST_DSN not set")
	}
	db, err := openPostgresDSN(dsn, "mfa_tokens_test")
	if err != nil {
		t.Fatalf("openPostgresDSN: %v", err)
	}
	defer db.Close() //nolint:errcheck

	if err := db.createToken("pg-test", "JBSWY3DPEHPK3PXP"); err != nil {
		t.Fatalf("createToken: %v", err)
	}
	tok, err := db.tokenByName("pg-test")
	if err != nil {
		t.Fatalf("tokenByName: %v", err)
	}
	if tok == nil || tok.Name != "pg-test" {
		t.Fatalf("expected token named pg-test, got %v", tok)
	}
	if err := db.deleteToken(tok.ID); err != nil {
		t.Fatalf("deleteToken: %v", err)
	}
}
