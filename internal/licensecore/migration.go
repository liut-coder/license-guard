package licensecore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

type MigrationOptions struct {
	SeedDemo bool
}

func RunPostgresMigrations(databaseURL string, migrationsDir string, opts MigrationOptions) ([]string, error) {
	if databaseURL == "" {
		return nil, errors.New("database url is required")
	}
	if migrationsDir == "" {
		migrationsDir = "./migrations"
	}

	files, err := filepath.Glob(filepath.Join(migrationsDir, "*.sql"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	if len(files) == 0 {
		return nil, fmt.Errorf("no migration files found in %s", migrationsDir)
	}

	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		return nil, err
	}

	var ran []string
	for _, file := range files {
		name := filepath.Base(file)
		if !opts.SeedDemo && strings.Contains(name, "_seed_") {
			continue
		}
		version := strings.TrimSuffix(name, filepath.Ext(name))
		applied, err := migrationApplied(ctx, db, version)
		if err != nil {
			return ran, err
		}
		if applied {
			continue
		}
		raw, err := os.ReadFile(file)
		if err != nil {
			return ran, err
		}
		statements := splitSQLStatements(string(raw))
		if len(statements) == 0 {
			continue
		}

		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return ran, err
		}
		for _, statement := range statements {
			if _, err := tx.ExecContext(ctx, statement); err != nil {
				_ = tx.Rollback()
				return ran, fmt.Errorf("%s: %w", name, err)
			}
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO schema_migrations(version) VALUES ($1) ON CONFLICT (version) DO NOTHING", version); err != nil {
			_ = tx.Rollback()
			return ran, fmt.Errorf("%s: record migration: %w", name, err)
		}
		if err := tx.Commit(); err != nil {
			return ran, err
		}
		ran = append(ran, name)
	}

	return ran, nil
}

func migrationApplied(ctx context.Context, db *sql.DB, version string) (bool, error) {
	var hasTable bool
	if err := db.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM information_schema.tables
			WHERE table_schema = current_schema()
				AND table_name = 'schema_migrations'
			)`).Scan(&hasTable); err != nil {
		return false, err
	}
	if !hasTable {
		return false, nil
	}

	var applied bool
	if err := db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)`, version).Scan(&applied); err != nil {
		return false, err
	}
	return applied, nil
}

func splitSQLStatements(sqlText string) []string {
	var statements []string
	var b strings.Builder
	inSingleQuote := false
	inDoubleQuote := false
	inLineComment := false
	inBlockComment := false
	dollarTag := ""

	for i := 0; i < len(sqlText); i++ {
		ch := sqlText[i]
		next := byte(0)
		if i+1 < len(sqlText) {
			next = sqlText[i+1]
		}

		if inLineComment {
			b.WriteByte(ch)
			if ch == '\n' {
				inLineComment = false
			}
			continue
		}
		if inBlockComment {
			b.WriteByte(ch)
			if ch == '*' && next == '/' {
				b.WriteByte(next)
				i++
				inBlockComment = false
			}
			continue
		}
		if dollarTag != "" {
			if strings.HasPrefix(sqlText[i:], dollarTag) {
				b.WriteString(dollarTag)
				i += len(dollarTag) - 1
				dollarTag = ""
				continue
			}
			b.WriteByte(ch)
			continue
		}

		if !inSingleQuote && !inDoubleQuote {
			if ch == '-' && next == '-' {
				b.WriteByte(ch)
				b.WriteByte(next)
				i++
				inLineComment = true
				continue
			}
			if ch == '/' && next == '*' {
				b.WriteByte(ch)
				b.WriteByte(next)
				i++
				inBlockComment = true
				continue
			}
			if ch == '$' {
				if tag, ok := readDollarTag(sqlText[i:]); ok {
					b.WriteString(tag)
					i += len(tag) - 1
					dollarTag = tag
					continue
				}
			}
		}

		switch ch {
		case '\'':
			b.WriteByte(ch)
			if !inDoubleQuote {
				if inSingleQuote && next == '\'' {
					b.WriteByte(next)
					i++
					continue
				}
				inSingleQuote = !inSingleQuote
			}
		case '"':
			b.WriteByte(ch)
			if !inSingleQuote {
				inDoubleQuote = !inDoubleQuote
			}
		case ';':
			if inSingleQuote || inDoubleQuote {
				b.WriteByte(ch)
				continue
			}
			statement := strings.TrimSpace(b.String())
			if statement != "" {
				statements = append(statements, statement)
			}
			b.Reset()
		default:
			b.WriteByte(ch)
		}
	}

	statement := strings.TrimSpace(b.String())
	if statement != "" {
		statements = append(statements, statement)
	}
	return statements
}

func readDollarTag(text string) (string, bool) {
	if text == "" || text[0] != '$' {
		return "", false
	}
	for i := 1; i < len(text); i++ {
		ch := text[i]
		if ch == '$' {
			return text[:i+1], true
		}
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_' {
			continue
		}
		return "", false
	}
	return "", false
}
