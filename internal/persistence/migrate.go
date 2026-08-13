// Package persistence owns Postgres adapters and mandatory scope guards.
package persistence

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

type Migrator struct{ database *pgx.Conn }

func NewMigrator(database *pgx.Conn) *Migrator { return &Migrator{database: database} }

func (m *Migrator) Apply(ctx context.Context) error {
	return m.ApplyThrough(ctx, 0)
}

// ApplyThrough is used by compatibility proofs to establish an N-1 schema.
// A zero maximum applies every embedded migration.
func (m *Migrator) ApplyThrough(ctx context.Context, maximum int) error {
	if _, err := m.database.Exec(ctx, `CREATE SCHEMA IF NOT EXISTS agent_migrations; CREATE TABLE IF NOT EXISTS agent_migrations.versions (version integer PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT transaction_timestamp())`); err != nil {
		return fmt.Errorf("create migration ledger: %w", err)
	}
	files, err := migrationNames("up")
	if err != nil {
		return err
	}
	for _, name := range files {
		version := migrationVersion(name)
		if maximum > 0 && version > maximum {
			continue
		}
		var present bool
		if err := m.database.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM agent_migrations.versions WHERE version=$1)`, version).Scan(&present); err != nil {
			return fmt.Errorf("check migration %d: %w", version, err)
		}
		if present {
			continue
		}
		body, err := migrationFiles.ReadFile("migrations/" + name)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", name, err)
		}
		tx, err := m.database.Begin(ctx)
		if err != nil {
			return fmt.Errorf("begin migration %d: %w", version, err)
		}
		if _, err = tx.Exec(ctx, string(body)); err == nil {
			_, err = tx.Exec(ctx, `INSERT INTO agent_migrations.versions(version) VALUES($1)`, version)
		}
		if err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("apply migration %d: %w", version, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit migration %d: %w", version, err)
		}
	}
	return nil
}

func (m *Migrator) RollbackLast(ctx context.Context) error {
	var version int
	if err := m.database.QueryRow(ctx, `SELECT version FROM agent_migrations.versions ORDER BY version DESC LIMIT 1`).Scan(&version); err != nil {
		return fmt.Errorf("find migration to roll back: %w", err)
	}
	name := fmt.Sprintf("%04d", version)
	files, err := fs.Glob(migrationFiles, "migrations/"+name+"_*.down.sql")
	if err != nil || len(files) != 1 {
		return fmt.Errorf("find rollback for %d: %w", version, err)
	}
	body, err := migrationFiles.ReadFile(files[0])
	if err != nil {
		return fmt.Errorf("read rollback %d: %w", version, err)
	}
	tx, err := m.database.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin rollback %d: %w", version, err)
	}
	if _, err = tx.Exec(ctx, string(body)); err == nil {
		_, err = tx.Exec(ctx, `DELETE FROM agent_migrations.versions WHERE version=$1`, version)
	}
	if err != nil {
		_ = tx.Rollback(ctx)
		return fmt.Errorf("rollback migration %d: %w", version, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit rollback %d: %w", version, err)
	}
	return nil
}

func (m *Migrator) Compatible(ctx context.Context) error {
	files, err := migrationNames("up")
	if err != nil {
		return err
	}
	var current int
	if err := m.database.QueryRow(ctx, `SELECT COALESCE(MAX(version), 0) FROM agent_migrations.versions`).Scan(&current); err != nil {
		return fmt.Errorf("read schema compatibility: %w", err)
	}
	wanted := migrationVersion(files[len(files)-1])
	if current != wanted {
		return fmt.Errorf("schema version %d is incompatible with required %d", current, wanted)
	}
	return nil
}

func migrationNames(direction string) ([]string, error) {
	entries, err := fs.ReadDir(migrationFiles, "migrations")
	if err != nil {
		return nil, fmt.Errorf("list migrations: %w", err)
	}
	var names []string
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), "."+direction+".sql") {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		return nil, fmt.Errorf("no %s migrations", direction)
	}
	return names, nil
}

func migrationVersion(name string) int {
	value, _ := strconv.Atoi(strings.SplitN(name, "_", 2)[0])
	return value
}
