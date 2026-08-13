// Package postgres implements the independent receipt journal port.
package postgres

import (
	"bytes"
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ancyloce/anvilkit-agent-service/internal/journal"
)

type Store struct{ database *pgxpool.Pool }

func New(database *pgxpool.Pool) *Store { return &Store{database: database} }

func (s *Store) EnsureSchema(ctx context.Context) error {
	_, err := s.database.Exec(ctx, `CREATE SCHEMA IF NOT EXISTS agent_receipts; CREATE TABLE IF NOT EXISTS agent_receipts.facts (fact_id text PRIMARY KEY, workspace_id text NOT NULL, project_id text NOT NULL, fact_class text NOT NULL, operation_order bigint NOT NULL UNIQUE CHECK(operation_order>0), canonical_bytes bytea NOT NULL, fact_digest bytea NOT NULL, projection bytea NOT NULL, recorded_at timestamptz NOT NULL DEFAULT transaction_timestamp())`)
	if err != nil {
		return fmt.Errorf("ensure independent journal schema: %w", err)
	}
	return nil
}
func (s *Store) Check(ctx context.Context) error {
	if err := s.database.Ping(ctx); err != nil {
		return fmt.Errorf("check independent journal: %w", err)
	}
	return nil
}
func (s *Store) Append(ctx context.Context, fact journal.Fact) error {
	result, err := s.database.Exec(ctx, `INSERT INTO agent_receipts.facts(fact_id,workspace_id,project_id,fact_class,operation_order,canonical_bytes,fact_digest,projection) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING`, fact.ID, fact.WorkspaceID, fact.ProjectID, fact.Class, fact.OperationOrder, fact.Canonical, fact.Digest[:], fact.Projection)
	if err != nil {
		return fmt.Errorf("append independent journal fact: %w", err)
	}
	if result.RowsAffected() == 1 {
		return nil
	}
	var digest, projection []byte
	if err := s.database.QueryRow(ctx, `SELECT fact_digest,projection FROM agent_receipts.facts WHERE fact_id=$1`, fact.ID).Scan(&digest, &projection); err != nil {
		return fmt.Errorf("read journal duplicate: %w", err)
	}
	if !bytes.Equal(digest, fact.Digest[:]) || !bytes.Equal(projection, fact.Projection) {
		return fmt.Errorf("journal conflict: fact identity reused with different bytes")
	}
	return nil
}
func (s *Store) List(ctx context.Context) ([]journal.Fact, error) {
	rows, err := s.database.Query(ctx, `SELECT fact_id,workspace_id,project_id,fact_class,operation_order,canonical_bytes,fact_digest,projection FROM agent_receipts.facts ORDER BY operation_order`)
	if err != nil {
		return nil, fmt.Errorf("list journal facts: %w", err)
	}
	defer rows.Close()
	var facts []journal.Fact
	for rows.Next() {
		var fact journal.Fact
		var digest []byte
		if err := rows.Scan(&fact.ID, &fact.WorkspaceID, &fact.ProjectID, &fact.Class, &fact.OperationOrder, &fact.Canonical, &digest, &fact.Projection); err != nil {
			return nil, fmt.Errorf("scan journal fact: %w", err)
		}
		if len(digest) != len(fact.Digest) {
			return nil, fmt.Errorf("journal fact %s has invalid digest", fact.ID)
		}
		copy(fact.Digest[:], digest)
		facts = append(facts, fact)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate journal facts: %w", err)
	}
	return facts, nil
}

var _ journal.Store = (*Store)(nil)
