// Package postgres persists pinned Contract Runtime validation evidence.
package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/ancyloce/anvilkit-agent-service/internal/contractclient"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Recorder struct{ database *pgxpool.Pool }

func New(database *pgxpool.Pool) (*Recorder, error) {
	if database == nil {
		return nil, fmt.Errorf("validation evidence database is required")
	}
	return &Recorder{database: database}, nil
}
func (r *Recorder) Record(ctx context.Context, value contractclient.Evidence) error {
	findings, err := json.Marshal(value.Findings)
	if err != nil {
		return fmt.Errorf("marshal validation findings: %w", err)
	}
	_, err = r.database.Exec(ctx, `INSERT INTO agent_evaluation.validation_evidence(workspace_id,project_id,run_id,boundary_kind,bom_digest,schema_digest,validator_version,catalog_digest,valid,findings,validated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, value.WorkspaceID, value.ProjectID, value.RunID, value.Kind, value.BOMDigest, value.SchemaDigest, value.ValidatorVersion, value.CatalogDigest, value.Valid, findings, value.ValidatedAt)
	if err != nil {
		return fmt.Errorf("persist validation evidence: %w", err)
	}
	return nil
}

var _ contractclient.Recorder = (*Recorder)(nil)
