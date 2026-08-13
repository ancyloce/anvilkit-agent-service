// Package postgres persists compiled-context evidence without disclosed content.
package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ancyloce/anvilkit-agent-service/internal/contextcompiler"
)

type Recorder struct{ database *pgxpool.Pool }

func New(database *pgxpool.Pool) (*Recorder, error) {
	if database == nil {
		return nil, fmt.Errorf("context evidence database is required")
	}
	return &Recorder{database: database}, nil
}

func (r *Recorder) Record(ctx context.Context, request contextcompiler.Request, result contextcompiler.Result) error {
	evidence, err := json.Marshal(result.Evidence)
	if err != nil {
		return fmt.Errorf("marshal context evidence: %w", err)
	}
	truncations, err := json.Marshal(result.Truncations)
	if err != nil {
		return fmt.Errorf("marshal context truncations: %w", err)
	}
	sum := sha256.Sum256(append(append([]byte(request.RunID+":"), evidence...), truncations...))
	id := "sha256:" + hex.EncodeToString(sum[:])
	_, err = r.database.Exec(ctx, `INSERT INTO agent_evaluation.context_evidence(workspace_id,project_id,run_id,evidence_id,compiled_context,truncations) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`, request.WorkspaceID, request.ProjectID, request.RunID, id, evidence, truncations)
	if err != nil {
		return fmt.Errorf("persist context evidence: %w", err)
	}
	return nil
}

var _ contextcompiler.EvidenceRecorder = (*Recorder)(nil)
