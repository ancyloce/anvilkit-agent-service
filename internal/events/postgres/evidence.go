package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ancyloce/anvilkit-agent-service/internal/events"
)

// EvidenceStore is the durable internal AgentEvidence store: an independent
// per-run evidenceSequence, immutable rows, an integrity digest over the
// canonical document, and access-audited reads. It is deliberately stricter
// than the public event store — only the composition's authority role can
// touch it, and every read leaves an audit row.
type EvidenceStore struct {
	database *pgxpool.Pool
	now      func() time.Time
}

func NewEvidenceStore(database *pgxpool.Pool, now func() time.Time) (*EvidenceStore, error) {
	if database == nil || now == nil {
		return nil, fmt.Errorf("evidence store: a database and clock are required")
	}
	return &EvidenceStore{database: database, now: now}, nil
}

var _ events.EvidenceRecorder = (*EvidenceStore)(nil)
var _ events.EvidenceReader = (*EvidenceStore)(nil)

func (s *EvidenceStore) AppendEvidence(ctx context.Context, value events.Evidence) (uint64, error) {
	if err := events.ValidateEvidence(value); err != nil {
		return 0, err
	}
	recordedAt := s.now().UTC()
	if recordedAt.IsZero() {
		return 0, fmt.Errorf("evidence store: authoritative time is unavailable")
	}
	// Idempotency by evidence identity: a durable operation replay reads the
	// recorded sequence instead of appending again.
	var existing uint64
	err := s.database.QueryRow(ctx, `SELECT evidence_sequence FROM agent_evidence.records WHERE workspace_id=$1 AND project_id=$2 AND evidence_id=$3`, value.WorkspaceID, value.ProjectID, value.EvidenceID).Scan(&existing)
	if err == nil {
		return existing, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return 0, fmt.Errorf("read recorded evidence: %w", err)
	}
	for {
		var sequence uint64
		if err := s.database.QueryRow(ctx, `SELECT COALESCE(MAX(evidence_sequence),0)+1 FROM agent_evidence.records WHERE workspace_id=$1 AND project_id=$2 AND run_id=$3`, value.WorkspaceID, value.ProjectID, value.RunID).Scan(&sequence); err != nil {
			return 0, fmt.Errorf("allocate evidence sequence: %w", err)
		}
		rendered, err := events.RenderEvidence(value, sequence, recordedAt)
		if err != nil {
			return 0, err
		}
		digest := sha256.Sum256(rendered)
		tag, err := s.database.Exec(ctx, `INSERT INTO agent_evidence.records(workspace_id,project_id,run_id,evidence_id,evidence_sequence,evidence_type,data_classification,retention_category,evidence_bytes,content_digest,recorded_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT DO NOTHING`,
			value.WorkspaceID, value.ProjectID, value.RunID, value.EvidenceID, sequence, value.Type, value.Classification, value.Retention, rendered, "sha256:"+hex.EncodeToString(digest[:]), recordedAt)
		if err != nil {
			return 0, fmt.Errorf("append evidence: %w", err)
		}
		if tag.RowsAffected() == 1 {
			return sequence, nil
		}
		// A concurrent append either recorded this identity (replay wins) or
		// claimed this sequence (retry with the next one).
		if err := s.database.QueryRow(ctx, `SELECT evidence_sequence FROM agent_evidence.records WHERE workspace_id=$1 AND project_id=$2 AND evidence_id=$3`, value.WorkspaceID, value.ProjectID, value.EvidenceID).Scan(&existing); err == nil {
			return existing, nil
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return 0, fmt.Errorf("read recorded evidence: %w", err)
		}
	}
}

func (s *EvidenceStore) ReadEvidence(ctx context.Context, scope events.Scope, runID, accessor, purpose string, limit int) ([]events.RecordedEvidence, error) {
	if err := scope.Validate(); err != nil || runID == "" {
		return nil, fmt.Errorf("evidence reads require a complete run scope")
	}
	if accessor == "" || len(accessor) > 128 || purpose == "" || len(purpose) > 256 {
		return nil, fmt.Errorf("evidence reads require an accessor identity and a declared purpose")
	}
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	// The access audit lands before any bytes are returned: an evidence read
	// without its audit row is not a mode.
	if _, err := s.database.Exec(ctx, `INSERT INTO agent_evidence.access_audit(workspace_id,project_id,run_id,accessor,purpose,accessed_at) VALUES($1,$2,$3,$4,$5,$6)`, scope.WorkspaceID, scope.ProjectID, runID, accessor, purpose, s.now().UTC()); err != nil {
		return nil, fmt.Errorf("audit evidence access: %w", err)
	}
	rows, err := s.database.Query(ctx, `SELECT evidence_bytes,evidence_sequence,recorded_at FROM agent_evidence.records WHERE workspace_id=$1 AND project_id=$2 AND run_id=$3 ORDER BY evidence_sequence LIMIT $4`, scope.WorkspaceID, scope.ProjectID, runID, limit)
	if err != nil {
		return nil, fmt.Errorf("read evidence: %w", err)
	}
	defer rows.Close()
	var records []events.RecordedEvidence
	for rows.Next() {
		var rendered []byte
		var record events.RecordedEvidence
		if err := rows.Scan(&rendered, &record.Sequence, &record.RecordedAt); err != nil {
			return nil, fmt.Errorf("scan evidence: %w", err)
		}
		var decoded struct {
			EvidenceID     string            `json:"evidenceId"`
			RunID          string            `json:"runId"`
			WorkspaceID    string            `json:"workspaceId"`
			ProjectID      string            `json:"projectId"`
			EvidenceType   string            `json:"evidenceType"`
			Classification string            `json:"dataClassification"`
			Retention      string            `json:"retentionCategory"`
			Payload        map[string]string `json:"payload"`
		}
		if err := json.Unmarshal(rendered, &decoded); err != nil {
			return nil, fmt.Errorf("decode evidence: %w", err)
		}
		record.Evidence = events.Evidence{WorkspaceID: decoded.WorkspaceID, ProjectID: decoded.ProjectID, RunID: decoded.RunID, EvidenceID: decoded.EvidenceID, Type: decoded.EvidenceType, Classification: decoded.Classification, Retention: decoded.Retention, Payload: decoded.Payload}
		records = append(records, record)
	}
	return records, rows.Err()
}
