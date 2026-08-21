package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ancyloce/anvilkit-agent-service/internal/events"
)

// EvidenceStore is the durable internal AgentEvidence store: an independent
// per-run evidenceSequence, immutable rows, a canonical integrity digest that
// is re-verified before anything is disclosed, a governed disclosure window
// per retention category, and authority-scoped access-audited reads. It is
// deliberately stricter than the public event store — only the composition's
// authority role can touch it, and every read leaves an audit row.
type EvidenceStore struct {
	database  *pgxpool.Pool
	validator events.ContractValidator
	now       func() time.Time
}

func NewEvidenceStore(database *pgxpool.Pool, validator events.ContractValidator, now func() time.Time) (*EvidenceStore, error) {
	if database == nil || validator == nil || now == nil {
		return nil, fmt.Errorf("evidence store: a database, contract validator, and clock are required")
	}
	return &EvidenceStore{database: database, validator: validator, now: now}, nil
}

var _ events.EvidenceRecorder = (*EvidenceStore)(nil)
var _ events.EvidenceReader = (*EvidenceStore)(nil)

func (s *EvidenceStore) AppendEvidence(ctx context.Context, value events.Evidence) (uint64, error) {
	if err := events.ValidateEvidence(value); err != nil {
		return 0, err
	}
	// The canonical document attests millisecond precision, so the column is
	// recorded at exactly that precision: a stored time must never carry
	// precision the integrity digest does not attest, or the two disagree by
	// construction.
	recordedAt := s.now().UTC().Truncate(time.Millisecond)
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
		// The canonical contract is proven before the row exists: a document
		// the contract rejects never becomes durable internal history.
		if err := s.validator.Require(ctx, events.AgentEvidenceSchemaURI, rendered); err != nil {
			return 0, fmt.Errorf("validate evidence against its canonical contract: %w", err)
		}
		digest, err := events.EvidenceDigest(rendered)
		if err != nil {
			return 0, err
		}
		tag, err := s.database.Exec(ctx, `INSERT INTO agent_evidence.records(workspace_id,project_id,run_id,evidence_id,evidence_sequence,evidence_type,data_classification,retention_category,evidence_bytes,content_digest,recorded_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT DO NOTHING`,
			value.WorkspaceID, value.ProjectID, value.RunID, value.EvidenceID, sequence, value.Type, value.Classification, value.Retention, rendered, digest, recordedAt)
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

// ReadEvidence discloses one run's evidence under the accessor's own proven
// authority. The tenant is taken from that authority rather than from a
// caller-supplied filter, so a cross-tenant read cannot be expressed; the
// accessor's clearance bounds which classifications are disclosed; the
// governed retention window bounds what is still disclosable; and every
// returned document is re-verified against its stored integrity digest.
func (s *EvidenceStore) ReadEvidence(ctx context.Context, authority events.EvidenceAuthority, runID string, limit int) ([]events.RecordedEvidence, error) {
	if err := authority.Validate(); err != nil {
		return nil, err
	}
	if err := events.ValidateEvidenceRun(runID); err != nil {
		return nil, err
	}
	limit = events.BoundedEvidencePage(limit)
	now := s.now().UTC()
	if now.IsZero() {
		return nil, fmt.Errorf("evidence store: authoritative time is unavailable")
	}
	// The access audit lands before any bytes are returned: an evidence read
	// without its audit row is not a mode.
	if _, err := s.database.Exec(ctx, `INSERT INTO agent_evidence.access_audit(workspace_id,project_id,run_id,accessor,purpose,clearance,accessed_at) VALUES($1,$2,$3,$4,$5,$6,$7)`, authority.Scope.WorkspaceID, authority.Scope.ProjectID, runID, authority.Accessor, authority.Purpose, authority.Clearance, now); err != nil {
		return nil, fmt.Errorf("audit evidence access: %w", err)
	}
	// The disclosure deadline is derived, so retention filters on the
	// recording time against the governed cutoff for each category. Clearance
	// and retention bound the query itself, so the limit bounds disclosable
	// records rather than rows that are then discarded.
	cutoffs, err := events.RetentionCutoffs(now)
	if err != nil {
		return nil, err
	}
	// The disclosure filter names each registered category explicitly. A new
	// category must be named there too, so refuse loudly here rather than
	// leaning on the filter's silent exclusion of what it does not know.
	for _, category := range events.RetentionCategories() {
		switch category {
		case events.RetentionOperational, events.RetentionAudit, events.RetentionSecurity:
		default:
			return nil, fmt.Errorf("evidence store: retention category %q is not covered by the disclosure filter", category)
		}
	}
	rows, err := s.database.Query(ctx, `SELECT evidence_bytes,evidence_sequence,recorded_at,retention_category,content_digest FROM agent_evidence.records WHERE workspace_id=$1 AND project_id=$2 AND run_id=$3 AND data_classification = ANY($4) AND recorded_at > CASE retention_category WHEN 'operational' THEN $5::timestamptz WHEN 'audit' THEN $6::timestamptz WHEN 'security' THEN $7::timestamptz END ORDER BY evidence_sequence LIMIT $8`,
		authority.Scope.WorkspaceID, authority.Scope.ProjectID, runID, authority.PermittedClassifications(),
		cutoffs[events.RetentionOperational], cutoffs[events.RetentionAudit], cutoffs[events.RetentionSecurity], limit)
	if err != nil {
		return nil, fmt.Errorf("read evidence: %w", err)
	}
	defer rows.Close()
	var records []events.RecordedEvidence
	for rows.Next() {
		var rendered []byte
		var retention string
		var record events.RecordedEvidence
		if err := rows.Scan(&rendered, &record.Sequence, &record.RecordedAt, &retention, &record.Digest); err != nil {
			return nil, fmt.Errorf("scan evidence: %w", err)
		}
		digest, err := events.EvidenceDigest(rendered)
		if err != nil {
			return nil, err
		}
		if digest != record.Digest {
			return nil, fmt.Errorf("evidence integrity failure: record %d of run %q does not match its recorded digest", record.Sequence, runID)
		}
		decoded, err := events.DecodeEvidence(rendered)
		if err != nil {
			return nil, err
		}
		// The row's indexed columns are what the query filtered on, but only
		// the document is under the integrity digest. Re-deciding scope,
		// sequence, and — above all — clearance against the attested document
		// is what stops a direct column write from widening a read: a
		// restricted fact relabelled "internal" in its column is refused
		// here, not disclosed.
		if decoded.WorkspaceID != authority.Scope.WorkspaceID || decoded.ProjectID != authority.Scope.ProjectID || decoded.RunID != runID {
			return nil, fmt.Errorf("evidence integrity failure: record %d does not attest the scope it is stored under", record.Sequence)
		}
		if decoded.Sequence != record.Sequence || !decoded.RecordedAt.Equal(record.RecordedAt) {
			return nil, fmt.Errorf("evidence integrity failure: record %d does not attest the sequence and recording time it is stored under", record.Sequence)
		}
		if decoded.Retention != retention {
			return nil, fmt.Errorf("evidence integrity failure: record %d does not attest the retention category it is stored under", record.Sequence)
		}
		if !authority.Permits(decoded.Classification) {
			return nil, fmt.Errorf("evidence integrity failure: record %d does not attest the data classification it is stored under", record.Sequence)
		}
		// The deadline is derived from what the document attests, so a
		// disclosed record always reports the governed lifetime in force.
		deadline, err := events.DisclosureDeadline(decoded.RecordedAt, decoded.Retention)
		if err != nil {
			return nil, err
		}
		record.ExpiresAt = deadline
		record.Evidence = decoded.Evidence
		records = append(records, record)
	}
	return records, rows.Err()
}
