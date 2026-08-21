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
var _ events.EvidenceLookup = (*EvidenceStore)(nil)

// RecordedEvidence answers what is already recorded under one evidence
// identity in this tenant, so a producer replaying a durable operation
// converges on the fact that was recorded rather than stamping a second
// account of it. It returns identity and timing only — disclosing a payload
// is what ReadEvidence is for, under a proven accessor authority.
func (s *EvidenceStore) RecordedEvidence(ctx context.Context, scope events.Scope, evidenceID string) (events.RecordedEvidence, bool, error) {
	if err := scope.Validate(); err != nil {
		return events.RecordedEvidence{}, false, err
	}
	var record events.RecordedEvidence
	var occurredAt time.Time
	var retention string
	var rendered []byte
	err := s.database.QueryRow(ctx, `SELECT evidence_sequence,recorded_at,retention_category,content_digest,evidence_bytes FROM agent_evidence.records WHERE workspace_id=$1 AND project_id=$2 AND evidence_id=$3`, scope.WorkspaceID, scope.ProjectID, evidenceID).Scan(&record.Sequence, &record.RecordedAt, &retention, &record.Digest, &rendered)
	if errors.Is(err, pgx.ErrNoRows) {
		return events.RecordedEvidence{}, false, nil
	}
	if err != nil {
		return events.RecordedEvidence{}, false, fmt.Errorf("read recorded evidence: %w", err)
	}
	decoded, err := events.DecodeEvidence(rendered)
	if err != nil {
		return events.RecordedEvidence{}, false, err
	}
	occurredAt = decoded.OccurredAt
	record.Identity, err = events.EvidenceIdentity(decoded.Evidence)
	if err != nil {
		return events.RecordedEvidence{}, false, err
	}
	deadline, err := events.DisclosureDeadline(record.RecordedAt, retention)
	if err != nil {
		return events.RecordedEvidence{}, false, err
	}
	record.ExpiresAt = deadline
	record.Evidence = events.Evidence{WorkspaceID: scope.WorkspaceID, ProjectID: scope.ProjectID, EvidenceID: evidenceID, Retention: retention, OccurredAt: occurredAt.UTC()}
	return record, true, nil
}

func (s *EvidenceStore) AppendEvidence(ctx context.Context, value events.Evidence) (uint64, error) {
	if err := events.ValidateEvidence(value); err != nil {
		return 0, err
	}
	// The stable identity binds the append to the tenant, run, evidence
	// identity, type, classification, retention, and canonical content its
	// producer decided — and to nothing the store allocates. It is what makes
	// a replay recognizable and a reused identifier carrying a different fact
	// a conflict rather than a silent answer with someone else's sequence.
	identity, err := events.EvidenceIdentity(value)
	if err != nil {
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
	// A replay of the same durable operation reads the recorded row instead of
	// appending again; a different fact under the same identity is refused.
	sequence, recorded, err := s.recordedIdentity(ctx, value)
	if err != nil {
		return 0, err
	}
	if recorded != "" {
		if recorded != identity {
			return 0, events.EvidenceConflict(value.EvidenceID)
		}
		return sequence, nil
	}
	for {
		var next uint64
		if err := s.database.QueryRow(ctx, `SELECT COALESCE(MAX(evidence_sequence),0)+1 FROM agent_evidence.records WHERE workspace_id=$1 AND project_id=$2 AND run_id=$3`, value.WorkspaceID, value.ProjectID, value.RunID).Scan(&next); err != nil {
			return 0, fmt.Errorf("allocate evidence sequence: %w", err)
		}
		rendered, err := events.RenderEvidence(value, next, recordedAt)
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
			value.WorkspaceID, value.ProjectID, value.RunID, value.EvidenceID, next, value.Type, value.Classification, value.Retention, rendered, digest, recordedAt)
		if err != nil {
			return 0, fmt.Errorf("append evidence: %w", err)
		}
		if tag.RowsAffected() == 1 {
			return next, nil
		}
		// A concurrent append either recorded this identity (replay or
		// conflict) or claimed this sequence (retry with the next one).
		sequence, recorded, err := s.recordedIdentity(ctx, value)
		if err != nil {
			return 0, err
		}
		if recorded != "" {
			if recorded != identity {
				return 0, events.EvidenceConflict(value.EvidenceID)
			}
			return sequence, nil
		}
	}
}

// recordedIdentity reads what is already recorded under one evidence
// identifier in this tenant. An absent row reports an empty identity.
func (s *EvidenceStore) recordedIdentity(ctx context.Context, value events.Evidence) (uint64, string, error) {
	var sequence uint64
	var rendered []byte
	err := s.database.QueryRow(ctx, `SELECT evidence_sequence,evidence_bytes FROM agent_evidence.records WHERE workspace_id=$1 AND project_id=$2 AND evidence_id=$3`, value.WorkspaceID, value.ProjectID, value.EvidenceID).Scan(&sequence, &rendered)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, "", nil
	}
	if err != nil {
		return 0, "", fmt.Errorf("read recorded evidence: %w", err)
	}
	identity, err := identityOfRecorded(rendered)
	if err != nil {
		return 0, "", err
	}
	return sequence, identity, nil
}

// ReadEvidence discloses one run's evidence under the accessor's own proven
// authority. The tenant is taken from that authority rather than from a
// caller-supplied filter, so a cross-tenant read cannot be expressed; the
// accessor's clearance bounds which classifications are disclosed; the
// governed retention window bounds what is still disclosable; and every
// returned document is re-verified against its stored integrity digest.
func (s *EvidenceStore) ReadEvidence(ctx context.Context, accessor events.EvidenceAuthority, runID string, limit int) ([]events.RecordedEvidence, error) {
	// The authority in force now is what decides this read: a clearance
	// minted a moment ago is evidence of a past decision, never permission
	// for this one. Revalidating re-reads the subject, the tenant scope, the
	// admitted role, the granted clearance, and every revocation axis.
	authority, err := accessor.Revalidated(ctx)
	if err != nil {
		return nil, err
	}
	if err := authority.Validate(); err != nil {
		return nil, err
	}
	if err := events.ValidateEvidenceRun(runID); err != nil {
		return nil, err
	}
	limit = events.BoundedEvidencePage(limit)
	scope := authority.Scope()
	now := s.now().UTC()
	if now.IsZero() {
		return nil, fmt.Errorf("evidence store: authoritative time is unavailable")
	}
	// The access audit lands before any bytes are returned: an evidence read
	// without its audit row is not a mode.
	if _, err := s.database.Exec(ctx, `INSERT INTO agent_evidence.access_audit(workspace_id,project_id,run_id,accessor,purpose,clearance,accessed_at) VALUES($1,$2,$3,$4,$5,$6,$7)`, scope.WorkspaceID, scope.ProjectID, runID, authority.Accessor(), authority.Purpose(), authority.Clearance(), now); err != nil {
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
		scope.WorkspaceID, scope.ProjectID, runID, authority.PermittedClassifications(),
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
		if decoded.WorkspaceID != scope.WorkspaceID || decoded.ProjectID != scope.ProjectID || decoded.RunID != runID {
			return nil, fmt.Errorf("evidence integrity failure: record %d does not attest the scope it is stored under", record.Sequence)
		}
		if decoded.Sequence != record.Sequence || !decoded.RecordedAt.Equal(record.RecordedAt) {
			return nil, fmt.Errorf("evidence integrity failure: record %d does not attest the sequence and recording time it is stored under", record.Sequence)
		}
		if decoded.Retention != retention {
			return nil, fmt.Errorf("evidence integrity failure: record %d does not attest the retention category it is stored under", record.Sequence)
		}
		record.Identity, err = events.EvidenceIdentity(decoded.Evidence)
		if err != nil {
			return nil, err
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
