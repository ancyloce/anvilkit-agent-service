package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	contractguard "github.com/ancyloce/anvilkit-agent-service/internal/contracts"
	"github.com/ancyloce/anvilkit-agent-service/internal/events"
)

// ProjectionWriter is the one production path from an internal execution fact
// to a durable public event (ADR-020 §2).
//
// Every production writer goes through it, so a public event is never written
// without the authoritative AgentEvidence it was projected from, and every
// stored event carries the source evidence reference and the digest of the
// projection ruleset that produced it. The evidence, the event, and the outbox
// hand-off land in the caller's transaction, so an event can never become
// observable without the record that explains where it came from.
type ProjectionWriter struct {
	guard  *contractguard.Guard
	bounds events.Bounds
	now    func() time.Time
}

func NewProjectionWriter(guard *contractguard.Guard, bounds events.Bounds, now func() time.Time) (*ProjectionWriter, error) {
	if guard == nil || now == nil {
		return nil, fmt.Errorf("projection writer: the contract guard and a clock are required")
	}
	if err := bounds.Validate(); err != nil {
		return nil, fmt.Errorf("projection writer: %w", err)
	}
	return &ProjectionWriter{guard: guard, bounds: bounds, now: now}, nil
}

// Fact is one public projection together with the producing component's
// attributable material and the run-local correlation its evidence carries.
type Fact struct {
	Projection  events.Projection
	Producer    events.EvidenceProducer
	Correlation events.ProjectionCorrelation
}

// Write records the source evidence, projects the public event from it, proves
// both against their canonical contracts, and persists the event and its
// outbox hand-off. It returns the projected event so a caller that needs the
// bytes — a checkpoint, an assertion — reads exactly what was written.
func (w *ProjectionWriter) Write(ctx context.Context, tx pgx.Tx, scope events.Scope, fact Fact) (events.Projected, error) {
	if tx == nil {
		return events.Projected{}, fmt.Errorf("projection writer: a transaction is required")
	}
	if err := scope.Validate(); err != nil {
		return events.Projected{}, err
	}
	fact.Projection.OccurredAt = events.ProjectionOccurrence(fact.Projection.OccurredAt)
	evidence, projection, err := events.ProjectionEvidence(fact.Projection, fact.Producer, fact.Correlation)
	if err != nil {
		return events.Projected{}, err
	}
	if _, err := w.appendEvidence(ctx, tx, evidence); err != nil {
		return events.Projected{}, err
	}
	projected, err := events.Project(projection, w.bounds)
	if err != nil {
		return events.Projected{}, fmt.Errorf("project %s event: %w", projection.Type, err)
	}
	if err := w.guard.Require(ctx, contractguard.EventIn, events.AgentEventSchemaURI, projected.Bytes); err != nil {
		return events.Projected{}, fmt.Errorf("validate %s event contract: %w", projection.Type, err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO agent_events.agent_events(workspace_id,project_id,run_id,sequence,event_id,event_bytes,created_at) VALUES($1,$2,$3,$4,$5,$6,$7)`,
		scope.WorkspaceID, scope.ProjectID, projection.RunID, projection.Sequence, projection.EventID, projected.Bytes, projection.OccurredAt); err != nil {
		return events.Projected{}, fmt.Errorf("persist %s event: %w", projection.Type, err)
	}
	if err := recordProvenance(ctx, tx, scope, projection.RunID, projection.EventID, projected); err != nil {
		return events.Projected{}, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO agent_events.outbox(workspace_id,project_id,outbox_id,run_id,event_sequence,topic,payload,available_at) VALUES($1,$2,$3,$4,$5,'agent.public-events',$6,$7)`,
		scope.WorkspaceID, scope.ProjectID, projection.EventID, projection.RunID, projection.Sequence, projected.Bytes, projection.OccurredAt); err != nil {
		return events.Projected{}, fmt.Errorf("persist %s outbox hand-off: %w", projection.Type, err)
	}
	return projected, nil
}

// appendEvidence records the projection's source fact inside the caller's
// transaction. It carries the same idempotency rule as the standalone
// evidence store: an identical replay converges on the recorded sequence, and
// the same identity carrying a different fact is a typed conflict.
func (w *ProjectionWriter) appendEvidence(ctx context.Context, tx pgx.Tx, value events.Evidence) (uint64, error) {
	identity, err := events.EvidenceIdentity(value)
	if err != nil {
		return 0, err
	}
	recordedAt := w.now().UTC().Truncate(time.Millisecond)
	if recordedAt.IsZero() {
		return 0, fmt.Errorf("projection writer: authoritative time is unavailable")
	}
	// Recorded evidence is immutable, so the append never updates a row: it
	// either claims a new one or reads back what is already there. A replay of
	// the same fact converges on the recorded sequence; the same identity
	// carrying a different fact is a conflict.
	sequence, recorded, err := recordedEvidenceIdentity(ctx, tx, value)
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
		if err := tx.QueryRow(ctx, `SELECT COALESCE(MAX(evidence_sequence),0)+1 FROM agent_evidence.records WHERE workspace_id=$1 AND project_id=$2 AND run_id=$3`, value.WorkspaceID, value.ProjectID, value.RunID).Scan(&next); err != nil {
			return 0, fmt.Errorf("allocate evidence sequence: %w", err)
		}
		rendered, err := events.RenderEvidence(value, next, recordedAt)
		if err != nil {
			return 0, err
		}
		if err := w.guard.Require(ctx, contractguard.EvidenceIn, events.AgentEvidenceSchemaURI, rendered); err != nil {
			return 0, fmt.Errorf("validate projection evidence contract: %w", err)
		}
		digest, err := events.EvidenceDigest(rendered)
		if err != nil {
			return 0, err
		}
		tag, err := tx.Exec(ctx, `INSERT INTO agent_evidence.records(workspace_id,project_id,run_id,evidence_id,evidence_sequence,evidence_type,data_classification,retention_category,evidence_bytes,content_digest,recorded_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT DO NOTHING`,
			value.WorkspaceID, value.ProjectID, value.RunID, value.EvidenceID, next, value.Type, value.Classification, value.Retention, rendered, digest, recordedAt)
		if err != nil {
			return 0, fmt.Errorf("append projection evidence: %w", err)
		}
		if tag.RowsAffected() == 1 {
			return next, nil
		}
		sequence, recorded, err := recordedEvidenceIdentity(ctx, tx, value)
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

// recordedEvidenceIdentity reads what is already recorded under one evidence
// identifier in this tenant. An absent row reports an empty identity.
func recordedEvidenceIdentity(ctx context.Context, tx pgx.Tx, value events.Evidence) (uint64, string, error) {
	var sequence uint64
	var rendered []byte
	err := tx.QueryRow(ctx, `SELECT evidence_sequence,evidence_bytes FROM agent_evidence.records WHERE workspace_id=$1 AND project_id=$2 AND evidence_id=$3`, value.WorkspaceID, value.ProjectID, value.EvidenceID).Scan(&sequence, &rendered)
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

// identityOfRecorded computes the stable identity of a stored evidence row
// from the document itself. The row's columns are bound to that document by a
// database constraint, so the identity a replay is compared against is always
// the attested one rather than an unattested column.
func identityOfRecorded(rendered []byte) (string, error) {
	decoded, err := events.DecodeEvidence(rendered)
	if err != nil {
		return "", err
	}
	return events.EvidenceIdentity(decoded.Evidence)
}

// recordProvenance records where one durable public event came from: the
// authoritative evidence it was projected from and the identity of the ruleset
// that projected it. It is unexported and called only from Write, in the same
// transaction as the event and the evidence: there is no caller outside this
// writer that can name a source evidence reference or a projector identity of
// its own, and no event can become observable without the record that explains
// it.
func recordProvenance(ctx context.Context, tx pgx.Tx, scope events.Scope, runID, eventID string, projected events.Projected) error {
	if projected.EvidenceID == "" || projected.ProjectorDigest == "" {
		return fmt.Errorf("record event provenance: the source evidence reference and projector digest are required")
	}
	if _, err := tx.Exec(ctx, `INSERT INTO agent_events.event_provenance(workspace_id,project_id,run_id,event_id,evidence_id,projector_digest) VALUES($1,$2,$3,$4,$5,$6)`,
		scope.WorkspaceID, scope.ProjectID, runID, eventID, projected.EvidenceID, projected.ProjectorDigest); err != nil {
		return fmt.Errorf("record event provenance: %w", err)
	}
	return nil
}
