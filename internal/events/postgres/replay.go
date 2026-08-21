package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	contractguard "github.com/ancyloce/anvilkit-agent-service/internal/contracts"
	"github.com/ancyloce/anvilkit-agent-service/internal/events"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
)

type Reader struct {
	database     *pgxpool.Pool
	pollInterval time.Duration
	guard        *contractguard.Guard
	bounds       events.Bounds
	// retention is the durable public-cursor retention window: a cursor whose
	// event is older answers 410 even while its bytes still exist, so clients
	// recover through the snapshot instead of an unbounded replay contract.
	// Zero means no age-based expiry (unit-test readers).
	retention time.Duration
	now       func() time.Time
}

func NewReader(database *pgxpool.Pool, guard *contractguard.Guard, configured ...events.Bounds) *Reader {
	bounds := events.DefaultBounds()
	if len(configured) == 1 {
		bounds = configured[0]
	}
	return &Reader{database: database, pollInterval: 25 * time.Millisecond, guard: guard, bounds: bounds, now: time.Now}
}

// NewRetainedReader builds the production reader with the deployment's
// declared cursor-retention window.
func NewRetainedReader(database *pgxpool.Pool, guard *contractguard.Guard, bounds events.Bounds, retention time.Duration, now func() time.Time) (*Reader, error) {
	if database == nil || guard == nil || retention <= 0 || now == nil {
		return nil, fmt.Errorf("retained event reader requires database, guard, a positive retention window, and a clock")
	}
	reader := NewReader(database, guard, bounds)
	reader.retention = retention
	reader.now = now
	return reader, nil
}

// This reader has no append: a durable public event is written only by the
// projection writer, from an authoritative AgentEvidence record it recorded in
// the same transaction (ADR-020 §2). There is no method here — for production
// or for tests — that takes event bytes, a source evidence reference, or a
// projector identity from a caller.

func (r *Reader) Replay(ctx context.Context, request events.ReplayRequest) (events.ReplayPage, error) {
	if err := request.Scope.Validate(); err != nil || request.RunID == "" {
		return events.ReplayPage{}, problem.New(problem.CodeResourceNotFound, "")
	}
	if request.Limit == 0 {
		request.Limit = 100
	}
	if request.Limit < 1 || request.Limit > 1000 {
		value := problem.New(problem.CodeRequestInvalid, "")
		value.Detail = "event replay limit is invalid"
		return events.ReplayPage{}, value
	}
	var after uint64
	if request.AfterEventID != "" {
		var cursorCreatedAt time.Time
		err := r.database.QueryRow(ctx, `SELECT sequence,created_at FROM agent_events.agent_events WHERE workspace_id=$1 AND project_id=$2 AND run_id=$3 AND event_id=$4`, request.Scope.WorkspaceID, request.Scope.ProjectID, request.RunID, request.AfterEventID).Scan(&after, &cursorCreatedAt)
		if err != nil {
			if err == pgx.ErrNoRows {
				return events.ReplayPage{}, events.CursorExpired()
			}
			return events.ReplayPage{}, err
		}
		if r.retention > 0 && r.now().Sub(cursorCreatedAt) > r.retention {
			return events.ReplayPage{}, events.CursorExpired()
		}
	}
	// Provenance and the evidence it names are joined in rather than assumed.
	// The database refuses to record either one incorrectly, but replay is
	// where a public fact is asserted to a consumer, so it proves the account
	// again from the stored rows: an event with no provenance, provenance
	// correlated to another run, or provenance naming evidence that does not
	// exist in this run is store corruption, never an ordinary public fact.
	// The joins are LEFT so the corruption is reported as itself rather than
	// disappearing as a shorter page.
	rows, err := r.database.Query(ctx, `SELECT e.event_id,e.sequence,e.event_bytes,p.evidence_id,p.projector_digest,p.run_id,d.run_id,e.created_at FROM agent_events.agent_events e LEFT JOIN agent_events.event_provenance p ON p.workspace_id=e.workspace_id AND p.project_id=e.project_id AND p.event_id=e.event_id LEFT JOIN agent_evidence.records d ON d.workspace_id=p.workspace_id AND d.project_id=p.project_id AND d.evidence_id=p.evidence_id WHERE e.workspace_id=$1 AND e.project_id=$2 AND e.run_id=$3 AND e.sequence>$4 ORDER BY e.sequence LIMIT $5`, request.Scope.WorkspaceID, request.Scope.ProjectID, request.RunID, after, request.Limit+1)
	if err != nil {
		return events.ReplayPage{}, err
	}
	defer rows.Close()
	page := events.ReplayPage{}
	for rows.Next() {
		var event events.Event
		event.RunID = request.RunID
		var evidenceID, projectorDigest, provenanceRunID, evidenceRunID *string
		if err := rows.Scan(&event.ID, &event.Sequence, &event.Bytes, &evidenceID, &projectorDigest, &provenanceRunID, &evidenceRunID, &event.CreatedAt); err != nil {
			return events.ReplayPage{}, err
		}
		if evidenceID == nil || projectorDigest == nil || provenanceRunID == nil {
			return events.ReplayPage{}, fmt.Errorf("authoritative event store corruption: event %q has no recorded provenance", event.ID)
		}
		if *provenanceRunID != event.RunID {
			return events.ReplayPage{}, fmt.Errorf("authoritative event store corruption: event %q is explained by provenance correlated to run %q", event.ID, *provenanceRunID)
		}
		if evidenceRunID == nil {
			return events.ReplayPage{}, fmt.Errorf("authoritative event store corruption: event %q names source evidence %q that does not exist", event.ID, *evidenceID)
		}
		if *evidenceRunID != event.RunID {
			return events.ReplayPage{}, fmt.Errorf("authoritative event store corruption: event %q names source evidence %q recorded under run %q", event.ID, *evidenceID, *evidenceRunID)
		}
		event.EvidenceID, event.ProjectorDigest = *evidenceID, *projectorDigest
		if r.guard == nil {
			return events.ReplayPage{}, fmt.Errorf("replay event: contract guard is required")
		}
		if err := events.ValidateEnvelope(event.Bytes, r.bounds, event.ID, event.RunID, event.Sequence); err != nil {
			return events.ReplayPage{}, fmt.Errorf("authoritative event store corruption: %w", err)
		}
		if err := r.guard.Require(ctx, contractguard.EventIn, events.AgentEventSchemaURI, event.Bytes); err != nil {
			return events.ReplayPage{}, fmt.Errorf("authoritative event store corruption: %w", err)
		}
		page.Events = append(page.Events, event)
	}
	if err := rows.Err(); err != nil {
		return events.ReplayPage{}, err
	}
	if len(page.Events) > request.Limit {
		page.Events = page.Events[:request.Limit]
		page.HasMore = true
	}
	if err := events.ValidateContiguous(page.Events, after); err != nil {
		return events.ReplayPage{}, fmt.Errorf("authoritative event store corruption: %w", err)
	}
	if len(page.Events) > 0 {
		page.CurrentCursor = page.Events[len(page.Events)-1].ID
		page.CurrentSequence = page.Events[len(page.Events)-1].Sequence
	} else {
		page.CurrentCursor = request.AfterEventID
		page.CurrentSequence = after
	}
	return page, nil
}

func (r *Reader) Snapshot(ctx context.Context, scope events.Scope, runID string) (events.SnapshotProjection, error) {
	if err := scope.Validate(); err != nil {
		return events.SnapshotProjection{}, problem.New(problem.CodeResourceNotFound, "")
	}
	tx, err := r.database.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return events.SnapshotProjection{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var raw []byte
	var cursor string
	err = tx.QueryRow(ctx, `SELECT snapshot,COALESCE((SELECT event_id FROM agent_events.agent_events e WHERE e.workspace_id=agent_control.agent_runs.workspace_id AND e.project_id=agent_control.agent_runs.project_id AND e.run_id=agent_control.agent_runs.run_id ORDER BY sequence DESC LIMIT 1),'') FROM agent_control.agent_runs WHERE workspace_id=$1 AND project_id=$2 AND run_id=$3`, scope.WorkspaceID, scope.ProjectID, runID).Scan(&raw, &cursor)
	if err != nil {
		if err == pgx.ErrNoRows {
			return events.SnapshotProjection{}, problem.New(problem.CodeResourceNotFound, "")
		}
		return events.SnapshotProjection{}, err
	}
	rows, err := tx.Query(ctx, `SELECT artifact_id,state,digest,security_generation FROM agent_artifacts.metadata WHERE workspace_id=$1 AND project_id=$2 AND run_id=$3 ORDER BY artifact_id`, scope.WorkspaceID, scope.ProjectID, runID)
	if err != nil {
		return events.SnapshotProjection{}, err
	}
	result := events.SnapshotProjection{Run: raw, Cursor: cursor}
	for rows.Next() {
		var artifact events.ArtifactProjection
		if err := rows.Scan(&artifact.ID, &artifact.State, &artifact.Digest, &artifact.SecurityGeneration); err != nil {
			return events.SnapshotProjection{}, err
		}
		result.Artifacts = append(result.Artifacts, artifact)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return events.SnapshotProjection{}, err
	}
	rows.Close()
	if err := tx.Commit(ctx); err != nil {
		return events.SnapshotProjection{}, err
	}
	return result, nil
}

func (r *Reader) Wait(ctx context.Context, scope events.Scope, runID string, after uint64, timeout time.Duration) error {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	ticker := time.NewTicker(r.pollInterval)
	defer ticker.Stop()
	for {
		var exists bool
		if err := r.database.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM agent_events.agent_events WHERE workspace_id=$1 AND project_id=$2 AND run_id=$3 AND sequence>$4)`, scope.WorkspaceID, scope.ProjectID, runID, after).Scan(&exists); err != nil {
			return err
		}
		if exists {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return nil
		case <-ticker.C:
		}
	}
}

func DecodeEvent(raw []byte) map[string]any {
	value := map[string]any{}
	_ = json.Unmarshal(raw, &value)
	return value
}

var _ events.Reader = (*Reader)(nil)
