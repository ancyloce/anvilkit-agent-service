package postgres

import (
	"bytes"
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
}

func NewReader(database *pgxpool.Pool, guard *contractguard.Guard, configured ...events.Bounds) *Reader {
	bounds := events.DefaultBounds()
	if len(configured) == 1 {
		bounds = configured[0]
	}
	return &Reader{database: database, pollInterval: 25 * time.Millisecond, guard: guard, bounds: bounds}
}

func (r *Reader) Append(ctx context.Context, scope events.Scope, event events.Event) error {
	if err := scope.Validate(); err != nil {
		return err
	}
	if event.ID == "" || event.RunID == "" || event.Sequence == 0 || len(event.Bytes) == 0 {
		return fmt.Errorf("append event: identity, run, sequence, and bytes are required")
	}
	if r.guard == nil {
		return fmt.Errorf("append event: contract guard is required")
	}
	if err := events.ValidateEnvelope(event.Bytes, r.bounds, event.ID, event.RunID, event.Sequence); err != nil {
		return fmt.Errorf("append event: %w", err)
	}
	if err := r.guard.Require(ctx, contractguard.EventIn, agentEventSchema, event.Bytes); err != nil {
		return err
	}
	result, err := r.database.Exec(ctx, `INSERT INTO agent_events.agent_events(workspace_id,project_id,run_id,sequence,event_id,event_bytes,created_at) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING`, scope.WorkspaceID, scope.ProjectID, event.RunID, event.Sequence, event.ID, event.Bytes, event.CreatedAt)
	if err != nil {
		return fmt.Errorf("append event: %w", err)
	}
	if result.RowsAffected() == 1 {
		return nil
	}
	var sequence uint64
	var runID string
	var existing []byte
	if err := r.database.QueryRow(ctx, `SELECT run_id,sequence,event_bytes FROM agent_events.agent_events WHERE workspace_id=$1 AND project_id=$2 AND event_id=$3`, scope.WorkspaceID, scope.ProjectID, event.ID).Scan(&runID, &sequence, &existing); err != nil {
		return fmt.Errorf("read duplicate event: %w", err)
	}
	if runID != event.RunID || sequence != event.Sequence || !bytes.Equal(existing, event.Bytes) {
		return fmt.Errorf("event conflict: repeated event ID has different bytes or identity")
	}
	return nil
}

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
		err := r.database.QueryRow(ctx, `SELECT sequence FROM agent_events.agent_events WHERE workspace_id=$1 AND project_id=$2 AND run_id=$3 AND event_id=$4`, request.Scope.WorkspaceID, request.Scope.ProjectID, request.RunID, request.AfterEventID).Scan(&after)
		if err != nil {
			if err == pgx.ErrNoRows {
				return events.ReplayPage{}, events.CursorExpired()
			}
			return events.ReplayPage{}, err
		}
	}
	rows, err := r.database.Query(ctx, `SELECT event_id,sequence,event_bytes,created_at FROM agent_events.agent_events WHERE workspace_id=$1 AND project_id=$2 AND run_id=$3 AND sequence>$4 ORDER BY sequence LIMIT $5`, request.Scope.WorkspaceID, request.Scope.ProjectID, request.RunID, after, request.Limit+1)
	if err != nil {
		return events.ReplayPage{}, err
	}
	defer rows.Close()
	page := events.ReplayPage{}
	for rows.Next() {
		var event events.Event
		event.RunID = request.RunID
		if err := rows.Scan(&event.ID, &event.Sequence, &event.Bytes, &event.CreatedAt); err != nil {
			return events.ReplayPage{}, err
		}
		if r.guard == nil {
			return events.ReplayPage{}, fmt.Errorf("replay event: contract guard is required")
		}
		if err := events.ValidateEnvelope(event.Bytes, r.bounds, event.ID, event.RunID, event.Sequence); err != nil {
			return events.ReplayPage{}, fmt.Errorf("authoritative event store corruption: %w", err)
		}
		if err := r.guard.Require(ctx, contractguard.EventIn, agentEventSchema, event.Bytes); err != nil {
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
