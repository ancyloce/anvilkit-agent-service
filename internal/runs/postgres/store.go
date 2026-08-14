// Package postgres implements the scoped AgentRun store.
package postgres

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ancyloce/anvilkit-agent-service/internal/events"
	"github.com/ancyloce/anvilkit-agent-service/internal/idempotency"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/runs"
)

type FailurePoint string

const (
	AfterRunWrite        FailurePoint = "after-run-write"
	AfterEventWrite      FailurePoint = "after-event-write"
	AfterOutboxWrite     FailurePoint = "after-outbox-write"
	AfterCheckpointWrite FailurePoint = "after-checkpoint-write"
)

type FailureInjector func(FailurePoint) error

type Store struct {
	database    *pgxpool.Pool
	idempotency *idempotency.Store
	eventBounds events.Bounds
	inject      FailureInjector
}

func New(database *pgxpool.Pool, idempotencyStore *idempotency.Store) *Store {
	return NewConfigured(database, idempotencyStore, events.DefaultBounds(), nil)

}

func NewConfigured(database *pgxpool.Pool, idempotencyStore *idempotency.Store, eventBounds events.Bounds, inject FailureInjector) *Store {
	return &Store{database: database, idempotency: idempotencyStore, eventBounds: eventBounds, inject: inject}
}

func (s *Store) Create(ctx context.Context, record runs.CreateRecord) (runs.CreateOutcome, error) {
	response, err := s.idempotency.Execute(ctx, idempotency.Request{WorkspaceID: record.Scope.WorkspaceID, ProjectID: record.Scope.ProjectID, Operation: "create-run", Key: record.Key, Digest: []byte(record.Digest), VersionBound: 0}, func(ctx context.Context, tx pgx.Tx) (idempotency.Response, error) {
		bytes, err := json.Marshal(record.Snapshot)
		if err != nil {
			return idempotency.Response{}, fmt.Errorf("marshal created run: %w", err)
		}
		_, err = tx.Exec(ctx, `INSERT INTO agent_control.agent_runs(workspace_id,project_id,run_id,state,version,execution_generation,next_event_sequence,snapshot,created_at,updated_at) VALUES($1,$2,$3,$4,1,1,2,$5,$6,$6)`, record.Scope.WorkspaceID, record.Scope.ProjectID, record.Snapshot.RunID, runs.Created, bytes, record.Snapshot.CreatedAt)
		if err != nil {
			return idempotency.Response{}, fmt.Errorf("persist durable run before workflow: %w", err)
		}
		if err := s.fail(AfterRunWrite); err != nil {
			return idempotency.Response{}, err
		}
		eventBytes, err := json.Marshal(map[string]any{"apiVersion": "anvilkit.io/contracts/v1", "kind": "AgentEvent", "eventId": record.Snapshot.LatestEventID, "runId": record.Snapshot.RunID, "sequence": 1, "eventType": "run.created", "occurredAt": contractTimestamp(record.Snapshot.CreatedAt), "traceContext": map[string]string{"traceparent": record.Traceparent}, "contractBomReference": record.Snapshot.ContractBOM, "payload": map[string]string{"state": string(runs.Created)}})
		if err != nil {
			return idempotency.Response{}, fmt.Errorf("marshal created event: %w", err)
		}
		if err := events.ValidateEnvelope(eventBytes, s.eventBounds, record.Snapshot.LatestEventID, string(record.Snapshot.RunID), 1); err != nil {
			return idempotency.Response{}, fmt.Errorf("validate created event: %w", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO agent_events.agent_events(workspace_id,project_id,run_id,sequence,event_id,event_bytes,created_at) VALUES($1,$2,$3,1,$4,$5,$6)`, record.Scope.WorkspaceID, record.Scope.ProjectID, record.Snapshot.RunID, record.Snapshot.LatestEventID, eventBytes, record.Snapshot.CreatedAt); err != nil {
			return idempotency.Response{}, fmt.Errorf("persist created event: %w", err)
		}
		if err := s.fail(AfterEventWrite); err != nil {
			return idempotency.Response{}, err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO agent_events.outbox(workspace_id,project_id,outbox_id,run_id,event_sequence,topic,payload,available_at) VALUES($1,$2,$3,$4,1,'agent.events.v1',$5,$6)`, record.Scope.WorkspaceID, record.Scope.ProjectID, record.Snapshot.LatestEventID, record.Snapshot.RunID, eventBytes, record.Snapshot.CreatedAt); err != nil {
			return idempotency.Response{}, fmt.Errorf("persist created outbox: %w", err)
		}
		if err := s.fail(AfterOutboxWrite); err != nil {
			return idempotency.Response{}, err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO agent_workflow.checkpoints(workspace_id,project_id,workflow_id,workflow_version,step_name,state_bytes) VALUES($1,$2,$3,1,'created',$4)`, record.Scope.WorkspaceID, record.Scope.ProjectID, string(record.Snapshot.RunID)+":v1", bytes); err != nil {
			return idempotency.Response{}, fmt.Errorf("persist created checkpoint: %w", err)
		}
		if err := s.fail(AfterCheckpointWrite); err != nil {
			return idempotency.Response{}, err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO agent_control.run_progress(workspace_id,project_id,run_id,state,entered_at,progress_at) VALUES($1,$2,$3,$4,$5,$5)`, record.Scope.WorkspaceID, record.Scope.ProjectID, record.Snapshot.RunID, runs.Created, record.Snapshot.CreatedAt); err != nil {
			return idempotency.Response{}, fmt.Errorf("persist created progress: %w", err)
		}
		return idempotency.Response{Status: 200, ContentType: "application/json", Body: bytes}, nil
	})
	if err != nil {
		return runs.CreateOutcome{}, translateConflict(err)
	}
	var snapshot runs.Snapshot
	if err := json.Unmarshal(response.Body, &snapshot); err != nil {
		return runs.CreateOutcome{}, fmt.Errorf("decode recorded create response: %w", err)
	}
	snapshot.Version = 1
	snapshot.LatestEventID = string(snapshot.RunID) + ":1"
	return runs.CreateOutcome{Snapshot: snapshot, Bytes: append([]byte(nil), response.Body...), Replayed: response.Replayed}, nil
}

func (s *Store) Get(ctx context.Context, scope runs.Scope, id runs.ID) (runs.Snapshot, error) {
	var raw []byte
	var version uint64
	var latestEventID string
	err := s.database.QueryRow(ctx, `SELECT snapshot,version,COALESCE((SELECT event_id FROM agent_events.agent_events e WHERE e.workspace_id=agent_control.agent_runs.workspace_id AND e.project_id=agent_control.agent_runs.project_id AND e.run_id=agent_control.agent_runs.run_id ORDER BY sequence DESC LIMIT 1),'') FROM agent_control.agent_runs WHERE workspace_id=$1 AND project_id=$2 AND run_id=$3`, scope.WorkspaceID, scope.ProjectID, id).Scan(&raw, &version, &latestEventID)
	if err != nil {
		if err == pgx.ErrNoRows {
			return runs.Snapshot{}, problem.New(problem.CodeResourceNotFound, "")
		}
		return runs.Snapshot{}, fmt.Errorf("get scoped run: %w", err)
	}
	var snapshot runs.Snapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		return runs.Snapshot{}, fmt.Errorf("decode run snapshot: %w", err)
	}
	snapshot.Version = version
	snapshot.LatestEventID = latestEventID
	return snapshot, nil
}

func (s *Store) List(ctx context.Context, scope runs.Scope, options runs.ListOptions) (runs.Page, error) {
	after := ""
	if options.Cursor != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(options.Cursor)
		if err != nil || len(decoded) > 256 {
			return runs.Page{}, requestProblem("cursor is invalid")
		}
		after = string(decoded)
	}
	rows, err := s.database.Query(ctx, `SELECT snapshot,version FROM agent_control.agent_runs WHERE workspace_id=$1 AND project_id=$2 AND run_id>$3 AND ($4='' OR state=$4) ORDER BY run_id LIMIT $5`, scope.WorkspaceID, scope.ProjectID, after, options.State, options.Limit+1)
	if err != nil {
		return runs.Page{}, fmt.Errorf("list scoped runs: %w", err)
	}
	defer rows.Close()
	page := runs.Page{PageInfo: runs.PageInfo{Limit: options.Limit}}
	for rows.Next() {
		var raw []byte
		var version uint64
		if err := rows.Scan(&raw, &version); err != nil {
			return runs.Page{}, err
		}
		var snapshot runs.Snapshot
		if err := json.Unmarshal(raw, &snapshot); err != nil {
			return runs.Page{}, err
		}
		snapshot.Version = version
		page.Items = append(page.Items, snapshot)
	}
	if err := rows.Err(); err != nil {
		return runs.Page{}, err
	}
	if len(page.Items) > options.Limit {
		last := page.Items[options.Limit-1]
		page.Items = page.Items[:options.Limit]
		page.PageInfo.HasMore = true
		page.PageInfo.NextCursor = base64.RawURLEncoding.EncodeToString([]byte(last.RunID))
	}
	return page, nil
}

func (s *Store) Transition(ctx context.Context, scope runs.Scope, id runs.ID, expectedVersion uint64, command runs.Command) (runs.Snapshot, error) {
	tx, err := s.database.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return runs.Snapshot{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var raw []byte
	var version, generation uint64
	var state runs.State
	err = tx.QueryRow(ctx, `SELECT snapshot,version,execution_generation,state FROM agent_control.agent_runs WHERE workspace_id=$1 AND project_id=$2 AND run_id=$3 FOR UPDATE`, scope.WorkspaceID, scope.ProjectID, id).Scan(&raw, &version, &generation, &state)
	if err != nil {
		if err == pgx.ErrNoRows {
			return runs.Snapshot{}, problem.New(problem.CodeResourceNotFound, "")
		}
		return runs.Snapshot{}, err
	}
	if version != expectedVersion {
		return runs.Snapshot{}, problem.New(problem.CodeVersionConflict, "")
	}
	var snapshot runs.Snapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		return runs.Snapshot{}, err
	}
	aggregate := runs.Run{ID: id, State: state, Version: version, ExecutionGeneration: generation, Problem: snapshot.Problem}
	updated, transition, err := aggregate.Apply(command)
	if err != nil {
		return runs.Snapshot{}, err
	}
	snapshot.Status, snapshot.Version, snapshot.ExecutionGeneration, snapshot.Problem, snapshot.UpdatedAt = updated.State, updated.Version, updated.ExecutionGeneration, updated.Problem, time.Now().UTC()
	snapshot.LatestEventID = fmt.Sprintf("%s:%d", id, updated.Version)
	updatedBytes, err := json.Marshal(snapshot)
	if err != nil {
		return runs.Snapshot{}, err
	}
	traceparent := command.Traceparent
	eventBytes, err := json.Marshal(map[string]any{"apiVersion": "anvilkit.io/contracts/v1", "kind": "AgentEvent", "eventId": snapshot.LatestEventID, "runId": id, "sequence": updated.Version, "eventType": "run.state-changed", "occurredAt": contractTimestamp(snapshot.UpdatedAt), "traceContext": map[string]string{"traceparent": traceparent}, "contractBomReference": snapshot.ContractBOM, "payload": map[string]string{"previousState": string(transition.Previous), "state": string(transition.Current)}})
	if err != nil {
		return runs.Snapshot{}, fmt.Errorf("marshal run transition event: %w", err)
	}
	if err := events.ValidateEnvelope(eventBytes, s.eventBounds, snapshot.LatestEventID, string(id), updated.Version); err != nil {
		return runs.Snapshot{}, fmt.Errorf("validate run transition event: %w", err)
	}
	var sequence uint64
	err = tx.QueryRow(ctx, `UPDATE agent_control.agent_runs SET state=$4,version=$5,execution_generation=$6,next_event_sequence=next_event_sequence+1,snapshot=$7,updated_at=$8 WHERE workspace_id=$1 AND project_id=$2 AND run_id=$3 AND version=$9 RETURNING next_event_sequence-1`, scope.WorkspaceID, scope.ProjectID, id, updated.State, updated.Version, updated.ExecutionGeneration, updatedBytes, snapshot.UpdatedAt, expectedVersion).Scan(&sequence)
	if err != nil {
		if err == pgx.ErrNoRows {
			return runs.Snapshot{}, problem.New(problem.CodeVersionConflict, "")
		}
		return runs.Snapshot{}, err
	}
	if err := s.fail(AfterRunWrite); err != nil {
		return runs.Snapshot{}, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO agent_events.agent_events(workspace_id,project_id,run_id,sequence,event_id,event_bytes,created_at) VALUES($1,$2,$3,$4,$5,$6,$7)`, scope.WorkspaceID, scope.ProjectID, id, sequence, snapshot.LatestEventID, eventBytes, snapshot.UpdatedAt); err != nil {
		return runs.Snapshot{}, err
	}
	if err := s.fail(AfterEventWrite); err != nil {
		return runs.Snapshot{}, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO agent_events.outbox(workspace_id,project_id,outbox_id,run_id,event_sequence,topic,payload,available_at) VALUES($1,$2,$3,$4,$5,'agent.events.v1',$6,$7)`, scope.WorkspaceID, scope.ProjectID, snapshot.LatestEventID, id, sequence, eventBytes, snapshot.UpdatedAt); err != nil {
		return runs.Snapshot{}, err
	}
	if err := s.fail(AfterOutboxWrite); err != nil {
		return runs.Snapshot{}, err
	}
	problemBytes, _ := json.Marshal(updated.Problem)
	if updated.Problem == nil {
		problemBytes = nil
	}
	if _, err := tx.Exec(ctx, `INSERT INTO agent_workflow.checkpoints(workspace_id,project_id,workflow_id,workflow_version,step_name,state_bytes,problem_bytes) VALUES($1,$2,$3,1,$4,$5,$6)`, scope.WorkspaceID, scope.ProjectID, string(id)+":v1", fmt.Sprintf("%s-v%d", updated.State, updated.Version), updatedBytes, problemBytes); err != nil {
		return runs.Snapshot{}, err
	}
	if err := s.fail(AfterCheckpointWrite); err != nil {
		return runs.Snapshot{}, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO agent_control.run_progress(workspace_id,project_id,run_id,state,entered_at,progress_at,stuck_at) VALUES($1,$2,$3,$4,$5,$5,NULL) ON CONFLICT(workspace_id,project_id,run_id) DO UPDATE SET state=EXCLUDED.state,entered_at=EXCLUDED.entered_at,progress_at=EXCLUDED.progress_at,stuck_at=NULL`, scope.WorkspaceID, scope.ProjectID, id, updated.State, snapshot.UpdatedAt); err != nil {
		return runs.Snapshot{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return runs.Snapshot{}, err
	}
	return snapshot, nil
}

func (s *Store) fail(point FailurePoint) error {
	if s.inject == nil {
		return nil
	}
	if err := s.inject(point); err != nil {
		return fmt.Errorf("injected run-store failure at %s: %w", point, err)
	}
	return nil
}

func translateConflict(err error) error {
	if contains(err.Error(), "canonical digest") {
		return problem.New(problem.CodeIdempotencyConflict, "")
	}
	if contains(err.Error(), "version") {
		return problem.New(problem.CodeVersionConflict, "")
	}
	return err
}
func contains(value, fragment string) bool {
	for index := 0; index+len(fragment) <= len(value); index++ {
		if value[index:index+len(fragment)] == fragment {
			return true
		}
	}
	return false
}
func requestProblem(detail string) problem.Details {
	value := problem.New(problem.CodeRequestInvalid, "")
	value.Detail = detail
	return value
}

var _ runs.Store = (*Store)(nil)

func contractTimestamp(value time.Time) string {
	return value.UTC().Truncate(time.Millisecond).Format("2006-01-02T15:04:05.000Z")
}
