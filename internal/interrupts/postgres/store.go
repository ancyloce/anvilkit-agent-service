// Package postgres implements durable Control control authority in the same
// Postgres transaction as run state, events, outbox, and checkpoints.
package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ancyloce/anvilkit-agent-service/internal/events"
	"github.com/ancyloce/anvilkit-agent-service/internal/idempotency"
	"github.com/ancyloce/anvilkit-agent-service/internal/interrupts"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/runs"
)

type Store struct {
	database    *pgxpool.Pool
	idempotency *idempotency.Store
	clock       func() time.Time
}

func New(database *pgxpool.Pool, idempotencyStore *idempotency.Store) (*Store, error) {
	if database == nil || idempotencyStore == nil {
		return nil, fmt.Errorf("interrupt Postgres store requires database and idempotency store")
	}
	return &Store{database: database, idempotency: idempotencyStore, clock: time.Now}, nil
}

func (s *Store) Current(ctx context.Context, scope runs.Scope, id runs.ID) (runs.Snapshot, error) {
	var raw []byte
	var version uint64
	err := s.database.QueryRow(ctx, `SELECT snapshot,version FROM agent_control.agent_runs WHERE workspace_id=$1 AND project_id=$2 AND run_id=$3`, scope.WorkspaceID, scope.ProjectID, id).Scan(&raw, &version)
	if err != nil {
		return runs.Snapshot{}, translate(err)
	}
	return decodeSnapshot(raw, version)
}

func (s *Store) Input(ctx context.Context, scope runs.Scope, runID runs.ID, id interrupts.RequestID) (interrupts.InputRequest, error) {
	var request interrupts.InputRequest
	var schema, response []byte
	var responseVersion *uint64
	var actor *string
	var accepted *time.Time
	err := s.database.QueryRow(ctx, `SELECT request_id,run_id,request_version,question,response_schema,expires_at,resume_checkpoint,created_at,response_bytes,response_actor_id,responded_at FROM agent_control.input_requests WHERE workspace_id=$1 AND project_id=$2 AND run_id=$3 AND request_id=$4`, scope.WorkspaceID, scope.ProjectID, runID, id).Scan(&request.ID, &request.RunID, &request.Version, &request.Question, &schema, &request.ExpiresAt, &request.ResumeCheckpoint, &request.CreatedAt, &response, &actor, &accepted)
	if err != nil {
		return interrupts.InputRequest{}, translate(err)
	}
	request.ResponseSchema = clone(schema)
	if accepted != nil {
		v := request.Version
		responseVersion = &v
		request.Response = &interrupts.InputResponse{RequestVersion: *responseVersion, Value: clone(response), ActorID: *actor, AcceptedAt: *accepted}
	}
	return request, nil
}

func (s *Store) OpenInput(ctx context.Context, write interrupts.Write, request interrupts.InputRequest, digest string) (interrupts.InputRequest, interrupts.OperationResult, error) {
	type envelope struct {
		Request interrupts.InputRequest    `json:"request"`
		Result  interrupts.OperationResult `json:"result"`
	}
	var value envelope
	replay, err := s.execute(ctx, write, "request-input", digest, func(ctx context.Context, tx pgx.Tx) (any, error) {
		err := tx.QueryRow(ctx, `INSERT INTO agent_control.input_requests(workspace_id,project_id,run_id,request_id,request_version,run_version,question,response_schema,resume_checkpoint,expires_at,created_at) VALUES($1,$2,$3,$4,(SELECT COALESCE(MAX(request_version),0)+1 FROM agent_control.input_requests WHERE workspace_id=$1 AND project_id=$2 AND run_id=$3),$5,$6,$7,$8,$9,$10) RETURNING request_version`, write.Scope.WorkspaceID, write.Scope.ProjectID, write.RunID, request.ID, write.ExpectedVersion, request.Question, request.ResponseSchema, request.ResumeCheckpoint, request.ExpiresAt, request.CreatedAt).Scan(&request.Version)
		if err != nil {
			return nil, err
		}
		snapshot, err := s.transition(ctx, tx, write, runs.Command{Kind: runs.RequestInput, Traceparent: write.Traceparent}, request.CreatedAt)
		if err != nil {
			return nil, err
		}
		return envelope{request, interrupts.OperationResult{Snapshot: snapshot}}, nil
	}, &value)
	if err != nil {
		return interrupts.InputRequest{}, interrupts.OperationResult{}, err
	}
	value.Result.Replayed = replay
	return value.Request, value.Result, nil
}

func (s *Store) AcceptInput(ctx context.Context, write interrupts.Write, command interrupts.InputResponseCommand, digest string, now time.Time) (interrupts.OperationResult, error) {
	var result interrupts.OperationResult
	replay, err := s.execute(ctx, write, "respond-input", digest, func(ctx context.Context, tx pgx.Tx) (any, error) {
		var version uint64
		var expires time.Time
		var responded *time.Time
		err := tx.QueryRow(ctx, `SELECT request_version,expires_at,responded_at FROM agent_control.input_requests WHERE workspace_id=$1 AND project_id=$2 AND run_id=$3 AND request_id=$4 FOR UPDATE`, write.Scope.WorkspaceID, write.Scope.ProjectID, write.RunID, command.RequestID).Scan(&version, &expires, &responded)
		if err != nil {
			return nil, err
		}
		if version != command.RequestVersion {
			return nil, interruptsProblem(problem.CodeInputRequestStale, "input request version is not current")
		}
		if responded != nil {
			return nil, interruptsProblem(problem.CodeInputAlreadyResponded, "input response is immutable")
		}
		if !now.Before(expires) {
			return nil, interruptsProblem(problem.CodeInputRequestExpired, "expired input remains awaiting input until the timeout policy is finalized")
		}
		if _, err := tx.Exec(ctx, `UPDATE agent_control.input_requests SET response_bytes=$5,response_digest=$6,response_actor_id=$7,responded_at=$8 WHERE workspace_id=$1 AND project_id=$2 AND run_id=$3 AND request_id=$4 AND responded_at IS NULL`, write.Scope.WorkspaceID, write.Scope.ProjectID, write.RunID, command.RequestID, command.Value, digest, write.Scope.ActorID, now); err != nil {
			return nil, err
		}
		snapshot, err := s.transition(ctx, tx, write, runs.Command{Kind: runs.AcceptInput, Traceparent: write.Traceparent}, now)
		if err != nil {
			return nil, err
		}
		return interrupts.OperationResult{Snapshot: snapshot}, nil
	}, &result)
	if err != nil {
		return interrupts.OperationResult{}, err
	}
	result.Replayed = replay
	return result, nil
}

func (s *Store) Approval(ctx context.Context, scope runs.Scope, runID runs.ID, id interrupts.RequestID) (interrupts.ApprovalRequest, error) {
	var request interrupts.ApprovalRequest
	var effects, cost, policy []byte
	var decision *string
	var reason, reviewer *string
	var decided *time.Time
	err := s.database.QueryRow(ctx, `SELECT request_id,run_id,decision_version,action_digest,effects,expected_cost,reviewer_policy,expires_at,resume_checkpoint,created_at,decision,decision_reason,reviewer_id,decided_at FROM agent_control.approval_requests WHERE workspace_id=$1 AND project_id=$2 AND run_id=$3 AND request_id=$4`, scope.WorkspaceID, scope.ProjectID, runID, id).Scan(&request.ID, &request.RunID, &request.Version, &request.ActionDigest, &effects, &cost, &policy, &request.ExpiresAt, &request.ResumeCheckpoint, &request.CreatedAt, &decision, &reason, &reviewer, &decided)
	if err != nil {
		return interrupts.ApprovalRequest{}, translate(err)
	}
	request.Effects, request.ExpectedCost, request.ReviewerPolicy = clone(effects), clone(cost), clone(policy)
	if decision != nil {
		request.Decision = &interrupts.Decision{RequestVersion: request.Version, Kind: interrupts.DecisionKind(*decision), ReviewerID: *reviewer, AcceptedAt: *decided}
		if reason != nil {
			request.Decision.Reason = *reason
		}
	}
	return request, nil
}

func (s *Store) OpenApproval(ctx context.Context, write interrupts.Write, request interrupts.ApprovalRequest, digest string) (interrupts.ApprovalRequest, interrupts.OperationResult, error) {
	type envelope struct {
		Request interrupts.ApprovalRequest `json:"request"`
		Result  interrupts.OperationResult `json:"result"`
	}
	var value envelope
	replay, err := s.execute(ctx, write, "request-approval", digest, func(ctx context.Context, tx pgx.Tx) (any, error) {
		err := tx.QueryRow(ctx, `INSERT INTO agent_control.approval_requests(workspace_id,project_id,run_id,request_id,decision_version,run_version,action_digest,effects,expected_cost,reviewer_policy,resume_checkpoint,expires_at,created_at) VALUES($1,$2,$3,$4,(SELECT COALESCE(MAX(decision_version),0)+1 FROM agent_control.approval_requests WHERE workspace_id=$1 AND project_id=$2 AND run_id=$3),$5,$6,$7,$8,$9,$10,$11,$12) RETURNING decision_version`, write.Scope.WorkspaceID, write.Scope.ProjectID, write.RunID, request.ID, write.ExpectedVersion, request.ActionDigest, request.Effects, request.ExpectedCost, request.ReviewerPolicy, request.ResumeCheckpoint, request.ExpiresAt, request.CreatedAt).Scan(&request.Version)
		if err != nil {
			return nil, err
		}
		snapshot, err := s.transition(ctx, tx, write, runs.Command{Kind: runs.RequestApproval, Traceparent: write.Traceparent}, request.CreatedAt)
		if err != nil {
			return nil, err
		}
		return envelope{request, interrupts.OperationResult{Snapshot: snapshot}}, nil
	}, &value)
	if err != nil {
		return interrupts.ApprovalRequest{}, interrupts.OperationResult{}, err
	}
	value.Result.Replayed = replay
	return value.Request, value.Result, nil
}

func (s *Store) DecideApproval(ctx context.Context, write interrupts.Write, command interrupts.ApprovalDecisionCommand, digest string, now time.Time) (interrupts.OperationResult, error) {
	var result interrupts.OperationResult
	replay, err := s.execute(ctx, write, "decide-approval", digest, func(ctx context.Context, tx pgx.Tx) (any, error) {
		var version uint64
		var expires time.Time
		var decided *time.Time
		err := tx.QueryRow(ctx, `SELECT decision_version,expires_at,decided_at FROM agent_control.approval_requests WHERE workspace_id=$1 AND project_id=$2 AND run_id=$3 AND request_id=$4 FOR UPDATE`, write.Scope.WorkspaceID, write.Scope.ProjectID, write.RunID, command.RequestID).Scan(&version, &expires, &decided)
		if err != nil {
			return nil, err
		}
		if version != command.RequestVersion {
			return nil, interruptsProblem(problem.CodeApprovalRequestStale, "approval version is not current")
		}
		if decided != nil {
			return nil, interruptsProblem(problem.CodeApprovalAlreadyDecided, "approval decision is immutable")
		}
		if !now.Before(expires) {
			return nil, interruptsProblem(problem.CodeApprovalRequestExpired, "expired approval remains awaiting approval until the timeout policy is finalized")
		}
		if _, err := tx.Exec(ctx, `UPDATE agent_control.approval_requests SET decision=$5,decision_reason=$6,reviewer_id=$7,decided_at=$8 WHERE workspace_id=$1 AND project_id=$2 AND run_id=$3 AND request_id=$4 AND decided_at IS NULL`, write.Scope.WorkspaceID, write.Scope.ProjectID, write.RunID, command.RequestID, command.Decision, command.Reason, write.Scope.ActorID, now); err != nil {
			return nil, err
		}
		snapshot, err := s.load(ctx, tx, write.Scope, write.RunID)
		if err != nil {
			return nil, err
		}
		if command.Decision == interrupts.DecisionReject || command.Decision == interrupts.DecisionChange {
			snapshot, err = s.transition(ctx, tx, write, runs.Command{Kind: runs.RejectApproval, Traceparent: write.Traceparent}, now)
			if err != nil {
				return nil, err
			}
		} else if err := s.controlEvent(ctx, tx, write, snapshot, "approval.decided", now); err != nil {
			return nil, err
		}
		return interrupts.OperationResult{Snapshot: snapshot}, nil
	}, &result)
	if err != nil {
		return interrupts.OperationResult{}, err
	}
	result.Replayed = replay
	return result, nil
}

func (s *Store) RequestCancellation(ctx context.Context, write interrupts.Write, digest string, now time.Time) (interrupts.Cancellation, interrupts.OperationResult, error) {
	type envelope struct {
		Cancellation interrupts.Cancellation    `json:"cancellation"`
		Result       interrupts.OperationResult `json:"result"`
	}
	var value envelope
	replay, err := s.execute(ctx, write, "cancel", digest, func(ctx context.Context, tx pgx.Tx) (any, error) {
		snapshot, err := s.load(ctx, tx, write.Scope, write.RunID)
		if err != nil {
			return nil, err
		}
		commit := snapshot.Status == runs.Committing || snapshot.Status == runs.AwaitingDomainConfirmation
		if !commit {
			snapshot, err = s.transition(ctx, tx, write, runs.Command{Kind: runs.RequestCancellation, Traceparent: write.Traceparent}, now)
			if err != nil {
				return nil, err
			}
		} else if err := s.controlEvent(ctx, tx, write, snapshot, "run.cancellation-requested", now); err != nil {
			return nil, err
		}
		c := interrupts.Cancellation{RequestedAt: now, RequestedBy: write.Scope.ActorID, CommitPhase: commit}
		evidence, _ := json.Marshal(c)
		if _, err := tx.Exec(ctx, `INSERT INTO agent_control.lifecycle_controls(workspace_id,project_id,run_id,control_id,control_kind,run_version,execution_generation,actor_id,request_digest,evidence,created_at) VALUES($1,$2,$3,$4,'cancel',$5,$6,$7,$8,$9,$10)`, write.Scope.WorkspaceID, write.Scope.ProjectID, write.RunID, write.IdempotencyKey, write.ExpectedVersion, snapshot.ExecutionGeneration, write.Scope.ActorID, digest, evidence, now); err != nil {
			return nil, err
		}
		return envelope{c, interrupts.OperationResult{Snapshot: snapshot}}, nil
	}, &value)
	if err != nil {
		return interrupts.Cancellation{}, interrupts.OperationResult{}, err
	}
	value.Result.Replayed = replay
	return value.Cancellation, value.Result, nil
}

func (s *Store) RecordCancellation(ctx context.Context, write interrupts.Write, cancellation interrupts.Cancellation) error {
	evidence, err := json.Marshal(cancellation)
	if err != nil {
		return err
	}
	tag, err := s.database.Exec(ctx, `UPDATE agent_control.lifecycle_controls SET evidence=$5 WHERE workspace_id=$1 AND project_id=$2 AND run_id=$3 AND control_id=$4 AND control_kind='cancel'`, write.Scope.WorkspaceID, write.Scope.ProjectID, write.RunID, write.IdempotencyKey, evidence)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return problem.New(problem.CodeVersionConflict, "")
	}
	return nil
}

func (s *Store) FinishCancellation(ctx context.Context, write interrupts.Write, c interrupts.Cancellation) (interrupts.OperationResult, error) {
	if c.CommitPhase || c.ExternalUncertain || !c.Reconciled {
		return interrupts.OperationResult{}, interruptsProblem(problem.CodeCancellationUnreconciled, "cancellation has not reconciled")
	}
	var result interrupts.OperationResult
	replay, err := s.execute(ctx, write, "cancel-reconciled", "sha256:reconciled", func(ctx context.Context, tx pgx.Tx) (any, error) {
		snapshot, err := s.transition(ctx, tx, write, runs.Command{Kind: runs.ReconcileCancellation, Traceparent: write.Traceparent}, s.clock().UTC())
		if err != nil {
			return nil, err
		}
		return interrupts.OperationResult{Snapshot: snapshot}, nil
	}, &result)
	if err != nil {
		return interrupts.OperationResult{}, err
	}
	result.Replayed = replay
	return result, nil
}

func (s *Store) RecordedRetry(ctx context.Context, write interrupts.Write, digest string) (interrupts.RetryOutcome, bool, error) {
	var storedDigest []byte
	var version int64
	var raw []byte
	err := s.database.QueryRow(ctx, `SELECT request_digest,version_bound,response_body FROM agent_control.write_idempotency WHERE workspace_id=$1 AND project_id=$2 AND operation='retry' AND idempotency_key=$3`, write.Scope.WorkspaceID, write.Scope.ProjectID, write.IdempotencyKey).Scan(&storedDigest, &version, &raw)
	if err == pgx.ErrNoRows {
		return interrupts.RetryOutcome{}, false, nil
	}
	if err != nil {
		return interrupts.RetryOutcome{}, false, err
	}
	if string(storedDigest) != digest || uint64(version) != write.ExpectedVersion {
		return interrupts.RetryOutcome{}, false, problem.New(problem.CodeIdempotencyConflict, "")
	}
	var result interrupts.RetryOutcome
	if err := json.Unmarshal(raw, &result); err != nil {
		return interrupts.RetryOutcome{}, false, err
	}
	result.Replayed = true
	return result, true, nil
}
func (s *Store) Retry(ctx context.Context, write interrupts.Write, digest, checkpoint string) (interrupts.RetryOutcome, error) {
	var result interrupts.RetryOutcome
	replay, err := s.execute(ctx, write, "retry", digest, func(ctx context.Context, tx pgx.Tx) (any, error) {
		snapshot, err := s.transition(ctx, tx, write, runs.Command{Kind: runs.Retry, RetryEligible: true, Traceparent: write.Traceparent}, s.clock().UTC())
		if err != nil {
			return nil, err
		}
		evidence, _ := json.Marshal(map[string]any{"resumeCheckpoint": checkpoint})
		if _, err := tx.Exec(ctx, `INSERT INTO agent_control.lifecycle_controls(workspace_id,project_id,run_id,control_id,control_kind,run_version,execution_generation,actor_id,request_digest,evidence,created_at) VALUES($1,$2,$3,$4,'retry',$5,$6,$7,$8,$9,$10)`, write.Scope.WorkspaceID, write.Scope.ProjectID, write.RunID, write.IdempotencyKey, write.ExpectedVersion, snapshot.ExecutionGeneration, write.Scope.ActorID, digest, evidence, s.clock().UTC()); err != nil {
			return nil, err
		}
		return interrupts.RetryOutcome{Snapshot: snapshot, ResumeCheckpoint: checkpoint}, nil
	}, &result)
	if err != nil {
		return interrupts.RetryOutcome{}, err
	}
	result.Replayed = replay
	return result, nil
}
func (s *Store) Discard(ctx context.Context, write interrupts.Write, digest string) (interrupts.OperationResult, error) {
	var result interrupts.OperationResult
	replay, err := s.execute(ctx, write, "discard", digest, func(ctx context.Context, tx pgx.Tx) (any, error) {
		now := s.clock().UTC()
		snapshot, err := s.transition(ctx, tx, write, runs.Command{Kind: runs.Discard, Traceparent: write.Traceparent}, now)
		if err != nil {
			return nil, err
		}
		evidence, _ := json.Marshal(map[string]any{"retained": []string{"events", "artifacts"}})
		if _, err := tx.Exec(ctx, `INSERT INTO agent_control.lifecycle_controls(workspace_id,project_id,run_id,control_id,control_kind,run_version,execution_generation,actor_id,request_digest,evidence,created_at) VALUES($1,$2,$3,$4,'discard',$5,$6,$7,$8,$9,$10)`, write.Scope.WorkspaceID, write.Scope.ProjectID, write.RunID, write.IdempotencyKey, write.ExpectedVersion, snapshot.ExecutionGeneration, write.Scope.ActorID, digest, evidence, now); err != nil {
			return nil, err
		}
		return interrupts.OperationResult{Snapshot: snapshot}, nil
	}, &result)
	if err != nil {
		return interrupts.OperationResult{}, err
	}
	result.Replayed = replay
	return result, nil
}

func (s *Store) CreateChild(ctx context.Context, write interrupts.Write, child interrupts.Child, digest string) (interrupts.Child, error) {
	var result interrupts.Child
	_, err := s.execute(ctx, write, "create-child", digest, func(ctx context.Context, tx pgx.Tx) (any, error) {
		parent, err := s.load(ctx, tx, write.Scope, write.RunID)
		if err != nil {
			return nil, err
		}
		if parent.Status != runs.Executing {
			return nil, problem.New(problem.CodeInvalidTransition, "")
		}
		child.RootRunID = parent.RootRunID
		if child.RootRunID == "" {
			child.RootRunID = parent.RunID
		}
		child.ContractBOM = clone(parent.ContractBOM)
		child.DataPolicy = clone(parent.Policy)
		childSnapshot := parent
		childSnapshot.RunID = child.RunID
		childSnapshot.RootRunID = child.RootRunID
		parentID := child.ParentRunID
		childSnapshot.ParentRunID = &parentID
		childSnapshot.Status = runs.Created
		childSnapshot.Version = 1
		childSnapshot.ExecutionGeneration = 1
		childSnapshot.Problem = nil
		childSnapshot.CreatedAt = child.CreatedAt
		childSnapshot.UpdatedAt = child.CreatedAt
		childSnapshot.LatestEventID = string(child.RunID) + ":1"
		childSnapshot.Idempotency = runs.IdempotencyProjection{Scope: write.Scope.WorkspaceID + ":create-child", Key: write.IdempotencyKey, CanonicalRequestDigest: digest}
		childBytes, err := json.Marshal(childSnapshot)
		if err != nil {
			return nil, err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO agent_control.agent_runs(workspace_id,project_id,run_id,state,version,execution_generation,next_event_sequence,snapshot,created_at,updated_at) VALUES($1,$2,$3,$4,1,1,2,$5,$6,$6)`, write.Scope.WorkspaceID, write.Scope.ProjectID, child.RunID, runs.Created, childBytes, child.CreatedAt); err != nil {
			return nil, err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO agent_control.run_children(workspace_id,project_id,root_run_id,parent_run_id,child_run_id,mode,predecessor_run_id,depth,actor_id,contract_bom,data_policy,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, write.Scope.WorkspaceID, write.Scope.ProjectID, child.RootRunID, child.ParentRunID, child.RunID, child.Mode, child.PredecessorRunID, child.Depth, child.ActorID, child.ContractBOM, child.DataPolicy, child.CreatedAt); err != nil {
			return nil, err
		}
		childWrite := interrupts.Write{Scope: write.Scope, RunID: child.RunID, Traceparent: write.Traceparent}
		event, err := marshalEvent(childWrite, childSnapshot, 1, childSnapshot.LatestEventID, "run.created", map[string]string{
			"parentRunId": string(child.ParentRunID),
			"rootRunId":   string(child.RootRunID),
			"state":       string(runs.Created),
		}, child.CreatedAt)
		if err != nil {
			return nil, err
		}
		if err := s.persistEvent(ctx, tx, childWrite, 1, childSnapshot.LatestEventID, event, child.CreatedAt); err != nil {
			return nil, err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO agent_workflow.checkpoints(workspace_id,project_id,workflow_id,workflow_version,step_name,state_bytes) VALUES($1,$2,$3,1,'created',$4)`, write.Scope.WorkspaceID, write.Scope.ProjectID, string(child.RunID)+":g1", childBytes); err != nil {
			return nil, err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO agent_control.run_progress(workspace_id,project_id,run_id,state,entered_at,progress_at) VALUES($1,$2,$3,$4,$5,$5)`, write.Scope.WorkspaceID, write.Scope.ProjectID, child.RunID, runs.Created, child.CreatedAt); err != nil {
			return nil, err
		}
		return child, nil
	}, &result)
	return result, err
}
func (s *Store) Parent(ctx context.Context, scope runs.Scope, id runs.ID) (interrupts.Child, bool, error) {
	var child interrupts.Child
	err := s.database.QueryRow(ctx, `SELECT child_run_id,root_run_id,parent_run_id,workspace_id,project_id,actor_id,contract_bom,data_policy,mode,predecessor_run_id,depth,created_at FROM agent_control.run_children WHERE workspace_id=$1 AND project_id=$2 AND child_run_id=$3`, scope.WorkspaceID, scope.ProjectID, id).Scan(&child.RunID, &child.RootRunID, &child.ParentRunID, &child.WorkspaceID, &child.ProjectID, &child.ActorID, &child.ContractBOM, &child.DataPolicy, &child.Mode, &child.PredecessorRunID, &child.Depth, &child.CreatedAt)
	if err == pgx.ErrNoRows {
		return interrupts.Child{}, false, nil
	}
	if err != nil {
		return interrupts.Child{}, false, err
	}
	return child, true, nil
}
func (s *Store) RecordChildOutcome(ctx context.Context, scope runs.Scope, id runs.ID, outcome interrupts.ChildOutcome) error {
	tx, err := s.database.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var mode interrupts.ChildMode
	var parentID runs.ID
	var existing *string
	if err := tx.QueryRow(ctx, `SELECT mode,parent_run_id,outcome_state FROM agent_control.run_children WHERE workspace_id=$1 AND project_id=$2 AND child_run_id=$3 FOR UPDATE`, scope.WorkspaceID, scope.ProjectID, id).Scan(&mode, &parentID, &existing); err != nil {
		return translate(err)
	}
	if existing != nil {
		if runs.State(*existing) == outcome.State {
			return tx.Commit(ctx)
		}
		return problem.New(problem.CodeIdempotencyConflict, "")
	}
	if mode == interrupts.ChildOptional && outcome.State != runs.Completed && outcome.Warning == "" {
		outcome.Warning = "optional child did not complete"
	}
	if outcome.Artifact != "" && (len(outcome.Artifact) > 512 || !strings.HasPrefix(outcome.Artifact, "artifact-lineage:")) {
		return problem.New(problem.CodeRequestInvalid, "")
	}
	if _, err := tx.Exec(ctx, `UPDATE agent_control.run_children SET outcome_state=$4,warning=$5,artifact_lineage_reference=$6 WHERE workspace_id=$1 AND project_id=$2 AND child_run_id=$3`, scope.WorkspaceID, scope.ProjectID, id, outcome.State, outcome.Warning, outcome.Artifact); err != nil {
		return err
	}
	if mode == interrupts.ChildRequired && outcome.State != runs.Completed {
		parent, err := s.load(ctx, tx, scope, parentID)
		if err != nil {
			return err
		}
		if parent.Status == runs.Executing || parent.Status == runs.Validating {
			failure := problem.New(problem.CodeWorkerFailed, "")
			failure.Detail = "required child did not complete"
			write := interrupts.Write{Scope: scope, RunID: parentID, ExpectedVersion: parent.Version, IdempotencyKey: "child-outcome:" + string(id), Traceparent: "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"}
			if _, err := s.transition(ctx, tx, write, runs.Command{Kind: runs.RecordFailure, Failure: &failure, Traceparent: write.Traceparent}, s.clock().UTC()); err != nil {
				return err
			}
		}
	}
	return tx.Commit(ctx)
}
func (s *Store) ChildOutcome(ctx context.Context, scope runs.Scope, id runs.ID) (interrupts.ChildOutcome, error) {
	var value interrupts.ChildOutcome
	err := s.database.QueryRow(ctx, `SELECT outcome_state,COALESCE(warning,''),COALESCE(artifact_lineage_reference,'') FROM agent_control.run_children WHERE workspace_id=$1 AND project_id=$2 AND child_run_id=$3 AND outcome_state IS NOT NULL`, scope.WorkspaceID, scope.ProjectID, id).Scan(&value.State, &value.Warning, &value.Artifact)
	if err != nil {
		return interrupts.ChildOutcome{}, translate(err)
	}
	return value, nil
}
func (s *Store) Descendants(ctx context.Context, scope runs.Scope, id runs.ID) ([]interrupts.Child, error) {
	rows, err := s.database.Query(ctx, `WITH RECURSIVE descendants AS (SELECT * FROM agent_control.run_children WHERE workspace_id=$1 AND project_id=$2 AND parent_run_id=$3 UNION ALL SELECT c.* FROM agent_control.run_children c JOIN descendants d ON c.parent_run_id=d.child_run_id WHERE c.workspace_id=$1 AND c.project_id=$2) SELECT child_run_id,root_run_id,parent_run_id,workspace_id,project_id,actor_id,contract_bom,data_policy,mode,predecessor_run_id,depth,created_at FROM descendants ORDER BY depth,child_run_id`, scope.WorkspaceID, scope.ProjectID, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []interrupts.Child
	for rows.Next() {
		var child interrupts.Child
		if err := rows.Scan(&child.RunID, &child.RootRunID, &child.ParentRunID, &child.WorkspaceID, &child.ProjectID, &child.ActorID, &child.ContractBOM, &child.DataPolicy, &child.Mode, &child.PredecessorRunID, &child.Depth, &child.CreatedAt); err != nil {
			return nil, err
		}
		result = append(result, child)
	}
	return result, rows.Err()
}

func (s *Store) RecordProgress(ctx context.Context, scope runs.Scope, id runs.ID, state runs.State, at time.Time) error {
	tag, err := s.database.Exec(ctx, `UPDATE agent_control.run_progress SET progress_at=GREATEST(progress_at,$5) WHERE workspace_id=$1 AND project_id=$2 AND run_id=$3 AND state=$4`, scope.WorkspaceID, scope.ProjectID, id, state, at)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return problem.New(problem.CodeVersionConflict, "")
	}
	return nil
}
func (s *Store) Progress(ctx context.Context) ([]interrupts.Progress, error) {
	rows, err := s.database.Query(ctx, `SELECT workspace_id,project_id,run_id,state,entered_at,progress_at,stuck_at FROM agent_control.run_progress`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []interrupts.Progress
	for rows.Next() {
		var p interrupts.Progress
		if err := rows.Scan(&p.Scope.WorkspaceID, &p.Scope.ProjectID, &p.RunID, &p.State, &p.EnteredAt, &p.ProgressAt, &p.StuckAt); err != nil {
			return nil, err
		}
		result = append(result, p)
	}
	return result, rows.Err()
}
func (s *Store) MarkStuck(ctx context.Context, progress interrupts.Progress, at time.Time, owner string) (bool, error) {
	tx, err := s.database.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	write := interrupts.Write{Scope: progress.Scope, RunID: progress.RunID, Traceparent: "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"}
	snapshot, err := s.load(ctx, tx, progress.Scope, progress.RunID)
	if err != nil {
		return false, err
	}
	if snapshot.Status != progress.State {
		return false, nil
	}
	tag, err := tx.Exec(ctx, `UPDATE agent_control.run_progress SET stuck_at=$5 WHERE workspace_id=$1 AND project_id=$2 AND run_id=$3 AND state=$4 AND stuck_at IS NULL`, progress.Scope.WorkspaceID, progress.Scope.ProjectID, progress.RunID, progress.State, at)
	if err != nil {
		return false, err
	}
	if tag.RowsAffected() != 1 {
		return false, tx.Commit(ctx)
	}
	if err := s.controlEvent(ctx, tx, write, snapshot, "run.stuck", at); err != nil {
		return false, err
	}
	alertID := fmt.Sprintf("%s:dwell:%s:%d", progress.RunID, progress.State, progress.EnteredAt.UnixNano())
	evidence, err := json.Marshal(map[string]any{"enteredAt": progress.EnteredAt, "progressAt": progress.ProgressAt, "breachedAt": at})
	if err != nil {
		return false, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO agent_control.run_alerts(workspace_id,project_id,alert_id,run_id,state,alert_kind,owner,evidence,created_at) VALUES($1,$2,$3,$4,$5,'run-dwell-deadline',$6,$7,$8)`, progress.Scope.WorkspaceID, progress.Scope.ProjectID, alertID, progress.RunID, progress.State, owner, evidence, at); err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return true, nil
}

func (s *Store) execute(ctx context.Context, write interrupts.Write, operation, digest string, handler func(context.Context, pgx.Tx) (any, error), target any) (bool, error) {
	response, err := s.idempotency.Execute(ctx, idempotency.Request{WorkspaceID: write.Scope.WorkspaceID, ProjectID: write.Scope.ProjectID, Operation: operation, Key: write.IdempotencyKey, RunID: string(write.RunID), Digest: []byte(digest), VersionBound: int64(write.ExpectedVersion)}, func(ctx context.Context, tx pgx.Tx) (idempotency.Response, error) {
		value, err := handler(ctx, tx)
		if err != nil {
			return idempotency.Response{}, err
		}
		raw, err := json.Marshal(value)
		if err != nil {
			return idempotency.Response{}, err
		}
		return idempotency.Response{Status: 200, ContentType: "application/json", Body: raw}, nil
	})
	if err != nil {
		return false, translate(err)
	}
	if err := json.Unmarshal(response.Body, target); err != nil {
		return false, err
	}
	return response.Replayed, nil
}
func (s *Store) load(ctx context.Context, tx pgx.Tx, scope runs.Scope, id runs.ID) (runs.Snapshot, error) {
	var raw []byte
	var version uint64
	err := tx.QueryRow(ctx, `SELECT snapshot,version FROM agent_control.agent_runs WHERE workspace_id=$1 AND project_id=$2 AND run_id=$3 FOR UPDATE`, scope.WorkspaceID, scope.ProjectID, id).Scan(&raw, &version)
	if err != nil {
		return runs.Snapshot{}, translate(err)
	}
	return decodeSnapshot(raw, version)
}
func (s *Store) transition(ctx context.Context, tx pgx.Tx, write interrupts.Write, command runs.Command, now time.Time) (runs.Snapshot, error) {
	snapshot, err := s.load(ctx, tx, write.Scope, write.RunID)
	if err != nil {
		return runs.Snapshot{}, err
	}
	aggregate := runs.Run{ID: snapshot.RunID, State: snapshot.Status, Version: snapshot.Version, ExecutionGeneration: snapshot.ExecutionGeneration, Problem: snapshot.Problem}
	updated, transition, err := aggregate.Apply(command)
	if err != nil {
		return runs.Snapshot{}, err
	}
	snapshot.Status, snapshot.Version, snapshot.ExecutionGeneration, snapshot.Problem, snapshot.UpdatedAt = updated.State, updated.Version, updated.ExecutionGeneration, updated.Problem, now
	snapshot.LatestEventID = fmt.Sprintf("%s:%d", write.RunID, updated.Version)
	raw, err := json.Marshal(snapshot)
	if err != nil {
		return runs.Snapshot{}, err
	}
	var sequence uint64
	err = tx.QueryRow(ctx, `UPDATE agent_control.agent_runs SET state=$4,version=$5,execution_generation=$6,next_event_sequence=next_event_sequence+1,snapshot=$7,updated_at=$8 WHERE workspace_id=$1 AND project_id=$2 AND run_id=$3 AND version=$9 RETURNING next_event_sequence-1`, write.Scope.WorkspaceID, write.Scope.ProjectID, write.RunID, updated.State, updated.Version, updated.ExecutionGeneration, raw, now, write.ExpectedVersion).Scan(&sequence)
	if err == pgx.ErrNoRows {
		return runs.Snapshot{}, problem.New(problem.CodeVersionConflict, "")
	}
	if err != nil {
		return runs.Snapshot{}, translate(err)
	}
	event, err := marshalEvent(write, snapshot, sequence, snapshot.LatestEventID, "run.state-changed", map[string]string{"previousState": string(transition.Previous), "state": string(transition.Current)}, now)
	if err != nil {
		return runs.Snapshot{}, err
	}
	if err := s.persistEvent(ctx, tx, write, sequence, snapshot.LatestEventID, event, now); err != nil {
		return runs.Snapshot{}, err
	}
	problemBytes, _ := json.Marshal(snapshot.Problem)
	if snapshot.Problem == nil {
		problemBytes = nil
	}
	if _, err := tx.Exec(ctx, `INSERT INTO agent_workflow.checkpoints(workspace_id,project_id,workflow_id,workflow_version,step_name,state_bytes,problem_bytes) VALUES($1,$2,$3,1,$4,$5,$6)`, write.Scope.WorkspaceID, write.Scope.ProjectID, string(write.RunID)+":g1", fmt.Sprintf("%s-v%d", snapshot.Status, snapshot.Version), raw, problemBytes); err != nil {
		return runs.Snapshot{}, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO agent_control.run_progress(workspace_id,project_id,run_id,state,entered_at,progress_at,stuck_at) VALUES($1,$2,$3,$4,$5,$5,NULL) ON CONFLICT(workspace_id,project_id,run_id) DO UPDATE SET state=EXCLUDED.state,entered_at=EXCLUDED.entered_at,progress_at=EXCLUDED.progress_at,stuck_at=NULL`, write.Scope.WorkspaceID, write.Scope.ProjectID, write.RunID, snapshot.Status, now); err != nil {
		return runs.Snapshot{}, err
	}
	return snapshot, nil
}
func (s *Store) controlEvent(ctx context.Context, tx pgx.Tx, write interrupts.Write, snapshot runs.Snapshot, eventType string, now time.Time) error {
	var sequence uint64
	if err := tx.QueryRow(ctx, `UPDATE agent_control.agent_runs SET next_event_sequence=next_event_sequence+1,updated_at=$4 WHERE workspace_id=$1 AND project_id=$2 AND run_id=$3 RETURNING next_event_sequence-1`, write.Scope.WorkspaceID, write.Scope.ProjectID, write.RunID, now).Scan(&sequence); err != nil {
		return err
	}
	id := fmt.Sprintf("%s:control:%d", write.RunID, sequence)
	wireEventType, err := wireTypeForControlEvent(eventType)
	if err != nil {
		return err
	}
	event, err := marshalEvent(write, snapshot, sequence, id, wireEventType, map[string]string{"controlType": eventType, "state": string(snapshot.Status)}, now)
	if err != nil {
		return err
	}
	return s.persistEvent(ctx, tx, write, sequence, id, event, now)
}
func (s *Store) persistEvent(ctx context.Context, tx pgx.Tx, write interrupts.Write, sequence uint64, id string, event []byte, now time.Time) error {
	if err := events.ValidateEnvelope(event, events.DefaultBounds(), id, string(write.RunID), sequence); err != nil {
		return fmt.Errorf("validate interrupt event: %w", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO agent_events.agent_events(workspace_id,project_id,run_id,sequence,event_id,event_bytes,created_at) VALUES($1,$2,$3,$4,$5,$6,$7)`, write.Scope.WorkspaceID, write.Scope.ProjectID, write.RunID, sequence, id, event, now); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `INSERT INTO agent_events.outbox(workspace_id,project_id,outbox_id,run_id,event_sequence,topic,payload,available_at) VALUES($1,$2,$3,$4,$5,'agent.public-events',$6,$7)`, write.Scope.WorkspaceID, write.Scope.ProjectID, id, write.RunID, sequence, event, now)
	return err
}

func wireTypeForControlEvent(eventType string) (string, error) {
	switch eventType {
	case "approval.decided", "run.cancellation-requested":
		return "run.state-changed", nil
	case "run.stuck":
		return "run.problem-recorded", nil
	default:
		return "", fmt.Errorf("unsupported control event type %q", eventType)
	}
}

func marshalEvent(write interrupts.Write, snapshot runs.Snapshot, sequence uint64, id, eventType string, payload map[string]string, now time.Time) ([]byte, error) {
	switch eventType {
	case "run.created", "run.state-changed", "run.input-requested", "run.approval-requested", "run.artifact-available", "run.problem-recorded":
	default:
		return nil, fmt.Errorf("unsupported agent event type %q", eventType)
	}
	envelope := map[string]any{
		"kind":                 "AgentEvent",
		"eventId":              id,
		"runId":                write.RunID,
		"workspaceId":          write.Scope.WorkspaceID,
		"projectId":            write.Scope.ProjectID,
		"sequence":             sequence,
		"eventType":            eventType,
		"occurredAt":           contractTimestamp(now),
		"subject":              map[string]string{"subjectType": "system", "subjectId": "agent-service"},
		"traceContext":         map[string]string{"traceparent": write.Traceparent},
		"contractBomReference": snapshot.ContractBOM,
	}
	if len(payload) != 0 {
		envelope["payload"] = payload
	}
	event, err := json.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("marshal interrupt event: %w", err)
	}
	return event, nil
}

func contractTimestamp(value time.Time) string {
	return value.UTC().Truncate(time.Millisecond).Format("2006-01-02T15:04:05.000Z")
}

func decodeSnapshot(raw []byte, version uint64) (runs.Snapshot, error) {
	var value runs.Snapshot
	if err := json.Unmarshal(raw, &value); err != nil {
		return runs.Snapshot{}, err
	}
	value.Version = version
	return value, nil
}
func clone(value []byte) json.RawMessage { return append(json.RawMessage(nil), value...) }
func interruptsProblem(code problem.Code, detail string) problem.Details {
	value := problem.New(code, "")
	value.Detail = detail
	return value
}
func translate(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return problem.New(problem.CodeResourceNotFound, "")
	}
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) && postgresError.Code == "23505" {
		return problem.New(problem.CodeIdempotencyConflict, "")
	}
	text := err.Error()
	if contains(text, "canonical digest") || contains(text, "version bound differs") {
		return problem.New(problem.CodeIdempotencyConflict, "")
	}
	if contains(text, "stale version") {
		return problem.New(problem.CodeVersionConflict, "")
	}
	return err
}
func contains(value, fragment string) bool {
	for i := 0; i+len(fragment) <= len(value); i++ {
		if value[i:i+len(fragment)] == fragment {
			return true
		}
	}
	return false
}

var _ interrupts.Repository = (*Store)(nil)
