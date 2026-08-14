// Package postgres persists model-gateway evidence without provider payloads.
package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ancyloce/anvilkit-agent-service/internal/modelgateway"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
)

type InvocationRecorder struct{ database *pgxpool.Pool }

func NewInvocationRecorder(database *pgxpool.Pool) (*InvocationRecorder, error) {
	if database == nil {
		return nil, fmt.Errorf("provider invocation database is required")
	}
	return &InvocationRecorder{database: database}, nil
}

func (r *InvocationRecorder) BeforeDisclosure(ctx context.Context, value modelgateway.InvocationRecord) error {
	classes, err := json.Marshal(value.DisclosedDataClasses)
	if err != nil {
		return fmt.Errorf("marshal disclosed data classes: %w", err)
	}
	policy, err := json.Marshal(value.PolicySnapshot)
	if err != nil {
		return fmt.Errorf("marshal provider policy snapshot: %w", err)
	}
	tx, err := r.database.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return fmt.Errorf("begin provider invocation evidence: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `INSERT INTO agent_control.provider_policy_snapshots(workspace_id,project_id,policy_version,policy_digest,policy_snapshot) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING`, value.WorkspaceID, value.ProjectID, value.PolicyVersion, value.PolicyDigest, policy); err != nil {
		return fmt.Errorf("persist immutable provider policy: %w", err)
	}
	var pinnedDigest string
	if err := tx.QueryRow(ctx, `SELECT policy_digest FROM agent_control.provider_policy_snapshots WHERE workspace_id=$1 AND project_id=$2 AND policy_version=$3`, value.WorkspaceID, value.ProjectID, value.PolicyVersion).Scan(&pinnedDigest); err != nil {
		return fmt.Errorf("read immutable provider policy: %w", err)
	}
	if pinnedDigest != value.PolicyDigest {
		return fmt.Errorf("provider policy version is already pinned to different content")
	}
	_, err = tx.Exec(ctx, `INSERT INTO agent_workflow.provider_invocations(workspace_id,project_id,run_id,invocation_id,physical_attempt_ids,registry_snapshot_digest,policy_version,policy_digest,policy_snapshot,provider,model_version,region,disclosed_data_classes,started_at) VALUES($1,$2,$3,$4,'[]'::jsonb,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, value.WorkspaceID, value.ProjectID, value.RunID, value.InvocationID, value.RegistrySnapshotDigest, value.PolicyVersion, value.PolicyDigest, policy, value.Provider, value.ModelVersion, value.Region, classes, value.StartedAt)
	if err != nil {
		return fmt.Errorf("persist provider invocation before disclosure: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit provider invocation evidence: %w", err)
	}
	return nil
}

func (r *InvocationRecorder) BeforeAttempt(ctx context.Context, value modelgateway.InvocationRecord) error {
	attempts, err := json.Marshal(value.PhysicalAttempts)
	if err != nil {
		return fmt.Errorf("marshal physical attempts: %w", err)
	}
	result, err := r.database.Exec(ctx, `UPDATE agent_workflow.provider_invocations SET physical_attempt_ids=$1 WHERE workspace_id=$2 AND project_id=$3 AND invocation_id=$4`, attempts, value.WorkspaceID, value.ProjectID, value.InvocationID)
	if err != nil {
		return fmt.Errorf("persist physical attempt before disclosure: %w", err)
	}
	if result.RowsAffected() != 1 {
		return fmt.Errorf("provider invocation identity missing before physical attempt")
	}
	return nil
}

func (r *InvocationRecorder) Complete(ctx context.Context, value modelgateway.InvocationRecord) error {
	attempts, err := json.Marshal(value.PhysicalAttempts)
	if err != nil {
		return fmt.Errorf("marshal physical attempts: %w", err)
	}
	var encodedProblem []byte
	if value.Problem != nil {
		encodedProblem, err = json.Marshal(value.Problem)
		if err != nil {
			return fmt.Errorf("marshal provider problem: %w", err)
		}
	}
	result, err := r.database.Exec(ctx, `UPDATE agent_workflow.provider_invocations SET physical_attempt_ids=$1,completed_at=$2,input_tokens=$3,output_tokens=$4,cost_micros=$5,output_digest=NULLIF($6,''),problem=$7 WHERE workspace_id=$8 AND project_id=$9 AND invocation_id=$10`, attempts, value.CompletedAt, value.InputTokens, value.OutputTokens, value.CostMicros, value.OutputDigest, nullableJSON(encodedProblem), value.WorkspaceID, value.ProjectID, value.InvocationID)
	if err != nil {
		return fmt.Errorf("complete provider invocation: %w", err)
	}
	if result.RowsAffected() != 1 {
		return fmt.Errorf("provider invocation identity missing at completion")
	}
	return nil
}

// Get reconstructs immutable invocation evidence for historical eligibility
// replay after process replacement.
func (r *InvocationRecorder) Get(ctx context.Context, workspaceID, projectID, invocationID string) (modelgateway.InvocationRecord, error) {
	if workspaceID == "" || projectID == "" || invocationID == "" {
		return modelgateway.InvocationRecord{}, fmt.Errorf("scoped invocation identity is required")
	}
	var value modelgateway.InvocationRecord
	var attempts, classes, policy, encodedProblem []byte
	var outputDigest *string
	err := r.database.QueryRow(ctx, `SELECT invocation_id,run_id,workspace_id,project_id,physical_attempt_ids,registry_snapshot_digest,policy_version,policy_digest,policy_snapshot,provider,model_version,region,disclosed_data_classes,started_at,completed_at,input_tokens,output_tokens,cost_micros,output_digest,problem FROM agent_workflow.provider_invocations WHERE workspace_id=$1 AND project_id=$2 AND invocation_id=$3`, workspaceID, projectID, invocationID).Scan(&value.InvocationID, &value.RunID, &value.WorkspaceID, &value.ProjectID, &attempts, &value.RegistrySnapshotDigest, &value.PolicyVersion, &value.PolicyDigest, &policy, &value.Provider, &value.ModelVersion, &value.Region, &classes, &value.StartedAt, &value.CompletedAt, &value.InputTokens, &value.OutputTokens, &value.CostMicros, &outputDigest, &encodedProblem)
	if err != nil {
		return modelgateway.InvocationRecord{}, fmt.Errorf("load provider invocation evidence: %w", err)
	}
	if err := json.Unmarshal(attempts, &value.PhysicalAttempts); err != nil {
		return modelgateway.InvocationRecord{}, fmt.Errorf("decode provider physical attempts: %w", err)
	}
	if err := json.Unmarshal(classes, &value.DisclosedDataClasses); err != nil {
		return modelgateway.InvocationRecord{}, fmt.Errorf("decode provider data classes: %w", err)
	}
	if err := json.Unmarshal(policy, &value.PolicySnapshot); err != nil {
		return modelgateway.InvocationRecord{}, fmt.Errorf("decode provider policy snapshot: %w", err)
	}
	if outputDigest != nil {
		value.OutputDigest = *outputDigest
	}
	if len(encodedProblem) > 0 {
		var details problem.Details
		if err := json.Unmarshal(encodedProblem, &details); err != nil {
			return modelgateway.InvocationRecord{}, fmt.Errorf("decode provider problem: %w", err)
		}
		value.Problem = &details
	}
	return value, nil
}

type ContinuationStore struct {
	database               *pgxpool.Pool
	workspaceID, projectID string
}

func NewContinuationStore(database *pgxpool.Pool, workspaceID, projectID string) (*ContinuationStore, error) {
	if database == nil || workspaceID == "" || projectID == "" {
		return nil, fmt.Errorf("scoped continuation database is required")
	}
	return &ContinuationStore{database: database, workspaceID: workspaceID, projectID: projectID}, nil
}

func (s *ContinuationStore) Put(ctx context.Context, id string, value modelgateway.Continuation) error {
	expires, err := time.Parse("2006-01-02T15:04:05.000Z", value.ExpiresAt)
	if err != nil {
		return fmt.Errorf("parse continuation expiry: %w", err)
	}
	_, err = s.database.Exec(ctx, `INSERT INTO agent_workflow.provider_continuations(workspace_id,project_id,continuation_id,api_version,kind,encrypted_binding,key_reference,provider,expires_at,restart_policy,binding_digest) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT(workspace_id,project_id,continuation_id) DO UPDATE SET encrypted_binding=EXCLUDED.encrypted_binding,key_reference=EXCLUDED.key_reference,provider=EXCLUDED.provider,expires_at=EXCLUDED.expires_at,restart_policy=EXCLUDED.restart_policy,binding_digest=EXCLUDED.binding_digest,updated_at=transaction_timestamp()`, s.workspaceID, s.projectID, id, value.APIVersion, value.Kind, value.EncryptedBinding, value.KeyReference, value.Provider, expires, value.RestartPolicy, value.BindingDigest)
	if err != nil {
		return fmt.Errorf("persist encrypted continuation: %w", err)
	}
	return nil
}

func (s *ContinuationStore) Get(ctx context.Context, id string) (modelgateway.Continuation, bool, error) {
	var value modelgateway.Continuation
	var expires time.Time
	err := s.database.QueryRow(ctx, `SELECT api_version,kind,encrypted_binding,key_reference,provider,expires_at,restart_policy,binding_digest FROM agent_workflow.provider_continuations WHERE workspace_id=$1 AND project_id=$2 AND continuation_id=$3`, s.workspaceID, s.projectID, id).Scan(&value.APIVersion, &value.Kind, &value.EncryptedBinding, &value.KeyReference, &value.Provider, &expires, &value.RestartPolicy, &value.BindingDigest)
	if err == pgx.ErrNoRows {
		return modelgateway.Continuation{}, false, nil
	}
	if err != nil {
		return modelgateway.Continuation{}, false, fmt.Errorf("load encrypted continuation: %w", err)
	}
	value.ExpiresAt = expires.UTC().Truncate(time.Millisecond).Format("2006-01-02T15:04:05.000Z")
	return value, true, nil
}

func (s *ContinuationStore) Delete(ctx context.Context, id string) error {
	_, err := s.database.Exec(ctx, `DELETE FROM agent_workflow.provider_continuations WHERE workspace_id=$1 AND project_id=$2 AND continuation_id=$3`, s.workspaceID, s.projectID, id)
	if err != nil {
		return fmt.Errorf("delete encrypted continuation: %w", err)
	}
	return nil
}

type SnapshotStore struct{ database *pgxpool.Pool }

func NewSnapshotStore(database *pgxpool.Pool) (*SnapshotStore, error) {
	if database == nil {
		return nil, fmt.Errorf("provider snapshot database is required")
	}
	return &SnapshotStore{database: database}, nil
}

func (s *SnapshotStore) Put(ctx context.Context, workspaceID, projectID string, value modelgateway.Snapshot) error {
	if workspaceID == "" || projectID == "" || value.Digest == "" {
		return fmt.Errorf("provider snapshot scope and digest are required")
	}
	registry, err := modelgateway.NewRegistry(value)
	if err != nil {
		return fmt.Errorf("validate provider snapshot: %w", err)
	}
	canonical := registry.Current()
	if canonical.Digest != value.Digest {
		return fmt.Errorf("provider snapshot digest does not match canonical content")
	}
	raw, err := json.Marshal(canonical)
	if err != nil {
		return fmt.Errorf("marshal provider snapshot: %w", err)
	}
	result, err := s.database.Exec(ctx, `INSERT INTO agent_control.provider_registry_snapshots(workspace_id,project_id,snapshot_digest,snapshot_version,snapshot) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING`, workspaceID, projectID, value.Digest, value.Version, raw)
	if err != nil {
		return fmt.Errorf("persist provider snapshot: %w", err)
	}
	if result.RowsAffected() == 0 {
		var existing []byte
		if err := s.database.QueryRow(ctx, `SELECT snapshot FROM agent_control.provider_registry_snapshots WHERE workspace_id=$1 AND project_id=$2 AND snapshot_digest=$3`, workspaceID, projectID, value.Digest).Scan(&existing); err != nil {
			return fmt.Errorf("read provider snapshot conflict: %w", err)
		}
		var stored modelgateway.Snapshot
		if err := json.Unmarshal(existing, &stored); err != nil {
			return fmt.Errorf("decode provider snapshot conflict: %w", err)
		}
		storedRegistry, err := modelgateway.NewRegistry(stored)
		if err != nil || storedRegistry.Current().Digest != value.Digest || stored.Version != value.Version {
			return fmt.Errorf("provider snapshot digest conflict")
		}
	}
	return nil
}

func nullableJSON(value []byte) any {
	if len(value) == 0 {
		return nil
	}
	return value
}

var _ modelgateway.Recorder = (*InvocationRecorder)(nil)
var _ modelgateway.ContinuationStore = (*ContinuationStore)(nil)
