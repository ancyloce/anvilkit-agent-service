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
	_, err = r.database.Exec(ctx, `INSERT INTO agent_workflow.provider_invocations(workspace_id,project_id,run_id,invocation_id,physical_attempt_ids,registry_snapshot_digest,policy_version,provider,model_version,region,disclosed_data_classes,started_at) VALUES($1,$2,$3,$4,'[]'::jsonb,$5,$6,$7,$8,$9,$10,$11)`, value.WorkspaceID, value.ProjectID, value.RunID, value.InvocationID, value.RegistrySnapshotDigest, value.PolicyVersion, value.Provider, value.ModelVersion, value.Region, classes, value.StartedAt)
	if err != nil {
		return fmt.Errorf("persist provider invocation before disclosure: %w", err)
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
	_, err = s.database.Exec(ctx, `INSERT INTO agent_workflow.provider_continuations(workspace_id,project_id,continuation_id,api_version,kind,encrypted_binding,provider,expires_at,restart_policy,binding_digest) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT(workspace_id,project_id,continuation_id) DO UPDATE SET encrypted_binding=EXCLUDED.encrypted_binding,provider=EXCLUDED.provider,expires_at=EXCLUDED.expires_at,restart_policy=EXCLUDED.restart_policy,binding_digest=EXCLUDED.binding_digest,updated_at=transaction_timestamp()`, s.workspaceID, s.projectID, id, value.APIVersion, value.Kind, value.EncryptedBinding, value.Provider, expires, value.RestartPolicy, value.BindingDigest)
	if err != nil {
		return fmt.Errorf("persist encrypted continuation: %w", err)
	}
	return nil
}

func (s *ContinuationStore) Get(ctx context.Context, id string) (modelgateway.Continuation, bool, error) {
	var value modelgateway.Continuation
	var expires time.Time
	err := s.database.QueryRow(ctx, `SELECT api_version,kind,encrypted_binding,provider,expires_at,restart_policy,binding_digest FROM agent_workflow.provider_continuations WHERE workspace_id=$1 AND project_id=$2 AND continuation_id=$3`, s.workspaceID, s.projectID, id).Scan(&value.APIVersion, &value.Kind, &value.EncryptedBinding, &value.Provider, &expires, &value.RestartPolicy, &value.BindingDigest)
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
