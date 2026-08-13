// Package postgres persists diagnostic tool decisions without untrusted text.
package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ancyloce/anvilkit-agent-service/internal/tools"
)

type Recorder struct{ database *pgxpool.Pool }

func New(database *pgxpool.Pool) (*Recorder, error) {
	if database == nil {
		return nil, fmt.Errorf("tool decision database is required")
	}
	return &Recorder{database: database}, nil
}

func (r *Recorder) Record(ctx context.Context, intent tools.Intent, proposal tools.Proposal, decision tools.Decision) error {
	sum := sha256.Sum256(proposal.Arguments)
	_, err := r.database.Exec(ctx, `INSERT INTO agent_evaluation.tool_decisions(workspace_id,project_id,run_id,actor_id,tool_id,arguments_digest,allowed,code,reason,profile_digest,policy_version,recorded_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, intent.WorkspaceID, intent.ProjectID, intent.RunID, intent.ActorID, proposal.ToolID, "sha256:"+hex.EncodeToString(sum[:]), decision.Allowed, decision.Code, decision.Reason, decision.ProfileDigest, decision.PolicyVersion, decision.RecordedAt)
	if err != nil {
		return fmt.Errorf("persist tool decision: %w", err)
	}
	return nil
}

var _ tools.Recorder = (*Recorder)(nil)

type ProfileStore struct{ database *pgxpool.Pool }

func NewProfileStore(database *pgxpool.Pool) (*ProfileStore, error) {
	if database == nil {
		return nil, fmt.Errorf("tool profile database is required")
	}
	return &ProfileStore{database: database}, nil
}

func (s *ProfileStore) Prepare(ctx context.Context, workspaceID, projectID, runID string, profile tools.Profile) error {
	if workspaceID == "" || projectID == "" || runID == "" || profile.Digest == "" {
		return fmt.Errorf("scoped pinned tool profile is required")
	}
	canonical, err := tools.NewProfile(profile.ID, profile.Version, profile.Policy, profile.Definitions)
	if err != nil || canonical.Digest != profile.Digest {
		return fmt.Errorf("tool profile failed pinned digest validation")
	}
	profile = canonical
	policy, err := json.Marshal(profile.Policy)
	if err != nil {
		return fmt.Errorf("marshal tool profile policy: %w", err)
	}
	definitions, err := json.Marshal(profile.Definitions)
	if err != nil {
		return fmt.Errorf("marshal tool profile definitions: %w", err)
	}
	_, err = s.database.Exec(ctx, `INSERT INTO agent_workflow.run_tool_profiles(workspace_id,project_id,run_id,profile_id,profile_version,profile_digest,policy,definitions) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING`, workspaceID, projectID, runID, profile.ID, profile.Version, profile.Digest, policy, definitions)
	if err != nil {
		return fmt.Errorf("pin run tool profile: %w", err)
	}
	var digest string
	if err := s.database.QueryRow(ctx, `SELECT profile_digest FROM agent_workflow.run_tool_profiles WHERE workspace_id=$1 AND project_id=$2 AND run_id=$3`, workspaceID, projectID, runID).Scan(&digest); err != nil {
		return fmt.Errorf("read pinned run tool profile: %w", err)
	}
	if digest != profile.Digest {
		return fmt.Errorf("run tool profile is already pinned to different evidence")
	}
	return nil
}

func (s *ProfileStore) Get(ctx context.Context, workspaceID, projectID, runID string) (tools.Profile, error) {
	var id, version, digest string
	var policy, definitions []byte
	if err := s.database.QueryRow(ctx, `SELECT profile_id,profile_version,profile_digest,policy,definitions FROM agent_workflow.run_tool_profiles WHERE workspace_id=$1 AND project_id=$2 AND run_id=$3`, workspaceID, projectID, runID).Scan(&id, &version, &digest, &policy, &definitions); err != nil {
		return tools.Profile{}, fmt.Errorf("load pinned run tool profile: %w", err)
	}
	var policyValue tools.PolicyReference
	var definitionValues []tools.Definition
	if err := json.Unmarshal(policy, &policyValue); err != nil {
		return tools.Profile{}, fmt.Errorf("decode pinned tool policy: %w", err)
	}
	if err := json.Unmarshal(definitions, &definitionValues); err != nil {
		return tools.Profile{}, fmt.Errorf("decode pinned tool definitions: %w", err)
	}
	profile, err := tools.NewProfile(tools.ProfileID(id), version, policyValue, definitionValues)
	if err != nil || profile.Digest != digest {
		return tools.Profile{}, fmt.Errorf("pinned run tool profile failed integrity validation")
	}
	return profile, nil
}
