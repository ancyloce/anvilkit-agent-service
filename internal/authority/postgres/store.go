// Package postgres is the durable, scoped current-authority source: material
// in force per workspace and project, subject activation per workspace and
// actor, and an append-only revocation ledger. Every boundary that re-reads
// authority observes a revocation on its next read; nothing serves a global
// always-active answer.
package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ancyloce/anvilkit-agent-service/internal/authority"
)

type Store struct {
	database *pgxpool.Pool
	clock    func() time.Time
}

func New(database *pgxpool.Pool, clock func() time.Time) (*Store, error) {
	if database == nil || clock == nil {
		return nil, fmt.Errorf("authority store: a database and clock are required")
	}
	return &Store{database: database, clock: clock}, nil
}

var _ authority.Source = (*Store)(nil)

// Binding is the governance material one workspace/project scope pins.
type Binding struct {
	WorkspaceID string
	ProjectID   string
	Definition  json.RawMessage
	ContractBOM json.RawMessage
	Policy      json.RawMessage
	Budget      json.RawMessage
	Grants      authority.Grants
}

// Subject is one actor the workspace admits, with its role.
type Subject struct {
	WorkspaceID string
	ActorID     string
	Role        string
	// Grants is what the register binds to this actor personally, beside the
	// role it admits them under.
	Grants authority.ActorAuthority
}

// grantsWire is the stored shape of the dispatch grants.
type grantsWire struct {
	AllowedTools            []string `json:"allowedTools"`
	AllowedCapabilities     []string `json:"allowedCapabilities"`
	AllowedEffects          []string `json:"allowedEffects"`
	MaximumRisk             string   `json:"maximumRisk"`
	DataClasses             []string `json:"dataClasses"`
	ApprovalDecisionVersion uint64   `json:"approvalDecisionVersion"`
}

// Seed upserts the scope's binding and subjects. Seeding is deployment
// configuration, not a runtime mutation path: it never touches the revocation
// ledger, so a recorded revocation survives any reseed.
func (s *Store) Seed(ctx context.Context, binding Binding, subjects []Subject) error {
	if binding.WorkspaceID == "" || binding.ProjectID == "" || len(binding.Definition) == 0 || len(binding.ContractBOM) == 0 || len(binding.Policy) == 0 || len(binding.Budget) == 0 {
		return fmt.Errorf("authority store: a complete scoped binding is required")
	}
	grants, err := json.Marshal(grantsWire{
		AllowedTools:            binding.Grants.AllowedTools,
		AllowedCapabilities:     binding.Grants.AllowedCapabilities,
		AllowedEffects:          binding.Grants.AllowedEffects,
		MaximumRisk:             binding.Grants.MaximumRisk,
		DataClasses:             binding.Grants.DataClasses,
		ApprovalDecisionVersion: binding.Grants.ApprovalDecisionVersion,
	})
	if err != nil {
		return fmt.Errorf("encode authority grants: %w", err)
	}
	if _, err := s.database.Exec(ctx, `INSERT INTO agent_control.authority_bindings(workspace_id,project_id,definition,contract_bom,policy,budget,grants,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)
		ON CONFLICT (workspace_id,project_id) DO UPDATE SET definition=excluded.definition,contract_bom=excluded.contract_bom,policy=excluded.policy,budget=excluded.budget,grants=excluded.grants,version=agent_control.authority_bindings.version+1,updated_at=excluded.updated_at`,
		binding.WorkspaceID, binding.ProjectID, binding.Definition, binding.ContractBOM, binding.Policy, binding.Budget, grants, s.clock().UTC()); err != nil {
		return fmt.Errorf("seed authority binding: %w", err)
	}
	for _, subject := range subjects {
		if subject.WorkspaceID == "" || subject.ActorID == "" || subject.Role == "" {
			return fmt.Errorf("authority store: a complete subject identity is required")
		}
		if _, err := s.database.Exec(ctx, `INSERT INTO agent_control.authority_subjects(workspace_id,actor_id,role,status,capabilities,data_classes,updated_at) VALUES($1,$2,$3,'active',$4,$5,$6)
			ON CONFLICT (workspace_id,actor_id) DO UPDATE SET role=excluded.role,capabilities=excluded.capabilities,data_classes=excluded.data_classes,updated_at=excluded.updated_at`,
			subject.WorkspaceID, subject.ActorID, subject.Role, nonNil(subject.Grants.Capabilities), nonNil(subject.Grants.DataClasses), s.clock().UTC()); err != nil {
			return fmt.Errorf("seed authority subject: %w", err)
		}
	}
	return nil
}

// Revoke appends one authority withdrawal. The ledger is append-only by
// database trigger; a revocation is never edited or deleted.
func (s *Store) Revoke(ctx context.Context, revocation authority.Revocation) error {
	switch revocation.Kind {
	case authority.RevokeActor, authority.RevokeRole, authority.RevokeWorkspace, authority.RevokeDefinition, authority.RevokePolicy, authority.RevokeBudget, authority.RevokeTarget, authority.RevokeApproval:
	default:
		return fmt.Errorf("authority store: %q is not a revocation kind", revocation.Kind)
	}
	if revocation.WorkspaceID == "" || revocation.ProjectID == "" || revocation.RevocationID == "" || revocation.Subject == "" {
		return fmt.Errorf("authority store: a complete revocation identity is required")
	}
	if _, err := s.database.Exec(ctx, `INSERT INTO agent_control.authority_revocations(workspace_id,project_id,revocation_id,kind,subject,reason,recorded_at) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING`,
		revocation.WorkspaceID, revocation.ProjectID, revocation.RevocationID, revocation.Kind, revocation.Subject, revocation.Reason, s.clock().UTC()); err != nil {
		return fmt.Errorf("record authority revocation: %w", err)
	}
	return nil
}

// Current answers one scoped authority observation. A scope with no seeded
// binding has no authority at all; a missing or revoked subject deactivates
// the actor axis; every recorded revocation is applied on this read.
func (s *Store) Current(ctx context.Context, scope authority.Scope) (authority.Current, error) {
	if scope.WorkspaceID == "" || scope.ProjectID == "" || scope.ActorID == "" {
		return authority.Current{}, fmt.Errorf("current authority: workspace, project, and actor identity are required")
	}
	var definition, contractBOM, policy, budget, grantsRaw []byte
	err := s.database.QueryRow(ctx, `SELECT definition,contract_bom,policy,budget,grants FROM agent_control.authority_bindings WHERE workspace_id=$1 AND project_id=$2`, scope.WorkspaceID, scope.ProjectID).
		Scan(&definition, &contractBOM, &policy, &budget, &grantsRaw)
	if errors.Is(err, pgx.ErrNoRows) {
		return authority.Current{}, fmt.Errorf("current authority: no governance material is bound to this scope")
	}
	if err != nil {
		return authority.Current{}, fmt.Errorf("read authority binding: %w", err)
	}
	var grants grantsWire
	if err := json.Unmarshal(grantsRaw, &grants); err != nil {
		return authority.Current{}, fmt.Errorf("decode authority grants: %w", err)
	}
	current := authority.Current{
		Definition:       json.RawMessage(definition),
		ContractBOM:      json.RawMessage(contractBOM),
		Policy:           json.RawMessage(policy),
		Budget:           json.RawMessage(budget),
		WorkspaceActive:  true,
		ActorActive:      true,
		PermissionActive: true,
		PolicyActive:     true,
		Grants: authority.Grants{
			AllowedTools:            grants.AllowedTools,
			AllowedCapabilities:     grants.AllowedCapabilities,
			AllowedEffects:          grants.AllowedEffects,
			MaximumRisk:             grants.MaximumRisk,
			DataClasses:             grants.DataClasses,
			ApprovalDecisionVersion: grants.ApprovalDecisionVersion,
		},
	}
	var role, status string
	var capabilities, dataClasses []string
	err = s.database.QueryRow(ctx, `SELECT role,status,capabilities,data_classes FROM agent_control.authority_subjects WHERE workspace_id=$1 AND actor_id=$2`, scope.WorkspaceID, scope.ActorID).
		Scan(&role, &status, &capabilities, &dataClasses)
	if errors.Is(err, pgx.ErrNoRows) {
		current.ActorActive = false
	} else if err != nil {
		return authority.Current{}, fmt.Errorf("read authority subject: %w", err)
	} else if status != "active" {
		current.ActorActive = false
	} else {
		// The admitted role and the actor's own capabilities and clearance are
		// authority-owned material: they are read from the scope's subject
		// register, so an operation that requires them checks the register
		// rather than anything the caller presented.
		current.ActorRole = role
		current.ActorGrants = authority.ActorAuthority{Capabilities: capabilities, DataClasses: dataClasses}
	}
	// Workspace, actor, and role withdrawals apply workspace-wide; material,
	// target, and approval withdrawals apply to the project they were recorded
	// under.
	rows, err := s.database.Query(ctx, `SELECT kind,subject FROM agent_control.authority_revocations WHERE workspace_id=$1 AND (project_id=$2 OR kind IN ('workspace','actor','role'))`, scope.WorkspaceID, scope.ProjectID)
	if err != nil {
		return authority.Current{}, fmt.Errorf("read authority revocations: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var kind, subject string
		if err := rows.Scan(&kind, &subject); err != nil {
			return authority.Current{}, fmt.Errorf("scan authority revocation: %w", err)
		}
		switch authority.RevocationKind(kind) {
		case authority.RevokeWorkspace:
			if subject == scope.WorkspaceID {
				current.WorkspaceActive = false
			}
		case authority.RevokeActor:
			if subject == scope.ActorID {
				current.ActorActive = false
			}
		case authority.RevokeRole:
			if role != "" && subject == role {
				current.ActorActive = false
			}
		case authority.RevokePolicy:
			current.PolicyActive = false
		case authority.RevokeDefinition:
			// Withdrawn material is absent material: MaterialComplete fails
			// and every boundary treats the authority as no longer permitting
			// the run.
			current.Definition = nil
		case authority.RevokeBudget:
			current.Budget = nil
		case authority.RevokeTarget:
			current.RevokedTargets = append(current.RevokedTargets, subject)
		case authority.RevokeApproval:
			current.RevokedApprovals = append(current.RevokedApprovals, subject)
		}
	}
	if err := rows.Err(); err != nil {
		return authority.Current{}, fmt.Errorf("read authority revocations: %w", err)
	}
	// An actor the register no longer admits holds nothing. Clearing this here
	// rather than relying on every consumer to check activation first is what
	// makes a withdrawn actor's capabilities and clearance unreadable instead
	// of merely unusable.
	if !current.ActorActive {
		current.ActorRole, current.ActorGrants = "", authority.ActorAuthority{}
	}
	return current, nil
}

// nonNil renders a nil slice as an empty array so a column that does not admit
// null never receives one.
func nonNil(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

// PinnedBOMDigest answers the Contract BOM digest the scope's current binding
// pins. The Contract Runtime verifies a request's claimed BOM identity against
// this authority-owned value, never against the caller's claim alone.
func (s *Store) PinnedBOMDigest(ctx context.Context, workspaceID, projectID string) (string, error) {
	if workspaceID == "" || projectID == "" {
		return "", fmt.Errorf("authority store: workspace and project identity are required")
	}
	var contractBOM []byte
	err := s.database.QueryRow(ctx, `SELECT contract_bom FROM agent_control.authority_bindings WHERE workspace_id=$1 AND project_id=$2`, workspaceID, projectID).Scan(&contractBOM)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", fmt.Errorf("authority store: no governance material is bound to this scope")
	}
	if err != nil {
		return "", fmt.Errorf("read authority binding: %w", err)
	}
	var reference struct {
		BOMDigest string `json:"bomDigest"`
	}
	if err := json.Unmarshal(contractBOM, &reference); err != nil {
		return "", fmt.Errorf("decode pinned contract BOM reference: %w", err)
	}
	if reference.BOMDigest == "" {
		return "", fmt.Errorf("authority store: the pinned contract BOM reference carries no digest")
	}
	return reference.BOMDigest, nil
}
