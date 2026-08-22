// Package postgres is the durable, scoped current-authority source: material
// in force per workspace and project, subject admission per workspace,
// project, and actor, and an append-only revocation ledger. Every boundary
// that re-reads authority observes a revocation on its next read; nothing
// serves a global always-active answer, and nothing an actor was admitted for
// in one project is readable in another.
package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ancyloce/anvilkit-agent-service/internal/authority"
	"github.com/ancyloce/anvilkit-agent-service/internal/securityaudit"
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
	// Generation orders the operator's authority documents. It is the
	// document's own ordinal, not a version the store maintains, because the
	// question it answers is about the document: is the authority this
	// process is holding newer than the authority already in force?
	//
	// Every instance seeds on startup from whatever document it was given,
	// and instances do not all restart at once or from the same content. An
	// unconditional write makes the last instance to start the authority, and
	// the last instance to start is routinely the one holding the oldest
	// document. The generation is what turns that into a refusal.
	Generation uint64
}

// Subject is one actor a project admits, with its role.
//
// The project is part of the identity, not decoration. A workspace holds many
// projects, and an admission made for one of them says nothing about the
// others: an actor admitted as an artifact custodian to do one project's work
// has no standing over another project's artifacts, evidence, or content. The
// register keys on the project so that is true by construction rather than by
// every reader remembering to check.
type Subject struct {
	WorkspaceID string
	ProjectID   string
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

// SeedAudit records one seeding decision in the protected audit before it is
// applied and again after. Seeding writes the authority every later decision
// is answered against, so a change to it is an authorization change: who
// raised the generation, on what document, and what it admitted have to be
// reconstructable afterwards. The protected audit service satisfies this.
type SeedAudit interface {
	PrivilegedMutation(ctx context.Context, record securityaudit.Record, mutation securityaudit.Mutation) error
}

// SeedDecision is the accountable identity behind one seeding.
type SeedDecision struct {
	// Actor is the operator identity the deployment seeds under, Workload the
	// component doing it, Reason the stated cause, Ticket the change record it
	// answers to, and Traceparent the trace of the startup that performed it.
	ActorID, Workload, Reason, Ticket, Traceparent string
}

// Applied reports what one seeding did.
type Applied struct {
	// Generation is the generation in force after the seeding, which is the
	// seed's own when it was applied and the standing one when it was not.
	Generation uint64
	// Superseded is true when the seed was refused because authority at or
	// beyond its generation is already in force. It is not an error: an
	// instance holding an older document has done the right thing by leaving
	// the newer authority alone.
	Superseded bool
	// WithdrawnSubjects counts admissions the seed removed.
	WithdrawnSubjects int
}

// Seed brings the scope's binding and subject register to exactly the state
// one authority document describes, or refuses because a newer document is
// already in force.
//
// Four properties hold together, and each of them is a way authority came
// back before.
//
// It is atomic. The binding and every subject are written in one transaction,
// so a process that dies partway through leaves the register on one side of
// the change or the other, never holding one document's material beside
// another document's admissions.
//
// It is monotonic and compare-and-set. The seed applies only when its
// generation is strictly greater than the one standing, and the update itself
// carries that condition, so two instances racing to seed resolve to the
// newer document rather than to whichever committed last. An older document
// is refused, not applied — which is what stops a stale replica from
// reinstating material an operator has already replaced.
//
// It is exact. Subjects the document does not name are withdrawn in the same
// transaction. An upsert alone can only add, so an admission the operator
// removed from the document survived every reseed; a withdrawal that does not
// withdraw is not one.
//
// And it never touches the revocation ledger, so a recorded revocation
// survives any reseed at any generation.
func (s *Store) Seed(ctx context.Context, binding Binding, subjects []Subject, audit SeedAudit, decision SeedDecision) (Applied, error) {
	if binding.WorkspaceID == "" || binding.ProjectID == "" || len(binding.Definition) == 0 || len(binding.ContractBOM) == 0 || len(binding.Policy) == 0 || len(binding.Budget) == 0 {
		return Applied{}, fmt.Errorf("authority store: a complete scoped binding is required")
	}
	if binding.Generation == 0 || binding.Generation > math.MaxInt64 {
		return Applied{}, fmt.Errorf("authority store: a seed must carry a positive bounded generation")
	}
	if audit == nil {
		return Applied{}, fmt.Errorf("authority store: seeding requires the protected audit")
	}
	for _, subject := range subjects {
		if subject.WorkspaceID != binding.WorkspaceID || subject.ProjectID != binding.ProjectID || subject.ActorID == "" || subject.Role == "" {
			return Applied{}, fmt.Errorf("authority store: a complete subject identity in the seeded scope is required")
		}
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
		return Applied{}, fmt.Errorf("encode authority grants: %w", err)
	}
	// The decision is recorded before the register is touched and its outcome
	// after. A seeding that was authorized and then interrupted is
	// reconstructable, and the compare-and-set below makes re-applying it
	// safe: the same generation is refused as superseded the second time.
	record := securityaudit.Record{
		ID:          seedDecisionIdentity(binding),
		Action:      "authority-seeded",
		Actor:       decision.ActorID,
		Workload:    decision.Workload,
		Reason:      decision.Reason,
		Ticket:      decision.Ticket,
		NewDigest:   seedDigest(binding, subjects, grants),
		Traceparent: decision.Traceparent,
		Scope:       securityaudit.Scope{WorkspaceID: binding.WorkspaceID, ProjectID: binding.ProjectID, ResourceID: "authority-binding"},
	}
	var applied Applied
	var attempted bool
	if err := audit.PrivilegedMutation(ctx, record, func(ctx context.Context) error {
		attempted = true
		result, err := s.apply(ctx, binding, subjects, grants)
		applied = result
		return err
	}); err != nil {
		return Applied{}, err
	}
	if !attempted {
		// This exact seeding is already closed on the protected audit, which
		// is what a restart re-running startup seeding looks like: the same
		// scope, the same generation, the same document. Nothing is applied a
		// second time, and what is reported is the state that stands.
		standing, err := s.generation(ctx, binding.WorkspaceID, binding.ProjectID)
		if err != nil {
			return Applied{}, err
		}
		return Applied{Generation: standing, Superseded: standing >= binding.Generation}, nil
	}
	return applied, nil
}

// generation reads the seed generation currently in force for one scope.
func (s *Store) generation(ctx context.Context, workspaceID, projectID string) (uint64, error) {
	var standing int64
	err := s.database.QueryRow(ctx, `SELECT seed_generation FROM agent_control.authority_bindings WHERE workspace_id=$1 AND project_id=$2`, workspaceID, projectID).Scan(&standing)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("read standing authority generation: %w", err)
	}
	return uint64(standing), nil
}

// apply writes one seeding as a single transaction.
func (s *Store) apply(ctx context.Context, binding Binding, subjects []Subject, grants []byte) (Applied, error) {
	tx, err := s.database.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return Applied{}, fmt.Errorf("open authority seeding transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	now := s.clock().UTC()
	// The insert takes an unseeded scope; the update takes a seeded one only
	// when this document is strictly newer. Both are one statement, so two
	// instances seeding at once cannot both believe they won.
	tag, err := tx.Exec(ctx, `INSERT INTO agent_control.authority_bindings(workspace_id,project_id,definition,contract_bom,policy,budget,grants,seed_generation,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
		ON CONFLICT (workspace_id,project_id) DO UPDATE SET definition=excluded.definition,contract_bom=excluded.contract_bom,policy=excluded.policy,budget=excluded.budget,grants=excluded.grants,seed_generation=excluded.seed_generation,version=agent_control.authority_bindings.version+1,updated_at=excluded.updated_at
		WHERE agent_control.authority_bindings.seed_generation < excluded.seed_generation`,
		binding.WorkspaceID, binding.ProjectID, binding.Definition, binding.ContractBOM, binding.Policy, binding.Budget, grants, int64(binding.Generation), now)
	if err != nil {
		return Applied{}, fmt.Errorf("seed authority binding: %w", err)
	}
	if tag.RowsAffected() == 0 {
		// Authority at or beyond this generation is already in force. Nothing
		// is written — not the binding, not one subject — and the standing
		// generation is reported so the caller can say what it deferred to.
		var standing int64
		if err := tx.QueryRow(ctx, `SELECT seed_generation FROM agent_control.authority_bindings WHERE workspace_id=$1 AND project_id=$2`, binding.WorkspaceID, binding.ProjectID).Scan(&standing); err != nil {
			return Applied{}, fmt.Errorf("read standing authority generation: %w", err)
		}
		if err := tx.Commit(ctx); err != nil {
			return Applied{}, fmt.Errorf("close superseded authority seeding: %w", err)
		}
		return Applied{Generation: uint64(standing), Superseded: true}, nil
	}
	admitted := make([]string, 0, len(subjects))
	for _, subject := range subjects {
		admitted = append(admitted, subject.ActorID)
		if _, err := tx.Exec(ctx, `INSERT INTO agent_control.authority_subjects(workspace_id,project_id,actor_id,role,status,capabilities,data_classes,updated_at) VALUES($1,$2,$3,$4,'active',$5,$6,$7)
			ON CONFLICT (workspace_id,project_id,actor_id) DO UPDATE SET role=excluded.role,status='active',capabilities=excluded.capabilities,data_classes=excluded.data_classes,updated_at=excluded.updated_at`,
			subject.WorkspaceID, subject.ProjectID, subject.ActorID, subject.Role, nonNil(subject.Grants.Capabilities), nonNil(subject.Grants.DataClasses), now); err != nil {
			return Applied{}, fmt.Errorf("seed authority subject: %w", err)
		}
	}
	// Whatever the document no longer names is no longer admitted. This is
	// the half an upsert cannot express, and without it removing a custodian
	// from the authority document left them a custodian.
	//
	// The row is withdrawn rather than removed. An admission that once stood
	// and was taken away is a thing worth being able to see afterwards, and
	// the runtime role holds no privilege to delete from this table at all —
	// which is the right shape for a register whose rows are authority.
	withdrawn, err := tx.Exec(ctx, `UPDATE agent_control.authority_subjects SET status='revoked',capabilities='{}',data_classes='{}',updated_at=$3 WHERE workspace_id=$1 AND project_id=$2 AND status='active' AND actor_id <> ALL($4)`,
		binding.WorkspaceID, binding.ProjectID, now, admitted)
	if err != nil {
		return Applied{}, fmt.Errorf("withdraw authority subjects the seed no longer admits: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Applied{}, fmt.Errorf("commit authority seeding: %w", err)
	}
	return Applied{Generation: binding.Generation, WithdrawnSubjects: int(withdrawn.RowsAffected())}, nil
}

// seedDecisionIdentity is the identity of one seeding decision: the scope and
// the generation being brought into force. Two attempts at the same generation
// are the same decision, so a restart that re-runs seeding resumes the
// recorded one rather than opening a second.
func seedDecisionIdentity(binding Binding) string {
	identity := sha256.Sum256([]byte(binding.WorkspaceID + "\x00" + binding.ProjectID + "\x00" + strconv.FormatUint(binding.Generation, 10)))
	return "authority." + hex.EncodeToString(identity[:16])
}

// seedDigest is the digest of exactly what one seeding admits: the material,
// the dispatch grants, and every subject with the role, capabilities, and
// clearance it is admitted under. The audit record carries it so the recorded
// decision names the authority it established rather than only the moment it
// was established.
func seedDigest(binding Binding, subjects []Subject, grants []byte) string {
	ordered := append([]Subject(nil), subjects...)
	sort.Slice(ordered, func(left, right int) bool { return ordered[left].ActorID < ordered[right].ActorID })
	payload, err := json.Marshal(struct {
		Scope       [2]string
		Generation  uint64
		Definition  json.RawMessage
		ContractBOM json.RawMessage
		Policy      json.RawMessage
		Budget      json.RawMessage
		Grants      json.RawMessage
		Subjects    []Subject
	}{[2]string{binding.WorkspaceID, binding.ProjectID}, binding.Generation, binding.Definition, binding.ContractBOM, binding.Policy, binding.Budget, grants, ordered})
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:])
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
	// The register is read at the project the observation is made for. An
	// admission in a sibling project is another project's decision, and it is
	// not answered here at all: the actor simply has no admitted role,
	// capability, or clearance in this one.
	err = s.database.QueryRow(ctx, `SELECT role,status,capabilities,data_classes FROM agent_control.authority_subjects WHERE workspace_id=$1 AND project_id=$2 AND actor_id=$3`, scope.WorkspaceID, scope.ProjectID, scope.ActorID).
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
