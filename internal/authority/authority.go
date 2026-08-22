// Package authority owns the single current-authority observation the whole
// Agent runtime reads. Run creation, Manager turns, the Tool Guard,
// delegation, retry, approval, and commit all resolve authority through this
// one port and one value type, so no boundary can act on a stale or private
// view of who is allowed to do what.
package authority

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
)

// Scope is the bounded identity an authority read is made for.
type Scope struct {
	WorkspaceID string
	ProjectID   string
	ActorID     string
}

func (s Scope) valid() bool {
	return s.WorkspaceID != "" && s.ProjectID != "" && s.ActorID != ""
}

// Grants is the dispatch authority currently granted to the actor. It is the
// only input the Tool Guard accepts beside the run's original intent.
type Grants struct {
	AllowedTools []string
	// AllowedCapabilities is the capability set the actor currently holds.
	// The Tool Guard authorizes the capability the signed ToolDefinition
	// names, not only the tool identity.
	AllowedCapabilities     []string
	AllowedEffects          []string
	MaximumRisk             string
	DataClasses             []string
	ApprovalDecisionVersion uint64
}

func (g Grants) clone() Grants {
	return Grants{
		AllowedTools:            append([]string(nil), g.AllowedTools...),
		AllowedCapabilities:     append([]string(nil), g.AllowedCapabilities...),
		AllowedEffects:          append([]string(nil), g.AllowedEffects...),
		MaximumRisk:             g.MaximumRisk,
		DataClasses:             append([]string(nil), g.DataClasses...),
		ApprovalDecisionVersion: g.ApprovalDecisionVersion,
	}
}

// ActorAuthority is what the scope's subject register binds to one actor
// personally: the capabilities that actor holds and the data classifications
// it is cleared for.
//
// It is deliberately separate from Grants. Grants is dispatch authority bound
// to the scope as a whole — what any run in this workspace and project may
// direct a tool to do — and every actor in the scope reads the same value.
// That is the right shape for dispatch and the wrong shape for a decision that
// answers for one person: if the right to destroy an artifact lived in Grants,
// admitting a single custodian would hand that right to every actor in the
// workspace, and only the admitted role would still be standing between them
// and the artifact. Operations that answer for one person's authority read
// this instead.
//
// An actor with no admitted subject record, or one the register no longer
// admits, has no actor authority at all.
type ActorAuthority struct {
	// Capabilities are the named operations this actor may perform. They are
	// spelled under their operation's own prefix, so a capability granted for
	// one operation can never satisfy another.
	Capabilities []string
	// DataClasses are the registered classifications this actor is cleared
	// for.
	DataClasses []string
}

// HasCapability reports whether the actor personally holds the named
// capability. Boundaries ask for the capability their exact operation needs
// rather than reading the whole set, so a grant of one can never be mistaken
// for a grant of another.
func (a ActorAuthority) HasCapability(name string) bool {
	if name == "" {
		return false
	}
	for _, granted := range a.Capabilities {
		if granted == name {
			return true
		}
	}
	return false
}

// Clears reports whether any classification the actor holds reaches the one
// required.
func (a ActorAuthority) Clears(classification string) bool {
	needed := ClassificationRank(classification)
	if needed == 0 {
		return false
	}
	for _, held := range a.DataClasses {
		if ClassificationRank(held) >= needed {
			return true
		}
	}
	return false
}

// Clearance is the highest registered classification the actor holds, or the
// empty string when it holds none.
func (a ActorAuthority) Clearance() string {
	clearance, rank := "", 0
	for _, held := range a.DataClasses {
		if candidate := ClassificationRank(held); candidate > rank {
			clearance, rank = held, candidate
		}
	}
	return clearance
}

func (a ActorAuthority) clone() ActorAuthority {
	return ActorAuthority{
		Capabilities: append([]string(nil), a.Capabilities...),
		DataClasses:  append([]string(nil), a.DataClasses...),
	}
}

// ClassificationRank orders the governed data-class registry from least to
// most sensitive. It is the one ranking the whole runtime reads: a clearance
// compared one way here and another way there would be two different rules
// wearing one name. An unregistered classification ranks zero and therefore
// never satisfies a requirement — a clearance the governed vocabulary does not
// name is not a clearance.
func ClassificationRank(classification string) int {
	switch classification {
	case "public":
		return 1
	case "internal":
		return 2
	case "confidential":
		return 3
	case "restricted":
		return 4
	default:
		return 0
	}
}

// Current is one authority observation: the governance material in force now
// plus the activation and grant state that decides whether the run may take
// its next step. Callers must re-read it immediately before every model
// disclosure and every external effect; a stored copy is evidence of a past
// decision, never authority for the next one.
type Current struct {
	Definition  json.RawMessage
	ContractBOM json.RawMessage
	Policy      json.RawMessage
	Budget      json.RawMessage

	WorkspaceActive  bool
	ActorActive      bool
	PermissionActive bool
	PolicyActive     bool

	// ActorRole is the role the scope's subject register admits this actor
	// under. It is authority-owned: it comes from the durable subject record,
	// never from a claim the caller presents, so a privileged operation can
	// require a role without trusting the request that asks for it. An actor
	// with no admitted subject record has no role.
	ActorRole string

	// ActorGrants is what the subject register binds to this actor
	// personally. Grants below is the scope's dispatch authority; the two are
	// never interchangeable.
	ActorGrants ActorAuthority

	Grants Grants

	// RevokedTargets and RevokedApprovals are the identity-specific revocation
	// axes: authority over one target or one accepted approval can be
	// withdrawn without deactivating the whole scope. Boundaries that act on a
	// specific target or approval must consult them on every re-read.
	RevokedTargets   []string
	RevokedApprovals []string
}

// Active reports whether every activation axis still permits execution.
func (c Current) Active() bool {
	return c.WorkspaceActive && c.ActorActive && c.PermissionActive && c.PolicyActive
}

// MaterialComplete reports whether every pinned governance document is
// present. Incomplete material is never treated as permissive.
func (c Current) MaterialComplete() bool {
	return len(c.Definition) != 0 && len(c.ContractBOM) != 0 && len(c.Policy) != 0 && len(c.Budget) != 0
}

// RoleOperator is the role a subject must hold in the scope's subject
// register to recover a run whose governed effect is durably escalated.
// Operator recovery decides an effect that may already exist at the domain
// owner, so it is a distinct role from the actor that runs an agent and the
// reviewer that approves one.
const RoleOperator = "agent-operator"

// RoleArtifactCustodian is the role a subject must hold in the scope's subject
// register to change an artifact's custody: to place or lift the legal hold
// that decides whether it may be destroyed, and to destroy it. Producing an
// artifact and deciding that it may cease to exist are different authorities,
// so they are different roles: an actor that runs agents and creates artifacts
// all day holds no power over whether any of them survives.
const RoleArtifactCustodian = "agent-artifact-custodian"

// HasRole reports whether the observation's admitted actor role is exactly the
// named one. A revoked actor has no role for this purpose: an inactive
// observation never satisfies a role requirement.
func (c Current) HasRole(role string) bool {
	return role != "" && c.ActorRole == role && c.ActorActive
}

// TargetRevoked reports whether authority over the named target has been
// withdrawn in this scope.
func (c Current) TargetRevoked(targetID string) bool {
	for _, revoked := range c.RevokedTargets {
		if revoked == targetID {
			return true
		}
	}
	return false
}

// ApprovalRevoked reports whether the named accepted approval has been
// withdrawn in this scope. A revoked approval can never authorize a commit.
func (c Current) ApprovalRevoked(requestID string) bool {
	for _, revoked := range c.RevokedApprovals {
		if revoked == requestID {
			return true
		}
	}
	return false
}

// Clone returns an independent copy so a caller can never mutate the source's
// material through a returned observation.
func (c Current) Clone() Current {
	return Current{
		Definition:       append(json.RawMessage(nil), c.Definition...),
		ContractBOM:      append(json.RawMessage(nil), c.ContractBOM...),
		Policy:           append(json.RawMessage(nil), c.Policy...),
		Budget:           append(json.RawMessage(nil), c.Budget...),
		WorkspaceActive:  c.WorkspaceActive,
		ActorActive:      c.ActorActive,
		PermissionActive: c.PermissionActive,
		PolicyActive:     c.PolicyActive,
		ActorRole:        c.ActorRole,
		ActorGrants:      c.ActorGrants.clone(),
		Grants:           c.Grants.clone(),
		RevokedTargets:   append([]string(nil), c.RevokedTargets...),
		RevokedApprovals: append([]string(nil), c.RevokedApprovals...),
	}
}

// Source is the one current-authority port. Every boundary in the runtime
// reads authority through this interface and no other.
type Source interface {
	Current(context.Context, Scope) (Current, error)
}

// RevocationKind names one axis of authority withdrawal. The durable
// current-authority source applies each kind on the next re-read at every
// boundary; nothing caches past permission.
type RevocationKind string

const (
	RevokeActor      RevocationKind = "actor"
	RevokeRole       RevocationKind = "role"
	RevokeWorkspace  RevocationKind = "workspace"
	RevokeDefinition RevocationKind = "definition"
	RevokePolicy     RevocationKind = "policy"
	RevokeBudget     RevocationKind = "budget"
	RevokeTarget     RevocationKind = "target"
	RevokeApproval   RevocationKind = "approval"
)

// Revocation is one append-only authority withdrawal. Subject names what is
// withdrawn: the actor ID, role name, workspace ID, target ID, or approval
// request ID; material kinds (definition, policy, budget) apply to the whole
// scope and name the material kind itself.
type Revocation struct {
	WorkspaceID  string
	ProjectID    string
	RevocationID string
	Kind         RevocationKind
	Subject      string
	Reason       string
}

// Static serves one configured authority observation and supports explicit
// revocation. Deployments that resolve authority from the durable scoped
// store supply that Source; this implementation is the configured-material
// case and the test topology's source.
type Static struct {
	lock    sync.RWMutex
	value   Current
	revoked bool
}

// NewStatic builds a static source. Material may be empty at construction:
// Current then fails closed instead of reporting permissive authority.
func NewStatic(value Current) *Static {
	return &Static{value: value.Clone()}
}

// Revoke deactivates authority from the next re-read onwards.
func (s *Static) Revoke() {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.revoked = true
}

// Restore reactivates authority. It exists so a deployment can model an
// authority source recovering; it never bypasses a re-read.
func (s *Static) Restore() {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.revoked = false
}

// Replace swaps the served material, modelling governance material changing
// underneath a running run.
func (s *Static) Replace(value Current) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.value = value.Clone()
}

func (s *Static) Current(_ context.Context, scope Scope) (Current, error) {
	if !scope.valid() {
		return Current{}, fmt.Errorf("current authority: workspace, project, and actor identity are required")
	}
	s.lock.RLock()
	defer s.lock.RUnlock()
	if !s.value.MaterialComplete() {
		return Current{}, fmt.Errorf("current authority: pinned governance material is unavailable")
	}
	value := s.value.Clone()
	if s.revoked {
		value.WorkspaceActive, value.ActorActive, value.PermissionActive, value.PolicyActive = false, false, false, false
	}
	// An actor the register no longer admits reads back holding nothing. The
	// durable source does exactly this, and a stand-in that left a withdrawn
	// actor's role and grants legible would be a looser contract than the one
	// it imitates — which is the difference a test would never catch.
	if !value.ActorActive {
		value.ActorRole, value.ActorGrants = "", ActorAuthority{}
	}
	return value, nil
}

var _ Source = (*Static)(nil)
