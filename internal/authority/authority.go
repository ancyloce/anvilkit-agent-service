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

	Grants Grants
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
		Grants:           c.Grants.clone(),
	}
}

// Source is the one current-authority port. Every boundary in the runtime
// reads authority through this interface and no other.
type Source interface {
	Current(context.Context, Scope) (Current, error)
}

// Static serves one configured authority observation and supports explicit
// revocation. Deployments that resolve authority from a file or an external
// authority service supply their own Source; this implementation is the
// configured-material case and the controlled topology's source.
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
	return value, nil
}

var _ Source = (*Static)(nil)
