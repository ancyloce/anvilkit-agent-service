// Package auth projects cryptographically verified workload/delegated claims
// into server-owned request authority. Browser-supplied context is unusable.
package auth

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/runs"
)

type Operation string

const (
	OpCreateRun          Operation = "create-run"
	OpListRuns           Operation = "list-runs"
	OpGetRun             Operation = "get-run"
	OpStreamEvents       Operation = "stream-events"
	OpCancel             Operation = "cancel"
	OpRetry              Operation = "retry"
	OpDiscard            Operation = "discard"
	OpRespondInput       Operation = "respond-input"
	OpDecideApproval     Operation = "decide-approval"
	OpIssueAuthorization Operation = "issue-authorization"
	OpAccessArtifact     Operation = "access-artifact"
	// OpResolveEscalation is the operator recovery of a run whose governed
	// effect is durably escalated. It is deliberately its own operation with
	// its own scope: nothing that can create, cancel, review, or retry a run
	// can decide an escalated effect, and nothing that can decide one can do
	// the rest.
	OpResolveEscalation Operation = "resolve-escalation"
	// OpReadEvidence is the disclosure of internal AgentEvidence. Evidence is
	// the high-fidelity internal execution record, so reading it is its own
	// operation under its own scope: nothing that can read, run, review, or
	// recover a run can disclose evidence by virtue of that.
	OpReadEvidence Operation = "read-evidence"
)
const (
	ScopeRead     = "agent:read"
	ScopeWrite    = "agent:write"
	ScopeReviewer = "agent:review"
	ScopeIssuer   = "agent:issue"
	// ScopeOperator is held only by the operator recovery surface.
	ScopeOperator = "agent:operate"
	// ScopeEvidence is held only by a subject authorized to read internal
	// AgentEvidence. It admits the read; the clearance that bounds which
	// classifications the read discloses comes from current authority, never
	// from a claim.
	ScopeEvidence = "agent:evidence"
)

func RequiredScopes(operation Operation) []string {
	switch operation {
	case OpListRuns, OpGetRun, OpStreamEvents, OpAccessArtifact:
		return []string{ScopeRead}
	case OpCreateRun, OpCancel, OpRetry, OpDiscard, OpRespondInput:
		return []string{ScopeWrite}
	case OpDecideApproval:
		return []string{ScopeReviewer}
	case OpIssueAuthorization:
		return []string{ScopeIssuer}
	case OpResolveEscalation:
		return []string{ScopeOperator}
	case OpReadEvidence:
		return []string{ScopeEvidence}
	default:
		return nil
	}
}

type Source string

const (
	SourceWorkload  Source = "workload"
	SourceDelegated Source = "delegated"
	SourceBrowser   Source = "browser"
)

type Claims struct {
	Verified                                                                   bool
	Source                                                                     Source
	Issuer, Audience, Subject, ActorID, WorkspaceID, ProjectID, Purpose, KeyID string
	Scopes                                                                     []string
	ExpiresAt                                                                  time.Time
	NotBefore                                                                  time.Time
}
type Trust interface {
	KeyActive(context.Context, string) (bool, error)
	SubjectActive(context.Context, string) (bool, error)
	DelegationActive(context.Context, string, string) (bool, error)
}
type Clock interface{ Now() time.Time }
type Config struct {
	Issuers          []string
	Audience         string
	MaximumClockSkew time.Duration
}
type Validator struct {
	config Config
	trust  Trust
	clock  Clock
}

func NewValidator(config Config, trust Trust, clock Clock) (*Validator, error) {
	if len(config.Issuers) == 0 || config.Audience == "" || trust == nil || clock == nil || config.MaximumClockSkew < 0 {
		return nil, fmt.Errorf("auth validator configuration is incomplete")
	}
	return &Validator{config: config, trust: trust, clock: clock}, nil
}

func (v *Validator) Authorize(ctx context.Context, claims Claims, operation Operation) (runs.Scope, error) {
	if !claims.Verified || claims.Source == SourceBrowser || (claims.Source != SourceWorkload && claims.Source != SourceDelegated) {
		return runs.Scope{}, authProblem(problem.CodeAuthenticationInvalid)
	}
	if !contains(v.config.Issuers, claims.Issuer) || claims.Audience != v.config.Audience || !boundedClaim(claims.Issuer) || !boundedClaim(claims.Audience) || !boundedClaim(claims.Subject) || !boundedClaim(claims.Purpose) || !boundedClaim(claims.KeyID) || len(claims.Scopes) > 64 {
		return runs.Scope{}, authProblem(problem.CodeAuthenticationInvalid)
	}
	scope := runs.Scope{WorkspaceID: claims.WorkspaceID, ProjectID: claims.ProjectID, ActorID: claims.ActorID}
	if err := scope.Validate(); err != nil {
		return runs.Scope{}, authProblem(problem.CodeAuthenticationInvalid)
	}
	for _, claimScope := range claims.Scopes {
		if !boundedClaim(claimScope) {
			return runs.Scope{}, authProblem(problem.CodeAuthenticationInvalid)
		}
	}
	now := v.clock.Now()
	if now.IsZero() || claims.ExpiresAt.IsZero() || !now.Before(claims.ExpiresAt.Add(v.config.MaximumClockSkew)) || now.Add(v.config.MaximumClockSkew).Before(claims.NotBefore) {
		return runs.Scope{}, authProblem(problem.CodeAuthenticationInvalid)
	}
	active, err := v.trust.KeyActive(ctx, claims.KeyID)
	if err != nil || !active {
		return runs.Scope{}, authProblem(problem.CodeAuthenticationInvalid)
	}
	active, err = v.trust.SubjectActive(ctx, claims.Subject)
	if err != nil || !active {
		return runs.Scope{}, authProblem(problem.CodeAuthorizationDenied)
	}
	if claims.Source == SourceDelegated {
		active, err = v.trust.DelegationActive(ctx, claims.Subject, claims.ActorID)
		if err != nil || !active {
			return runs.Scope{}, authProblem(problem.CodeAuthorizationDenied)
		}
	} else if claims.Subject != claims.ActorID {
		return runs.Scope{}, authProblem(problem.CodeAuthorizationDenied)
	}
	required := RequiredScopes(operation)
	if len(required) == 0 {
		return runs.Scope{}, authProblem(problem.CodeAuthorizationDenied)
	}
	for _, scope := range required {
		if !contains(claims.Scopes, scope) {
			return runs.Scope{}, authProblem(problem.CodeAuthorizationDenied)
		}
	}
	return scope, nil
}

func (v *Validator) Revalidate(ctx context.Context, claims Claims, operation Operation) error {
	_, err := v.Authorize(ctx, claims, operation)
	return err
}
func ProtectedOperations() []Operation {
	values := []Operation{OpCreateRun, OpListRuns, OpGetRun, OpStreamEvents, OpCancel, OpRetry, OpDiscard, OpRespondInput, OpDecideApproval, OpIssueAuthorization, OpAccessArtifact, OpResolveEscalation, OpReadEvidence}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	return values
}
func authProblem(code problem.Code) problem.Details {
	value := problem.New(code, "")
	value.Detail = "request authority could not be verified"
	return value
}
func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func boundedClaim(value string) bool { return len(value) >= 1 && len(value) <= 256 }
