package tools

import (
	"context"
	"fmt"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
)

type Boundary string

const (
	ContextDisclosure     Boundary = "context-disclosure"
	ProviderInvocation    Boundary = "provider-invocation"
	ToolTaskDispatch      Boundary = "tool-task-dispatch"
	WaitResumption        Boundary = "wait-resumption"
	ArtifactAccess        Boundary = "artifact-access"
	AuthorizationIssuance Boundary = "authorization-issuance"
)

func Boundaries() []Boundary {
	return []Boundary{ContextDisclosure, ProviderInvocation, ToolTaskDispatch, WaitResumption, ArtifactAccess, AuthorizationIssuance}
}

type AuthorityState struct{ WorkspaceExists, ActorActive, PermissionActive, ProviderActive, PolicyActive, TrustActive bool }
type AuthoritySource interface {
	Current(context.Context, string, string) (AuthorityState, error)
}
type FreshnessGuard struct{ source AuthoritySource }

func NewFreshnessGuard(source AuthoritySource) (*FreshnessGuard, error) {
	if source == nil {
		return nil, fmt.Errorf("authority source required")
	}
	return &FreshnessGuard{source}, nil
}
func (g *FreshnessGuard) Check(ctx context.Context, boundary Boundary, workspace, actor string) error {
	valid := false
	for _, candidate := range Boundaries() {
		if candidate == boundary {
			valid = true
		}
	}
	if !valid || workspace == "" || actor == "" {
		return problem.New(problem.CodeRequestInvalid, "")
	}
	state, err := g.source.Current(ctx, workspace, actor)
	if err != nil {
		return problem.New(problem.CodeAuthorityStale, "")
	}
	if !state.WorkspaceExists || !state.ActorActive || !state.PermissionActive || !state.ProviderActive || !state.PolicyActive || !state.TrustActive {
		details := problem.New(problem.CodeAuthorityStale, "")
		details.Detail = "current authority revoked at " + string(boundary)
		return details
	}
	return nil
}
