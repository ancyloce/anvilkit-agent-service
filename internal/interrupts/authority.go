package interrupts

import (
	"context"
	"encoding/json"
	"fmt"

	contractschema "github.com/ancyloce/anvilkit-agent-service/contracts/generated/schema"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/runs"
)

type CurrentRunReader interface {
	Current(context.Context, runs.Scope, runs.ID) (runs.Snapshot, error)
}

type CurrentPolicyAuthority interface {
	Current(context.Context, runs.Scope) (runs.Authority, error)
}

// CurrentAuthority enforces decision-time reviewer policy and separation of
// duties using the current run and policy authority. The transport separately
// proves the caller holds the agent:review operation scope.
type CurrentAuthority struct {
	runs     CurrentRunReader
	policies CurrentPolicyAuthority
}

func NewCurrentAuthority(runReader CurrentRunReader, policies CurrentPolicyAuthority) (*CurrentAuthority, error) {
	if runReader == nil || policies == nil {
		return nil, fmt.Errorf("current interrupt authority requires run and policy authority")
	}
	return &CurrentAuthority{runs: runReader, policies: policies}, nil
}

func (a *CurrentAuthority) AuthorizeInput(ctx context.Context, scope runs.Scope, request InputRequest) error {
	snapshot, err := a.runs.Current(ctx, scope, request.RunID)
	if err != nil {
		return fmt.Errorf("resolve run for input authorization: %w", err)
	}
	if snapshot.ActorID == "" || scope.ActorID != snapshot.ActorID {
		return authorityDenied("only the run actor can answer its input request")
	}
	return nil
}

func (a *CurrentAuthority) AuthorizeReviewer(ctx context.Context, scope runs.Scope, request ApprovalRequest, _ DecisionKind) error {
	snapshot, err := a.runs.Current(ctx, scope, request.RunID)
	if err != nil {
		return fmt.Errorf("resolve run for reviewer authorization: %w", err)
	}
	if snapshot.ActorID == "" || scope.ActorID == snapshot.ActorID {
		return authorityDenied("the run actor cannot review its own approval request")
	}
	requestPolicy, err := decodePolicyReference(request.ReviewerPolicy)
	if err != nil {
		return fmt.Errorf("decode stored reviewer policy: %w", err)
	}
	runPolicy, err := decodePolicyReference(snapshot.Policy)
	if err != nil {
		return fmt.Errorf("decode run reviewer policy: %w", err)
	}
	current, err := a.policies.Current(ctx, scope)
	if err != nil {
		return fmt.Errorf("resolve current reviewer policy: %w", err)
	}
	currentPolicy, err := decodePolicyReference(current.Policy)
	if err != nil {
		return fmt.Errorf("decode current reviewer policy: %w", err)
	}
	if requestPolicy != runPolicy || requestPolicy != currentPolicy {
		return authorityDenied("the approval request reviewer policy is not current")
	}
	return nil
}

func (*CurrentAuthority) RetryEligibility(_ context.Context, _ runs.Scope, snapshot runs.Snapshot) (bool, string, error) {
	if snapshot.Status != runs.Failed {
		return false, "", nil
	}
	if snapshot.Problem != nil && (snapshot.Problem.Retryability == "safe-after-backoff" || snapshot.Problem.Retryability == "operator-action") {
		return true, "preparing:authority", nil
	}
	return false, "", nil
}

func decodePolicyReference(raw json.RawMessage) (contractschema.SharedPrimitivesV1PolicyReference, error) {
	var reference contractschema.SharedPrimitivesV1PolicyReference
	if err := json.Unmarshal(raw, &reference); err != nil {
		return contractschema.SharedPrimitivesV1PolicyReference{}, err
	}
	return reference, nil
}

func authorityDenied(detail string) problem.Details {
	value := problem.New(problem.CodeAuthorizationDenied, "")
	value.Detail = detail
	return value
}

var _ Authority = (*CurrentAuthority)(nil)
