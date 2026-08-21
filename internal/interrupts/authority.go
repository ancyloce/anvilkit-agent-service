package interrupts

import (
	"context"
	"encoding/json"
	"fmt"

	contractschema "github.com/ancyloce/anvilkit-agent-service/contracts/generated/schema"
	"github.com/ancyloce/anvilkit-agent-service/internal/authority"
	"github.com/ancyloce/anvilkit-agent-service/internal/canonical"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/runs"
)

type CurrentRunReader interface {
	Current(context.Context, runs.Scope, runs.ID) (runs.Snapshot, error)
}

// CurrentPolicyAuthority is the shared current-authority port. Approval is a
// guarded boundary like any other: the reviewer decision is refused unless
// current authority is active and its reviewer policy is still the one the
// run and the request were pinned to.
type CurrentPolicyAuthority = authority.Source

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
	// Accepting an input is a disclosure into a run that will keep executing,
	// so it is a fresh authorization decision over the complete material set,
	// not a continuation of the decision the run was created under.
	return a.requireCurrentMaterial(ctx, scope, snapshot)
}

// requireCurrentMaterial proves that the whole authority and material set the
// run was admitted under is still in force: the activation axes, the pinned
// agent definition, the Contract BOM, the policy (which is also the reviewer
// policy every recorded approval on this run was decided under), the pinned
// agent budget, and the target the run may act on. Callers run it before
// accepting an input and before an explicit retry is persisted or resumed, so
// a stale set stops the run before its execution generation is incremented
// and before any workflow is started.
func (a *CurrentAuthority) requireCurrentMaterial(ctx context.Context, scope runs.Scope, snapshot runs.Snapshot) error {
	if snapshot.ActorID == "" || snapshot.WorkspaceID == "" {
		return authorityDenied("the run does not carry a resolvable actor and workspace")
	}
	if scope.WorkspaceID != snapshot.WorkspaceID || scope.WorkspaceID != snapshot.Target.WorkspaceID || scope.ProjectID != snapshot.Target.ProjectID {
		return authorityDenied("the request scope is not the target this run is bound to")
	}
	current, err := a.policies.Current(ctx, scope.AuthorityScope())
	if err != nil {
		return fmt.Errorf("resolve current authority: %w", err)
	}
	if !current.MaterialComplete() {
		return staleAuthority("current authority material is unavailable")
	}
	if !current.Active() {
		return staleAuthority("current authority no longer permits this run")
	}
	for _, material := range []struct {
		label           string
		current, pinned json.RawMessage
	}{
		{"agent definition", current.Definition, snapshot.Definition},
		{"Contract BOM", current.ContractBOM, snapshot.ContractBOM},
		{"policy", current.Policy, snapshot.Policy},
		{"agent budget", current.Budget, snapshot.Budget},
	} {
		if !canonicalEqual(material.current, material.pinned) {
			return staleAuthority("the pinned " + material.label + " is no longer current")
		}
	}
	// The target axis is identity-specific: authority over this run's exact
	// target can be withdrawn without deactivating the scope, and a response,
	// retry, or resume against a revoked target restarts execution against it.
	if current.TargetRevoked(snapshot.Target.ID) {
		return staleAuthority("authority over the run's target is revoked")
	}
	return nil
}

// canonicalEqual compares two governance documents by canonical digest, so
// insignificant encoding differences never read as a material change and a
// document that cannot be canonicalized never reads as equal.
func canonicalEqual(left, right json.RawMessage) bool {
	leftDigest, leftErr := canonical.Digest(left)
	rightDigest, rightErr := canonical.Digest(right)
	return leftErr == nil && rightErr == nil && leftDigest == rightDigest
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
	current, err := a.policies.Current(ctx, scope.AuthorityScope())
	if err != nil {
		return fmt.Errorf("resolve current reviewer policy: %w", err)
	}
	if !current.Active() || !current.MaterialComplete() {
		return staleAuthority("current authority no longer permits an approval decision")
	}
	currentPolicy, err := decodePolicyReference(current.Policy)
	if err != nil {
		return fmt.Errorf("decode current reviewer policy: %w", err)
	}
	if requestPolicy != runPolicy || requestPolicy != currentPolicy {
		return authorityDenied("the approval request reviewer policy is not current")
	}
	// An approval decision acts on one specific target and one specific
	// request: either being individually revoked denies the decision even
	// while the scope stays active.
	if current.TargetRevoked(snapshot.Target.ID) {
		return staleAuthority("authority over the run's target is revoked")
	}
	if current.ApprovalRevoked(string(request.ID)) {
		return authorityDenied("the approval request has been revoked by current authority")
	}
	return nil
}

// AuthorizeResume revalidates the complete current authority and material set
// before a recorded retry is resumed. The retry may have been recorded under
// an authority that has since been revoked or replaced, and the resume starts
// real execution, so it is authorized in its own right.
func (a *CurrentAuthority) AuthorizeResume(ctx context.Context, scope runs.Scope, snapshot runs.Snapshot) error {
	return a.requireCurrentMaterial(ctx, scope, snapshot)
}

// RetryEligibility answers whether an explicit retry may be persisted and
// resumed. Eligibility is not a property of the recorded failure alone: the
// retry restarts execution under the authority in force now, so the complete
// current material set is revalidated first. A stale set returns the typed
// authority problem instead of an ineligible answer, which stops the caller
// before the run generation is incremented or a workflow is started.
func (a *CurrentAuthority) RetryEligibility(ctx context.Context, scope runs.Scope, snapshot runs.Snapshot) (bool, string, error) {
	if snapshot.Status != runs.Failed {
		return false, "", nil
	}
	if snapshot.Problem == nil || (snapshot.Problem.Retryability != "safe-after-backoff" && snapshot.Problem.Retryability != "operator-action") {
		return false, "", nil
	}
	if err := a.requireCurrentMaterial(ctx, scope, snapshot); err != nil {
		return false, "", err
	}
	return true, "preparing:authority", nil
}

func decodePolicyReference(raw json.RawMessage) (contractschema.SharedPrimitivesPolicyReference, error) {
	var reference contractschema.SharedPrimitivesPolicyReference
	if err := json.Unmarshal(raw, &reference); err != nil {
		return contractschema.SharedPrimitivesPolicyReference{}, err
	}
	return reference, nil
}

func staleAuthority(detail string) problem.Details {
	value := problem.New(problem.CodeAuthorityStale, "")
	value.Detail = detail
	return value
}

func authorityDenied(detail string) problem.Details {
	value := problem.New(problem.CodeAuthorizationDenied, "")
	value.Detail = detail
	return value
}

var _ Authority = (*CurrentAuthority)(nil)
