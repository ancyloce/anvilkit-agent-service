package interrupts

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/ancyloce/anvilkit-agent-service/internal/authority"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/runs"
)

// The material set a complete run and a complete current-authority
// observation agree on. Every test below changes exactly one document, one
// activation axis, or the target, and proves the boundary fails closed.
var (
	materialDefinition = json.RawMessage(`{"definitionId":"definition.platform.manager","definitionDigest":"sha256:` + string(makeDigest('1')) + `"}`)
	materialBOM        = json.RawMessage(`{"repository":"anvilkit/contracts","bomDigest":"sha256:` + string(makeDigest('2')) + `"}`)
	materialPolicy     = policyReference("policy.reviewers", "v1", 'a')
	materialBudget     = json.RawMessage(`{"kind":"AgentBudget","reservationId":"reservation.material"}`)
)

func materialScope(actor string) runs.Scope {
	return runs.Scope{WorkspaceID: "workspace", ProjectID: "project", ActorID: actor}
}

func materialSnapshot(state runs.State) runs.Snapshot {
	return runs.Snapshot{
		RunID:               "run",
		RootRunID:           "run",
		WorkspaceID:         "workspace",
		ActorID:             "run-actor",
		Domain:              "platform-agent",
		Operation:           "artifact-validation",
		Target:              runs.Target{Type: "page", ID: "page.material", WorkspaceID: "workspace", ProjectID: "project"},
		Definition:          materialDefinition,
		ContractBOM:         materialBOM,
		Policy:              materialPolicy,
		Budget:              materialBudget,
		Status:              state,
		Version:             4,
		ExecutionGeneration: 1,
	}
}

func materialAuthority() authority.Current {
	return authority.Current{
		Definition:       materialDefinition,
		ContractBOM:      materialBOM,
		Policy:           materialPolicy,
		Budget:           materialBudget,
		WorkspaceActive:  true,
		ActorActive:      true,
		PermissionActive: true,
		PolicyActive:     true,
	}
}

func failedSnapshot() runs.Snapshot {
	snapshot := materialSnapshot(runs.Failed)
	failure := problem.New(problem.CodeProviderUnavailable, "")
	failure.Retryability = "safe-after-backoff"
	snapshot.Problem = &failure
	return snapshot
}

// staleMaterial enumerates every way the authority and material set a run was
// admitted under can stop being current between admission and the next
// authorization boundary.
func staleMaterial() []struct {
	name     string
	mutate   func(authority.Current) authority.Current
	scope    runs.Scope
	code     problem.Code
	snapshot *runs.Snapshot
} {
	return []struct {
		name     string
		mutate   func(authority.Current) authority.Current
		scope    runs.Scope
		code     problem.Code
		snapshot *runs.Snapshot
	}{
		{name: "definition replaced", mutate: func(c authority.Current) authority.Current {
			c.Definition = json.RawMessage(`{"definitionId":"definition.platform.manager","definitionDigest":"sha256:` + string(makeDigest('9')) + `"}`)
			return c
		}, code: problem.CodeAuthorityStale},
		{name: "contract bom replaced", mutate: func(c authority.Current) authority.Current {
			c.ContractBOM = json.RawMessage(`{"repository":"anvilkit/contracts","bomDigest":"sha256:` + string(makeDigest('8')) + `"}`)
			return c
		}, code: problem.CodeAuthorityStale},
		{name: "policy replaced", mutate: func(c authority.Current) authority.Current {
			c.Policy = policyReference("policy.reviewers", "v2", 'b')
			return c
		}, code: problem.CodeAuthorityStale},
		{name: "budget replaced", mutate: func(c authority.Current) authority.Current {
			c.Budget = json.RawMessage(`{"kind":"AgentBudget","reservationId":"reservation.replaced"}`)
			return c
		}, code: problem.CodeAuthorityStale},
		{name: "workspace deactivated", mutate: func(c authority.Current) authority.Current {
			c.WorkspaceActive = false
			return c
		}, code: problem.CodeAuthorityStale},
		{name: "actor deactivated", mutate: func(c authority.Current) authority.Current {
			c.ActorActive = false
			return c
		}, code: problem.CodeAuthorityStale},
		{name: "permission revoked", mutate: func(c authority.Current) authority.Current {
			c.PermissionActive = false
			return c
		}, code: problem.CodeAuthorityStale},
		{name: "policy deactivated", mutate: func(c authority.Current) authority.Current {
			c.PolicyActive = false
			return c
		}, code: problem.CodeAuthorityStale},
		{name: "material incomplete", mutate: func(c authority.Current) authority.Current {
			c.Budget = nil
			return c
		}, code: problem.CodeAuthorityStale},
		{name: "target revoked", mutate: func(c authority.Current) authority.Current {
			c.RevokedTargets = []string{"page.material"}
			return c
		}, code: problem.CodeAuthorityStale},
		{name: "target project is not the request scope", mutate: func(c authority.Current) authority.Current { return c },
			scope: runs.Scope{WorkspaceID: "workspace", ProjectID: "other-project", ActorID: "run-actor"}, code: problem.CodeAuthorizationDenied},
		{name: "target workspace is not the request scope", mutate: func(c authority.Current) authority.Current { return c },
			scope: runs.Scope{WorkspaceID: "other-workspace", ProjectID: "project", ActorID: "run-actor"}, code: problem.CodeAuthorizationDenied},
	}
}

func TestInputIsRefusedWhenAnyPartOfTheCurrentMaterialSetIsStale(t *testing.T) {
	for _, test := range staleMaterial() {
		t.Run(test.name, func(t *testing.T) {
			current := test.mutate(materialAuthority())
			gate, err := NewCurrentAuthority(authorityRunReader{snapshot: materialSnapshot(runs.AwaitingInput)}, policyAuthority{authority: current})
			if err != nil {
				t.Fatal(err)
			}
			scope := test.scope
			if scope.ActorID == "" {
				scope = materialScope("run-actor")
			}
			err = gate.AuthorizeInput(context.Background(), scope, InputRequest{RunID: "run"})
			var details problem.Details
			if !errors.As(err, &details) || details.Code != string(test.code) {
				t.Fatalf("input authorization error = %v, want %s", err, test.code)
			}
		})
	}
}

func TestRetryIsRefusedWhenAnyPartOfTheCurrentMaterialSetIsStale(t *testing.T) {
	for _, test := range staleMaterial() {
		t.Run(test.name, func(t *testing.T) {
			current := test.mutate(materialAuthority())
			gate, err := NewCurrentAuthority(authorityRunReader{snapshot: failedSnapshot()}, policyAuthority{authority: current})
			if err != nil {
				t.Fatal(err)
			}
			scope := test.scope
			if scope.ActorID == "" {
				scope = materialScope("run-actor")
			}
			eligible, checkpoint, err := gate.RetryEligibility(context.Background(), scope, failedSnapshot())
			var details problem.Details
			if !errors.As(err, &details) || details.Code != string(test.code) {
				t.Fatalf("retry eligibility error = %v, want %s", err, test.code)
			}
			if eligible || checkpoint != "" {
				t.Fatalf("stale authority produced an eligible retry: eligible=%t checkpoint=%q", eligible, checkpoint)
			}
		})
	}
}

func TestCurrentMaterialSetAdmitsInputRetryAndResume(t *testing.T) {
	gate, err := NewCurrentAuthority(authorityRunReader{snapshot: failedSnapshot()}, policyAuthority{authority: materialAuthority()})
	if err != nil {
		t.Fatal(err)
	}
	scope := materialScope("run-actor")
	if err := gate.AuthorizeInput(context.Background(), scope, InputRequest{RunID: "run"}); err != nil {
		t.Fatalf("current material denied the run actor's input: %v", err)
	}
	eligible, checkpoint, err := gate.RetryEligibility(context.Background(), scope, failedSnapshot())
	if err != nil || !eligible || checkpoint != "preparing:authority" {
		t.Fatalf("retry eligibility = (%t, %q, %v)", eligible, checkpoint, err)
	}
	if err := gate.AuthorizeResume(context.Background(), scope, failedSnapshot()); err != nil {
		t.Fatalf("current material denied a recorded retry resume: %v", err)
	}
}

func TestResumeOfARecordedRetryIsRefusedWhenAuthorityWasRevokedAfterRecording(t *testing.T) {
	revoked := materialAuthority()
	revoked.PermissionActive = false
	gate, err := NewCurrentAuthority(authorityRunReader{snapshot: materialSnapshot(runs.Preparing)}, policyAuthority{authority: revoked})
	if err != nil {
		t.Fatal(err)
	}
	err = gate.AuthorizeResume(context.Background(), materialScope("run-actor"), materialSnapshot(runs.Preparing))
	var details problem.Details
	if !errors.As(err, &details) || details.Code != string(problem.CodeAuthorityStale) {
		t.Fatalf("resume authorization error = %v, want %s", err, problem.CodeAuthorityStale)
	}
}

// The target axis is identity-specific: revoking authority over the run's
// exact target denies the resume of a recorded retry even while every other
// axis stays active — the resume would restart execution against it.
func TestResumeIsRefusedWhenTheRunTargetIsRevoked(t *testing.T) {
	revoked := materialAuthority()
	revoked.RevokedTargets = []string{"page.material"}
	gate, err := NewCurrentAuthority(authorityRunReader{snapshot: materialSnapshot(runs.Preparing)}, policyAuthority{authority: revoked})
	if err != nil {
		t.Fatal(err)
	}
	err = gate.AuthorizeResume(context.Background(), materialScope("run-actor"), materialSnapshot(runs.Preparing))
	var details problem.Details
	if !errors.As(err, &details) || details.Code != string(problem.CodeAuthorityStale) {
		t.Fatalf("resume with a revoked target = %v", err)
	}
	// A different target's revocation does not deny this run.
	other := materialAuthority()
	other.RevokedTargets = []string{"page.other"}
	gate, err = NewCurrentAuthority(authorityRunReader{snapshot: materialSnapshot(runs.Preparing)}, policyAuthority{authority: other})
	if err != nil {
		t.Fatal(err)
	}
	if err := gate.AuthorizeResume(context.Background(), materialScope("run-actor"), materialSnapshot(runs.Preparing)); err != nil {
		t.Fatalf("an unrelated target revocation denied the resume: %v", err)
	}
}

// An approval decision acts on one specific target and one specific request:
// either being individually revoked denies the reviewer decision.
func TestApprovalDecisionIsDeniedForRevokedTargetOrRevokedRequest(t *testing.T) {
	request := ApprovalRequest{ID: "approval.1", RunID: "run", ActionDigest: "sha256:" + string(makeDigest('7')), ReviewerPolicy: materialPolicy}
	cases := map[string]struct {
		mutate func(authority.Current) authority.Current
		code   problem.Code
	}{
		"target revoked": {mutate: func(c authority.Current) authority.Current {
			c.RevokedTargets = []string{"page.material"}
			return c
		}, code: problem.CodeAuthorityStale},
		"approval revoked": {mutate: func(c authority.Current) authority.Current {
			c.RevokedApprovals = []string{"approval.1"}
			return c
		}, code: problem.CodeAuthorizationDenied},
	}
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			gate, err := NewCurrentAuthority(authorityRunReader{snapshot: materialSnapshot(runs.AwaitingApproval)}, policyAuthority{authority: test.mutate(materialAuthority())})
			if err != nil {
				t.Fatal(err)
			}
			err = gate.AuthorizeReviewer(context.Background(), materialScope("reviewer"), request, DecisionApprove)
			var details problem.Details
			if !errors.As(err, &details) || details.Code != string(test.code) {
				t.Fatalf("reviewer decision = %v, want %s", err, test.code)
			}
		})
	}
	// The unrevoked baseline admits the decision.
	gate, err := NewCurrentAuthority(authorityRunReader{snapshot: materialSnapshot(runs.AwaitingApproval)}, policyAuthority{authority: materialAuthority()})
	if err != nil {
		t.Fatal(err)
	}
	if err := gate.AuthorizeReviewer(context.Background(), materialScope("reviewer"), request, DecisionApprove); err != nil {
		t.Fatalf("baseline reviewer decision denied: %v", err)
	}
}

func TestRetryEligibilityFailsClosedWhenAuthorityCannotBeResolved(t *testing.T) {
	gate, err := NewCurrentAuthority(authorityRunReader{snapshot: failedSnapshot()}, policyAuthority{err: errors.New("authority unavailable")})
	if err != nil {
		t.Fatal(err)
	}
	eligible, _, err := gate.RetryEligibility(context.Background(), materialScope("run-actor"), failedSnapshot())
	if err == nil || eligible {
		t.Fatalf("retry was declared eligible without current authority: eligible=%t err=%v", eligible, err)
	}
}
