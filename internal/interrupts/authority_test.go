package interrupts

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/authority"
	"github.com/ancyloce/anvilkit-agent-service/internal/journal"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/runs"
)

type authorityRunReader struct {
	snapshot runs.Snapshot
	err      error
}

func (r authorityRunReader) Current(context.Context, runs.Scope, runs.ID) (runs.Snapshot, error) {
	return r.snapshot, r.err
}

type policyAuthority struct {
	authority runs.Authority
	err       error
}

func (a policyAuthority) Current(context.Context, authority.Scope) (authority.Current, error) {
	return a.authority, a.err
}

// currentReviewerAuthority is a complete, active current-authority
// observation carrying the reviewer policy in force.
func currentReviewerAuthority(policy json.RawMessage) authority.Current {
	return authority.Current{
		Definition:       json.RawMessage(`{"definitionId":"definition.test"}`),
		ContractBOM:      json.RawMessage(`{"bom":"test"}`),
		Policy:           policy,
		Budget:           json.RawMessage(`{"budget":"test"}`),
		WorkspaceActive:  true,
		ActorActive:      true,
		PermissionActive: true,
		PolicyActive:     true,
	}
}

func TestCurrentAuthorityEnforcesSeparationAndCurrentReviewerPolicy(t *testing.T) {
	policy := policyReference("policy.reviewers", "v1", 'a')
	otherPolicy := policyReference("policy.reviewers", "v2", 'b')
	baseSnapshot := runs.Snapshot{RunID: "run", ActorID: "run-actor", Policy: policy, Status: runs.AwaitingApproval}
	baseRequest := ApprovalRequest{RunID: "run", ReviewerPolicy: policy}
	tests := []struct {
		name          string
		reviewer      string
		requestPolicy json.RawMessage
		runPolicy     json.RawMessage
		currentPolicy json.RawMessage
		wantDenied    bool
	}{
		{name: "eligible reviewer", reviewer: "reviewer", requestPolicy: policy, runPolicy: policy, currentPolicy: policy},
		{name: "self approval", reviewer: "run-actor", requestPolicy: policy, runPolicy: policy, currentPolicy: policy, wantDenied: true},
		{name: "request policy injection", reviewer: "reviewer", requestPolicy: otherPolicy, runPolicy: policy, currentPolicy: policy, wantDenied: true},
		{name: "run policy mismatch", reviewer: "reviewer", requestPolicy: policy, runPolicy: otherPolicy, currentPolicy: policy, wantDenied: true},
		{name: "policy revoked or replaced", reviewer: "reviewer", requestPolicy: policy, runPolicy: policy, currentPolicy: otherPolicy, wantDenied: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := baseSnapshot
			snapshot.Policy = test.runPolicy
			request := baseRequest
			request.ReviewerPolicy = test.requestPolicy
			authority, err := NewCurrentAuthority(authorityRunReader{snapshot: snapshot}, policyAuthority{authority: currentReviewerAuthority(test.currentPolicy)})
			if err != nil {
				t.Fatal(err)
			}
			err = authority.AuthorizeReviewer(context.Background(), runs.Scope{WorkspaceID: "workspace", ProjectID: "project", ActorID: test.reviewer}, request, DecisionApprove)
			var details problem.Details
			denied := errors.As(err, &details) && details.Code == string(problem.CodeAuthorizationDenied)
			if test.wantDenied != denied || !test.wantDenied && err != nil {
				t.Fatalf("authorization error = %v, denied=%t", err, denied)
			}
		})
	}
}

func TestCurrentAuthorityFailsClosedWhenAuthorityCannotBeResolved(t *testing.T) {
	policy := policyReference("policy.reviewers", "v1", 'a')
	authority, err := NewCurrentAuthority(authorityRunReader{snapshot: runs.Snapshot{RunID: "run", ActorID: "run-actor", Policy: policy}}, policyAuthority{err: errors.New("policy unavailable")})
	if err != nil {
		t.Fatal(err)
	}
	if err := authority.AuthorizeReviewer(context.Background(), runs.Scope{ActorID: "reviewer"}, ApprovalRequest{RunID: "run", ReviewerPolicy: policy}, DecisionApprove); err == nil {
		t.Fatal("review was authorized without current policy authority")
	}
}

func TestCurrentAuthorityRestrictsInputToRunActor(t *testing.T) {
	authority, err := NewCurrentAuthority(authorityRunReader{snapshot: materialSnapshot(runs.AwaitingInput)}, policyAuthority{authority: materialAuthority()})
	if err != nil {
		t.Fatal(err)
	}
	request := InputRequest{RunID: "run"}
	if err := authority.AuthorizeInput(context.Background(), materialScope("run-actor"), request); err != nil {
		t.Fatalf("run actor was denied: %v", err)
	}
	err = authority.AuthorizeInput(context.Background(), materialScope("different-actor"), request)
	var details problem.Details
	if !errors.As(err, &details) || details.Code != string(problem.CodeAuthorizationDenied) {
		t.Fatalf("different actor was not denied: %v", err)
	}
}

func TestSelfApprovalIsDeniedBeforeDecisionMutation(t *testing.T) {
	policy := policyReference("policy.reviewers", "v1", 'a')
	runScope := scope()
	runScope.ActorID = "run-actor"
	runSnapshot := snapshot("run", runs.AwaitingReview, 1)
	runSnapshot.ActorID = "run-actor"
	runSnapshot.Policy = policy
	repository := NewMemoryRepository()
	if err := repository.Seed(runScope, runSnapshot); err != nil {
		t.Fatal(err)
	}
	authority, err := NewCurrentAuthority(repository, policyAuthority{authority: runs.Authority{Policy: policy}})
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(repository, BoundSchemaValidator{}, authority, &testRuntime{}, &testLeases{}, &testReconciler{clear: true}, &testReservation{}, journal.NewMemoryStore(), &testClock{now: testNow}, &testIDs{}, Limits{ChildDepth: 2, ChildFanout: 2})
	if err != nil {
		t.Fatal(err)
	}
	openWrite := write("run", 1, "open")
	openWrite.Scope = runScope
	request, opened, err := service.RequestApproval(context.Background(), openWrite, OpenApproval{ActionDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Effects: json.RawMessage(`{"effect":"apply"}`), ExpectedCost: json.RawMessage(`{"amount":"1"}`), ReviewerPolicy: policy, ExpiresAt: testNow.Add(time.Hour), ResumeCheckpoint: "review"})
	if err != nil {
		t.Fatal(err)
	}
	decisionWrite := write("run", opened.Snapshot.Version, "decide")
	decisionWrite.Scope = runScope
	_, err = service.DecideApproval(context.Background(), decisionWrite, ApprovalDecisionCommand{RequestID: request.ID, RequestVersion: request.Version, Decision: DecisionApprove})
	var details problem.Details
	if !errors.As(err, &details) || details.Code != string(problem.CodeAuthorizationDenied) {
		t.Fatalf("self-approval error = %v", err)
	}
	current, currentErr := repository.Current(context.Background(), runScope, "run")
	stored, requestErr := repository.Approval(context.Background(), runScope, "run", request.ID)
	if currentErr != nil || requestErr != nil || current.Status != runs.AwaitingApproval || current.Version != opened.Snapshot.Version || stored.Decision != nil {
		t.Fatalf("self-approval mutated state: run=%#v request=%#v currentErr=%v requestErr=%v", current, stored, currentErr, requestErr)
	}
}

func policyReference(id, version string, digestByte byte) json.RawMessage {
	return json.RawMessage(`{"policyId":"` + id + `","version":"` + version + `","digest":"sha256:` + string(makeDigest(digestByte)) + `"}`)
}

func makeDigest(value byte) []byte {
	result := make([]byte, 64)
	for index := range result {
		result[index] = value
	}
	return result
}
