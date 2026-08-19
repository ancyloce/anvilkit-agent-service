package interrupts

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/journal"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/runs"
)

var testNow = time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)

type testClock struct{ now time.Time }

func (c *testClock) Now() time.Time { return c.now }

type testIDs struct {
	lock         sync.Mutex
	request, run int
}

func (i *testIDs) NewRequestID() (RequestID, error) {
	i.lock.Lock()
	defer i.lock.Unlock()
	i.request++
	return RequestID(fmt.Sprintf("request-%d", i.request)), nil
}
func (i *testIDs) NewRunID() (runs.ID, error) {
	i.lock.Lock()
	defer i.lock.Unlock()
	i.run++
	return runs.ID(fmt.Sprintf("child-%d", i.run)), nil
}

type testAuthority struct {
	denyInput, denyReview bool
	retry                 bool
	checkpoint            string
}

func (a *testAuthority) AuthorizeInput(context.Context, runs.Scope, InputRequest) error {
	if a.denyInput {
		return problem.New(problem.CodeAuthorizationDenied, "")
	}
	return nil
}
func (a *testAuthority) AuthorizeReviewer(context.Context, runs.Scope, ApprovalRequest, DecisionKind) error {
	if a.denyReview {
		return problem.New(problem.CodeAuthorizationDenied, "")
	}
	return nil
}
func (a *testAuthority) RetryEligibility(_ context.Context, _ runs.Scope, snapshot runs.Snapshot) (bool, string, error) {
	return a.retry && snapshot.Status == runs.Failed, a.checkpoint, nil
}

type signal struct {
	workflow, topic, key string
	payload              json.RawMessage
}
type testRuntime struct {
	lock      sync.Mutex
	signals   []signal
	children  []Child
	waits     []string
	stopped   []runs.ID
	resumed   []string
	stopErr   error
	resumeErr error
}

func (r *testRuntime) StartChild(_ context.Context, child Child) error {
	r.lock.Lock()
	defer r.lock.Unlock()
	r.children = append(r.children, child)
	return nil
}
func (r *testRuntime) OpenWait(_ context.Context, _ runs.Scope, id, topic string, _ time.Duration) error {
	r.lock.Lock()
	defer r.lock.Unlock()
	r.waits = append(r.waits, id+":"+topic)
	return nil
}

func (r *testRuntime) Signal(_ context.Context, workflow, topic string, payload json.RawMessage, key string) error {
	r.lock.Lock()
	defer r.lock.Unlock()
	r.signals = append(r.signals, signal{workflow, topic, key, append(json.RawMessage(nil), payload...)})
	return nil
}
func (r *testRuntime) StopRun(_ context.Context, _ runs.Scope, id runs.ID, _ uint64) error {
	r.lock.Lock()
	defer r.lock.Unlock()
	if r.stopErr != nil {
		return r.stopErr
	}
	r.stopped = append(r.stopped, id)
	return nil
}
func (r *testRuntime) ResumeRun(_ context.Context, _ runs.Scope, snapshot runs.Snapshot, checkpoint, resumeKey string) error {
	r.lock.Lock()
	defer r.lock.Unlock()
	if r.resumeErr != nil {
		return r.resumeErr
	}
	key := fmt.Sprintf("%s:%d:%s:%s", snapshot.RunID, snapshot.ExecutionGeneration, checkpoint, resumeKey)
	for _, existing := range r.resumed {
		if existing == key {
			return nil
		}
	}
	r.resumed = append(r.resumed, key)
	return nil
}

type testLeases struct {
	lock    sync.Mutex
	revoked []runs.ID
}

func (l *testLeases) RevokeRun(_ context.Context, _ runs.Scope, id runs.ID) error {
	l.lock.Lock()
	defer l.lock.Unlock()
	l.revoked = append(l.revoked, id)
	return nil
}

type testReconciler struct {
	clear         bool
	authoritative *runs.State
	err           error
}

func (r *testReconciler) Reconcile(context.Context, runs.Scope, runs.ID, bool) (bool, *runs.State, error) {
	return r.clear, r.authoritative, r.err
}

type testReservation struct {
	lock  sync.Mutex
	calls []string
	err   error
}

func (r *testReservation) ReserveChild(_ context.Context, request ChildBudgetRequest) error {
	r.lock.Lock()
	defer r.lock.Unlock()
	r.calls = append(r.calls, fmt.Sprintf("%s:%s:%s", request.Write.RunID, request.ChildRunID, request.Mode))
	return r.err
}

func scope() runs.Scope {
	return runs.Scope{WorkspaceID: "workspace", ProjectID: "project", ActorID: "actor"}
}
func snapshot(id runs.ID, state runs.State, version uint64) runs.Snapshot {
	return runs.Snapshot{RunID: id, RootRunID: id, WorkspaceID: "workspace", ActorID: "actor", Status: state, Version: version, ExecutionGeneration: 1, ContractBOM: json.RawMessage(`{"bom":"v1"}`), Policy: json.RawMessage(`{"dataPolicy":"restricted"}`), Budget: json.RawMessage(`{"reservation":"root"}`), CreatedAt: testNow.Add(-time.Hour), UpdatedAt: testNow.Add(-time.Minute)}
}
func write(id runs.ID, version uint64, key string) Write {
	return Write{Scope: scope(), RunID: id, ExpectedVersion: version, IdempotencyKey: key, Traceparent: "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"}
}
func reviewerPolicy() json.RawMessage {
	return json.RawMessage(`{"policyId":"policy.reviewers","version":"v1","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`)
}

func newTestService(t *testing.T, repository *MemoryRepository, clock *testClock, authority *testAuthority, reconciler *testReconciler, reservation *testReservation) (*Service, *testRuntime, *testLeases) {
	t.Helper()
	runtime, leases := &testRuntime{}, &testLeases{}
	service, err := NewService(repository, BoundSchemaValidator{}, authority, runtime, leases, reconciler, reservation, journal.NewMemoryStore(), clock, &testIDs{}, Limits{ChildDepth: 2, ChildFanout: 2})
	if err != nil {
		t.Fatal(err)
	}
	return service, runtime, leases
}

func TestInputWaitSurvivesServiceReplacementAndAcceptsExactlyOneCurrentResponse(t *testing.T) {
	repository := NewMemoryRepository()
	if err := repository.Seed(scope(), snapshot("run", runs.Planning, 4)); err != nil {
		t.Fatal(err)
	}
	clock := &testClock{now: testNow}
	authority := &testAuthority{}
	service, _, _ := newTestService(t, repository, clock, authority, &testReconciler{clear: true}, &testReservation{})
	schema := json.RawMessage(`{"type":"object","required":["answer"],"properties":{"answer":{"type":"string","maxLength":20}},"additionalProperties":false}`)
	request, opened, err := service.RequestInput(context.Background(), write("run", 4, "open"), OpenInput{Question: "Which locale?", ResponseSchema: schema, ExpiresAt: testNow.Add(time.Hour), ResumeCheckpoint: "planning:compile"})
	if err != nil || opened.Snapshot.Status != runs.AwaitingInput {
		t.Fatalf("opened=%#v err=%v", opened, err)
	}

	// A replacement service instance shares only durable repository/runtime state.
	replacement, runtime, _ := newTestService(t, repository, clock, authority, &testReconciler{clear: true}, &testReservation{})
	command := InputResponseCommand{RequestID: request.ID, RequestVersion: 1, Value: json.RawMessage(`{"answer":"en-US"}`)}
	const writers = 12
	var wait sync.WaitGroup
	results := make(chan error, writers)
	for index := 0; index < writers; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			_, err := replacement.RespondInput(context.Background(), write("run", 5, fmt.Sprintf("respond-%d", index)), command)
			results <- err
		}(index)
	}
	wait.Wait()
	close(results)
	accepted, conflicts := 0, map[string]int{}
	for err := range results {
		if err == nil {
			accepted++
		} else {
			var details problem.Details
			if !errors.As(err, &details) {
				t.Fatalf("unexpected %T %v", err, err)
			}
			conflicts[details.Code]++
		}
	}
	if accepted != 1 || conflicts[string(problem.CodeInputAlreadyResponded)] != writers-1 {
		t.Fatalf("accepted=%d conflicts=%v", accepted, conflicts)
	}
	current, _ := repository.Current(context.Background(), scope(), "run")
	if current.Status != runs.Planning || current.Version != 6 || len(runtime.signals) != 1 || len(runtime.resumed) != 1 || runtime.resumed[0] != "run:1:planning:compile:input:"+string(request.ID) {
		t.Fatalf("current=%#v signals=%d resumed=%v", current, len(runtime.signals), runtime.resumed)
	}
}

func TestInputResponseConflictCodesAndExpiryNeverInventOutcome(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*testAuthority, *testClock, *InputResponseCommand)
		want   problem.Code
	}{
		{"stale", func(_ *testAuthority, _ *testClock, command *InputResponseCommand) { command.RequestVersion = 2 }, problem.CodeInputRequestStale},
		{"unauthorized", func(authority *testAuthority, _ *testClock, _ *InputResponseCommand) { authority.denyInput = true }, problem.CodeAuthorizationDenied},
		{"expired", func(_ *testAuthority, clock *testClock, _ *InputResponseCommand) {
			clock.now = testNow.Add(2 * time.Hour)
		}, problem.CodeInputRequestExpired},
		{"schema", func(_ *testAuthority, _ *testClock, command *InputResponseCommand) {
			command.Value = json.RawMessage(`{"unknown":true}`)
		}, problem.CodeInputSchemaInvalid},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			repository := NewMemoryRepository()
			_ = repository.Seed(scope(), snapshot("run", runs.Planning, 1))
			clock := &testClock{now: testNow}
			authority := &testAuthority{}
			service, _, _ := newTestService(t, repository, clock, authority, &testReconciler{clear: true}, &testReservation{})
			schema := json.RawMessage(`{"type":"object","required":["answer"],"properties":{"answer":{"type":"string"}},"additionalProperties":false}`)
			request, _, err := service.RequestInput(context.Background(), write("run", 1, "open"), OpenInput{Question: "q", ResponseSchema: schema, ExpiresAt: testNow.Add(time.Hour), ResumeCheckpoint: "planning"})
			if err != nil {
				t.Fatal(err)
			}
			command := InputResponseCommand{RequestID: request.ID, RequestVersion: 1, Value: json.RawMessage(`{"answer":"yes"}`)}
			test.mutate(authority, clock, &command)
			_, err = service.RespondInput(context.Background(), write("run", 2, "respond"), command)
			var details problem.Details
			if !errors.As(err, &details) || details.Code != string(test.want) {
				t.Fatalf("err=%v details=%#v", err, details)
			}
			current, _ := repository.Current(context.Background(), scope(), "run")
			if current.Status != runs.AwaitingInput || current.Version != 2 {
				t.Fatalf("expiry/conflict mutated run: %#v", current)
			}
		})
	}

	// Same key with changed bytes is distinct from an already-responded request.
	repository := NewMemoryRepository()
	_ = repository.Seed(scope(), snapshot("run", runs.Planning, 1))
	clock := &testClock{now: testNow}
	service, _, _ := newTestService(t, repository, clock, &testAuthority{}, &testReconciler{clear: true}, &testReservation{})
	schema := json.RawMessage(`{"type":"object","required":["answer"],"properties":{"answer":{"type":"string"}},"additionalProperties":false}`)
	request, _, _ := service.RequestInput(context.Background(), write("run", 1, "open"), OpenInput{Question: "q", ResponseSchema: schema, ExpiresAt: testNow.Add(time.Hour), ResumeCheckpoint: "planning"})
	_, _ = service.RespondInput(context.Background(), write("run", 2, "same"), InputResponseCommand{RequestID: request.ID, RequestVersion: 1, Value: json.RawMessage(`{"answer":"a"}`)})
	_, err := service.RespondInput(context.Background(), write("run", 2, "same"), InputResponseCommand{RequestID: request.ID, RequestVersion: 1, Value: json.RawMessage(`{"answer":"b"}`)})
	var details problem.Details
	if !errors.As(err, &details) || details.Code != string(problem.CodeIdempotencyConflict) {
		t.Fatalf("changed replay err=%v", err)
	}
}

func TestSequentialInputRequestsReceiveMonotonicVersions(t *testing.T) {
	repository := NewMemoryRepository()
	_ = repository.Seed(scope(), snapshot("run", runs.Planning, 1))
	clock := &testClock{now: testNow}
	service, _, _ := newTestService(t, repository, clock, &testAuthority{}, &testReconciler{clear: true}, &testReservation{})
	schema := json.RawMessage(`{"type":"object","required":["answer"],"properties":{"answer":{"type":"string"}},"additionalProperties":false}`)
	first, opened, err := service.RequestInput(context.Background(), write("run", 1, "open-1"), OpenInput{Question: "first", ResponseSchema: schema, ExpiresAt: testNow.Add(time.Hour), ResumeCheckpoint: "planning:first"})
	if err != nil || first.Version != 1 {
		t.Fatalf("first request = %#v, %v", first, err)
	}
	responded, err := service.RespondInput(context.Background(), write("run", opened.Snapshot.Version, "respond-1"), InputResponseCommand{RequestID: first.ID, RequestVersion: first.Version, Value: json.RawMessage(`{"answer":"one"}`)})
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := service.RequestInput(context.Background(), write("run", responded.Snapshot.Version, "open-2"), OpenInput{Question: "second", ResponseSchema: schema, ExpiresAt: testNow.Add(time.Hour), ResumeCheckpoint: "planning:second"})
	if err != nil || second.Version != 2 {
		t.Fatalf("second request = %#v, %v; want version 2", second, err)
	}
}

func TestApprovalEvidenceIsImmutableAndCannotCommitWithoutM5Gateway(t *testing.T) {
	repository := NewMemoryRepository()
	_ = repository.Seed(scope(), snapshot("run", runs.AwaitingReview, 7))
	clock := &testClock{now: testNow}
	service, runtime, _ := newTestService(t, repository, clock, &testAuthority{}, &testReconciler{clear: true}, &testReservation{})
	command := OpenApproval{ActionDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Effects: json.RawMessage(`{"kind":"page-apply"}`), ExpectedCost: json.RawMessage(`{"amount":"1"}`), ReviewerPolicy: reviewerPolicy(), ExpiresAt: testNow.Add(time.Hour), ResumeCheckpoint: "review:approved"}
	request, opened, err := service.RequestApproval(context.Background(), write("run", 7, "open"), command)
	if err != nil || opened.Snapshot.Status != runs.AwaitingApproval {
		t.Fatalf("opened=%#v err=%v", opened, err)
	}
	command.Effects[2] = 'X'
	stored, _ := repository.Approval(context.Background(), scope(), "run", request.ID)
	if string(stored.Effects) != `{"kind":"page-apply"}` {
		t.Fatalf("request evidence mutated: %s", stored.Effects)
	}
	approved, err := service.DecideApproval(context.Background(), write("run", 8, "approve"), ApprovalDecisionCommand{RequestID: request.ID, RequestVersion: 1, Decision: DecisionApprove})
	if err != nil {
		t.Fatal(err)
	}
	if approved.Snapshot.Status != runs.AwaitingApproval || approved.Snapshot.Version != 8 || len(runtime.signals) != 1 {
		t.Fatalf("approval bypassed commit gateway: %#v", approved)
	}
	_, err = service.DecideApproval(context.Background(), write("run", 8, "other"), ApprovalDecisionCommand{RequestID: request.ID, RequestVersion: 1, Decision: DecisionReject})
	var details problem.Details
	if !errors.As(err, &details) || details.Code != string(problem.CodeApprovalAlreadyDecided) {
		t.Fatalf("decision mutation err=%v", err)
	}
}

func TestApprovalWaitSurvivesServiceReplacement(t *testing.T) {
	repository := NewMemoryRepository()
	_ = repository.Seed(scope(), snapshot("run", runs.AwaitingReview, 7))
	clock := &testClock{now: testNow}
	authority := &testAuthority{}
	service, _, _ := newTestService(t, repository, clock, authority, &testReconciler{clear: true}, &testReservation{})
	request, opened, err := service.RequestApproval(context.Background(), write("run", 7, "open-restart"), OpenApproval{ActionDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Effects: json.RawMessage(`{"kind":"page-apply"}`), ExpectedCost: json.RawMessage(`{"amount":"1"}`), ReviewerPolicy: reviewerPolicy(), ExpiresAt: testNow.Add(time.Hour), ResumeCheckpoint: "review:approved"})
	if err != nil || opened.Snapshot.Status != runs.AwaitingApproval {
		t.Fatalf("opened=%#v err=%v", opened, err)
	}
	replacement, runtime, _ := newTestService(t, repository, clock, authority, &testReconciler{clear: true}, &testReservation{})
	result, err := replacement.DecideApproval(context.Background(), write("run", opened.Snapshot.Version, "decide-restart"), ApprovalDecisionCommand{RequestID: request.ID, RequestVersion: 1, Decision: DecisionReject})
	if err != nil || result.Snapshot.Status != runs.AwaitingReview || len(runtime.resumed) != 1 || runtime.resumed[0] != "run:1:review:approved:approval:"+string(request.ID) {
		t.Fatalf("replacement result=%#v resumed=%v err=%v", result, runtime.resumed, err)
	}
}

func TestApprovalRejectAndChangeReturnToReview(t *testing.T) {
	for _, decision := range []DecisionKind{DecisionReject, DecisionChange} {
		t.Run(string(decision), func(t *testing.T) {
			repository := NewMemoryRepository()
			_ = repository.Seed(scope(), snapshot("run", runs.AwaitingReview, 1))
			service, runtime, _ := newTestService(t, repository, &testClock{now: testNow}, &testAuthority{}, &testReconciler{clear: true}, &testReservation{})
			request, opened, err := service.RequestApproval(context.Background(), write("run", 1, "open"), OpenApproval{ActionDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Effects: json.RawMessage(`{"effect":"apply"}`), ExpectedCost: json.RawMessage(`{"amount":"1"}`), ReviewerPolicy: reviewerPolicy(), ExpiresAt: testNow.Add(time.Hour), ResumeCheckpoint: "review"})
			if err != nil {
				t.Fatal(err)
			}
			result, err := service.DecideApproval(context.Background(), write("run", opened.Snapshot.Version, "decide"), ApprovalDecisionCommand{RequestID: request.ID, RequestVersion: 1, Decision: decision})
			if err != nil || result.Snapshot.Status != runs.AwaitingReview || len(runtime.resumed) != 1 || runtime.resumed[0] != "run:1:review:approval:"+string(request.ID) {
				t.Fatalf("decision=%s result=%#v resumed=%v err=%v", decision, result, runtime.resumed, err)
			}
		})
	}
}

func TestApprovalReviewerPolicyMustBeAContractReference(t *testing.T) {
	repository := NewMemoryRepository()
	_ = repository.Seed(scope(), snapshot("run", runs.AwaitingReview, 1))
	service, _, _ := newTestService(t, repository, &testClock{now: testNow}, &testAuthority{}, &testReconciler{clear: true}, &testReservation{})
	_, _, err := service.RequestApproval(context.Background(), write("run", 1, "open"), OpenApproval{ActionDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Effects: json.RawMessage(`{"effect":"apply"}`), ExpectedCost: json.RawMessage(`{"amount":"1"}`), ReviewerPolicy: json.RawMessage(`{"scope":"agent:review"}`), ExpiresAt: testNow.Add(time.Hour), ResumeCheckpoint: "review"})
	var details problem.Details
	if !errors.As(err, &details) || details.Code != string(problem.CodeRequestInvalid) {
		t.Fatalf("invalid reviewer policy was accepted: %v", err)
	}
	current, currentErr := repository.Current(context.Background(), scope(), "run")
	if currentErr != nil || current.Status != runs.AwaitingReview || current.Version != 1 {
		t.Fatalf("invalid reviewer policy mutated run: %#v, %v", current, currentErr)
	}
}

func TestSequentialApprovalRequestsReceiveMonotonicVersions(t *testing.T) {
	repository := NewMemoryRepository()
	_ = repository.Seed(scope(), snapshot("run", runs.AwaitingReview, 1))
	service, _, _ := newTestService(t, repository, &testClock{now: testNow}, &testAuthority{}, &testReconciler{clear: true}, &testReservation{})
	command := OpenApproval{ActionDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Effects: json.RawMessage(`{"effect":"apply"}`), ExpectedCost: json.RawMessage(`{"amount":"1"}`), ReviewerPolicy: reviewerPolicy(), ExpiresAt: testNow.Add(time.Hour), ResumeCheckpoint: "review"}
	first, opened, err := service.RequestApproval(context.Background(), write("run", 1, "open-1"), command)
	if err != nil || first.Version != 1 {
		t.Fatalf("first request = %#v, %v", first, err)
	}
	rejected, err := service.DecideApproval(context.Background(), write("run", opened.Snapshot.Version, "reject-1"), ApprovalDecisionCommand{RequestID: first.ID, RequestVersion: first.Version, Decision: DecisionReject})
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := service.RequestApproval(context.Background(), write("run", rejected.Snapshot.Version, "open-2"), command)
	if err != nil || second.Version != 2 {
		t.Fatalf("second request = %#v, %v; want version 2", second, err)
	}
}

func TestInterruptMutationsFailClosedWhenAuthorityClockIsUnavailable(t *testing.T) {
	repository := NewMemoryRepository()
	_ = repository.Seed(scope(), snapshot("run", runs.Planning, 1))
	service, _, _ := newTestService(t, repository, &testClock{}, &testAuthority{}, &testReconciler{clear: true}, &testReservation{})
	_, _, err := service.RequestInput(context.Background(), write("run", 1, "open"), OpenInput{Question: "q", ResponseSchema: json.RawMessage(`{"type":"string"}`), ExpiresAt: testNow.Add(time.Hour), ResumeCheckpoint: "planning"})
	var details problem.Details
	if !errors.As(err, &details) || details.Code != string(problem.CodeAuthorityStale) {
		t.Fatalf("zero authority clock err = %v", err)
	}
	current, currentErr := repository.Current(context.Background(), scope(), "run")
	if currentErr != nil || current.Status != runs.Planning || current.Version != 1 {
		t.Fatalf("clock failure mutated run: %#v, %v", current, currentErr)
	}
}

func TestApprovalDecisionConflictFamiliesDoNotMutateWait(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*testAuthority, *testClock, *ApprovalDecisionCommand)
		want   problem.Code
	}{
		{"stale", func(_ *testAuthority, _ *testClock, command *ApprovalDecisionCommand) { command.RequestVersion = 2 }, problem.CodeApprovalRequestStale},
		{"unauthorized", func(authority *testAuthority, _ *testClock, _ *ApprovalDecisionCommand) { authority.denyReview = true }, problem.CodeAuthorizationDenied},
		{"expired", func(_ *testAuthority, clock *testClock, _ *ApprovalDecisionCommand) {
			clock.now = testNow.Add(2 * time.Hour)
		}, problem.CodeApprovalRequestExpired},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			repository := NewMemoryRepository()
			_ = repository.Seed(scope(), snapshot("run", runs.AwaitingReview, 1))
			clock, authority := &testClock{now: testNow}, &testAuthority{}
			service, _, _ := newTestService(t, repository, clock, authority, &testReconciler{clear: true}, &testReservation{})
			request, opened, err := service.RequestApproval(context.Background(), write("run", 1, "open"), OpenApproval{ActionDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Effects: json.RawMessage(`{"effect":"apply"}`), ExpectedCost: json.RawMessage(`{"amount":"1"}`), ReviewerPolicy: reviewerPolicy(), ExpiresAt: testNow.Add(time.Hour), ResumeCheckpoint: "review"})
			if err != nil {
				t.Fatal(err)
			}
			command := ApprovalDecisionCommand{RequestID: request.ID, RequestVersion: 1, Decision: DecisionApprove}
			test.mutate(authority, clock, &command)
			_, err = service.DecideApproval(context.Background(), write("run", opened.Snapshot.Version, "decision"), command)
			var details problem.Details
			if !errors.As(err, &details) || details.Code != string(test.want) {
				t.Fatalf("err=%v details=%#v", err, details)
			}
			current, _ := repository.Current(context.Background(), scope(), "run")
			if current.Status != runs.AwaitingApproval || current.Version != opened.Snapshot.Version {
				t.Fatalf("approval conflict mutated wait: %#v", current)
			}
		})
	}
}

func TestCancellationMatrixAndCommitPhaseNeverClaimsCancelled(t *testing.T) {
	states := []runs.State{runs.Created, runs.Preparing, runs.Planning, runs.AwaitingInput, runs.Executing, runs.Validating, runs.AwaitingReview, runs.AwaitingApproval, runs.Conflict}
	for _, state := range states {
		t.Run(string(state), func(t *testing.T) {
			repository := NewMemoryRepository()
			_ = repository.Seed(scope(), snapshot("run", state, 3))
			service, runtime, leases := newTestService(t, repository, &testClock{now: testNow}, &testAuthority{}, &testReconciler{clear: true}, &testReservation{})
			result, err := service.Cancel(context.Background(), write("run", 3, "cancel"))
			if err != nil || result.Snapshot.Status != runs.Cancelled {
				t.Fatalf("result=%#v err=%v", result, err)
			}
			if len(leases.revoked) != 1 || len(runtime.stopped) != 1 || runtime.stopped[0] != "run" {
				t.Fatalf("dispatch/lease cancellation missing: stopped=%v revoked=%v", runtime.stopped, leases.revoked)
			}
			entry := repository.runs["run"]
			if entry.cancellation == nil || !entry.cancellation.DispatchStopped || !entry.cancellation.LeasesRevoked || !entry.cancellation.ChildrenPropagated || !entry.cancellation.Reconciled {
				t.Fatalf("durable cancellation progress missing: %#v", entry.cancellation)
			}
		})
	}
	for _, state := range []runs.State{runs.Committing, runs.AwaitingDomainConfirmation} {
		t.Run(string(state), func(t *testing.T) {
			repository := NewMemoryRepository()
			_ = repository.Seed(scope(), snapshot("run", state, 9))
			completed := runs.Completed
			service, _, _ := newTestService(t, repository, &testClock{now: testNow}, &testAuthority{}, &testReconciler{clear: true, authoritative: &completed}, &testReservation{})
			result, err := service.Cancel(context.Background(), write("run", 9, "cancel"))
			if err != nil || result.Snapshot.Status != state {
				t.Fatalf("commit cancellation masked authority: %#v err=%v", result, err)
			}
		})
	}
	repository := NewMemoryRepository()
	_ = repository.Seed(scope(), snapshot("run", runs.Executing, 1))
	service, _, _ := newTestService(t, repository, &testClock{now: testNow}, &testAuthority{}, &testReconciler{clear: false}, &testReservation{})
	result, err := service.Cancel(context.Background(), write("run", 1, "cancel"))
	if err != nil || result.Snapshot.Status != runs.Cancelling {
		t.Fatalf("uncertainty not visible: %#v err=%v", result, err)
	}
}

func TestCancellationResumesAfterDispatchStopFailureWithoutFalseEvidence(t *testing.T) {
	repository := NewMemoryRepository()
	_ = repository.Seed(scope(), snapshot("run", runs.Executing, 1))
	service, runtime, _ := newTestService(t, repository, &testClock{now: testNow}, &testAuthority{}, &testReconciler{clear: true}, &testReservation{})
	runtime.stopErr = errors.New("stop unavailable")
	result, err := service.Cancel(context.Background(), write("run", 1, "cancel"))
	if err == nil || result.Snapshot.Status != runs.Cancelling {
		t.Fatalf("failed cancellation request=%#v err=%v", result, err)
	}
	entry := repository.runs["run"]
	if entry.cancellation == nil || entry.cancellation.DispatchStopped || entry.cancellation.Reconciled {
		t.Fatalf("failed side effect was recorded as complete: %#v", entry.cancellation)
	}
	runtime.stopErr = nil
	result, err = service.Cancel(context.Background(), write("run", 1, "cancel"))
	if err != nil || result.Snapshot.Status != runs.Cancelled || len(runtime.stopped) != 1 {
		t.Fatalf("cancellation did not resume safely: %#v stopped=%v err=%v", result, runtime.stopped, err)
	}
}

func TestRetryIsIdempotentIncrementsGenerationAndPreservesAuthority(t *testing.T) {
	repository := NewMemoryRepository()
	failed := snapshot("run", runs.Failed, 10)
	retryProblem := problem.New(problem.CodeInfrastructureUnavailable, "")
	failed.Problem = &retryProblem
	_ = repository.Seed(scope(), failed)
	authority := &testAuthority{retry: true, checkpoint: "prepare:authority"}
	service, runtime, _ := newTestService(t, repository, &testClock{now: testNow}, authority, &testReconciler{clear: true}, &testReservation{})
	first, err := service.Retry(context.Background(), write("run", 10, "retry"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.Retry(context.Background(), write("run", 10, "retry"))
	if err != nil {
		t.Fatal(err)
	}
	if first.Snapshot.ExecutionGeneration != 2 || first.Snapshot.Version != 11 || first.Snapshot.Status != runs.Preparing || second.Snapshot.ExecutionGeneration != 2 || !second.Replayed || first.ResumeCheckpoint != "prepare:authority" {
		t.Fatalf("first=%#v second=%#v", first, second)
	}
	if string(first.Snapshot.ContractBOM) != string(failed.ContractBOM) || string(first.Snapshot.Budget) != string(failed.Budget) {
		t.Fatal("retry rewrote retained authority/history inventory")
	}
	if len(runtime.resumed) != 1 || runtime.resumed[0] != "run:2:prepare:authority:" {
		t.Fatalf("retry did not resume earliest safe checkpoint exactly once: %v", runtime.resumed)
	}
}

func TestRetryReevaluatesEligibilityAfterAuthorityChanges(t *testing.T) {
	repository := NewMemoryRepository()
	failed := snapshot("run", runs.Failed, 3)
	recorded := problem.New(problem.CodeInfrastructureUnavailable, "")
	failed.Problem = &recorded
	_ = repository.Seed(scope(), failed)
	authority := &testAuthority{retry: false, checkpoint: "prepare:rechecked"}
	service, runtime, _ := newTestService(t, repository, &testClock{now: testNow}, authority, &testReconciler{clear: true}, &testReservation{})
	_, err := service.Retry(context.Background(), write("run", 3, "retry"))
	var details problem.Details
	if !errors.As(err, &details) || details.Code != recorded.Code || details.Retryability != recorded.Retryability {
		t.Fatalf("ineligible retry did not return recorded problem unchanged: %#v err=%v", details, err)
	}
	current, _ := repository.Current(context.Background(), scope(), "run")
	if current.Status != runs.Failed || current.Version != 3 || len(runtime.resumed) != 0 {
		t.Fatalf("ineligible retry mutated authority: %#v resumed=%v", current, runtime.resumed)
	}
	authority.retry = true
	outcome, err := service.Retry(context.Background(), write("run", 3, "retry"))
	if err != nil || outcome.Snapshot.ExecutionGeneration != 2 || outcome.ResumeCheckpoint != "prepare:rechecked" || len(runtime.resumed) != 1 {
		t.Fatalf("new authority was not reevaluated: %#v resumed=%v err=%v", outcome, runtime.resumed, err)
	}
}

func TestRetryReplayRecoversAfterWorkflowResumeFailure(t *testing.T) {
	repository := NewMemoryRepository()
	failed := snapshot("run", runs.Failed, 6)
	recorded := problem.New(problem.CodeInfrastructureUnavailable, "")
	failed.Problem = &recorded
	_ = repository.Seed(scope(), failed)
	service, runtime, _ := newTestService(t, repository, &testClock{now: testNow}, &testAuthority{retry: true, checkpoint: "prepare:safe"}, &testReconciler{clear: true}, &testReservation{})
	runtime.resumeErr = errors.New("runtime unavailable")
	if _, err := service.Retry(context.Background(), write("run", 6, "retry")); err == nil {
		t.Fatal("retry did not report workflow resume failure")
	}
	current, _ := repository.Current(context.Background(), scope(), "run")
	if current.Status != runs.Preparing || current.ExecutionGeneration != 2 || current.Version != 7 {
		t.Fatalf("durable retry transition missing after resume failure: %#v", current)
	}
	runtime.resumeErr = nil
	replayed, err := service.Retry(context.Background(), write("run", 6, "retry"))
	if err != nil || !replayed.Replayed || len(runtime.resumed) != 1 || replayed.Snapshot.ExecutionGeneration != 2 {
		t.Fatalf("retry replay did not recover resume: %#v resumed=%v err=%v", replayed, runtime.resumed, err)
	}
}

func TestDiscardRequiresReviewAndRetainsSnapshotEvidence(t *testing.T) {
	repository := NewMemoryRepository()
	original := snapshot("run", runs.AwaitingReview, 2)
	_ = repository.Seed(scope(), original)
	service, _, _ := newTestService(t, repository, &testClock{now: testNow}, &testAuthority{}, &testReconciler{clear: true}, &testReservation{})
	result, err := service.Discard(context.Background(), write("run", 2, "discard"))
	if err != nil || result.Snapshot.Status != runs.Discarded || string(result.Snapshot.ContractBOM) != string(original.ContractBOM) {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	_, err = service.Discard(context.Background(), write("run", 3, "again"))
	if err == nil {
		t.Fatal("terminal discard accepted mutation")
	}
}

func TestChildrenInheritAuthorityEnforceBoundsAndGateFallbackReservation(t *testing.T) {
	repository := NewMemoryRepository()
	parent := snapshot("parent", runs.Executing, 4)
	_ = repository.Seed(scope(), parent)
	reservation := &testReservation{}
	service, _, _ := newTestService(t, repository, &testClock{now: testNow}, &testAuthority{}, &testReconciler{clear: true}, reservation)
	required, err := service.CreateChild(context.Background(), write("parent", 4, "required"), CreateChild{Mode: ChildRequired})
	if err != nil {
		t.Fatal(err)
	}
	if required.RootRunID != "parent" || required.ParentRunID != "parent" || required.WorkspaceID != "workspace" || required.ProjectID != "project" || required.ActorID != "actor" || string(required.ContractBOM) != string(parent.ContractBOM) || string(required.DataPolicy) != string(parent.Policy) {
		t.Fatalf("inheritance mismatch %#v", required)
	}
	optional, err := service.CreateChild(context.Background(), write("parent", 4, "optional"), CreateChild{Mode: ChildOptional})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.CreateChild(context.Background(), write("parent", 4, "overflow"), CreateChild{Mode: ChildOptional}); err == nil {
		t.Fatal("fanout bound not enforced")
	}
	if err := repository.RecordChildOutcome(context.Background(), scope(), optional.RunID, ChildOutcome{State: runs.Failed}); err != nil {
		t.Fatal(err)
	}
	optionalOutcome, _ := repository.ChildOutcome(context.Background(), scope(), optional.RunID)
	if optionalOutcome.Warning == "" {
		t.Fatal("optional failure warning absent")
	}
	before := len(reservation.calls)
	predecessor := required.RunID
	if _, err = service.CreateChild(context.Background(), write("parent", 4, "fallback-early"), CreateChild{Mode: ChildFallback, PredecessorRunID: &predecessor}); err == nil {
		t.Fatal("early fallback accepted")
	}
	if len(reservation.calls) != before {
		t.Fatal("fallback reserved before eligible predecessor")
	}
	if err := repository.RecordChildOutcome(context.Background(), scope(), required.RunID, ChildOutcome{State: runs.Failed, Artifact: "artifact-lineage:required"}); err != nil {
		t.Fatal(err)
	}
	// The two-child fanout is already full, so fallback still cannot dispatch.
	if _, err = service.CreateChild(context.Background(), write("parent", 4, "fallback"), CreateChild{Mode: ChildFallback, PredecessorRunID: &predecessor}); err == nil {
		t.Fatal("fallback bypassed fanout")
	}
}

func TestChildBudgetDenialPreventsDurableCreationAndDispatch(t *testing.T) {
	repository := NewMemoryRepository()
	_ = repository.Seed(scope(), snapshot("parent", runs.Executing, 4))
	denial := problem.New(problem.CodeBudgetDenied, "")
	reservation := &testReservation{err: denial}
	service, runtime, _ := newTestService(t, repository, &testClock{now: testNow}, &testAuthority{}, &testReconciler{clear: true}, reservation)
	_, err := service.CreateChild(context.Background(), write("parent", 4, "budget-denied"), CreateChild{Mode: ChildRequired})
	var details problem.Details
	if !errors.As(err, &details) || details.Code != string(problem.CodeBudgetDenied) {
		t.Fatalf("child budget denial err=%v", err)
	}
	if len(runtime.children) != 0 {
		t.Fatalf("budget-denied child dispatched: %#v", runtime.children)
	}
	children, childrenErr := repository.Descendants(context.Background(), scope(), "parent")
	if childrenErr != nil || len(children) != 0 {
		t.Fatalf("budget-denied child persisted: %#v, %v", children, childrenErr)
	}
}

func TestFallbackReservesOnlyAfterEligibleFailureAndRequiredFailureFailsParent(t *testing.T) {
	repository := NewMemoryRepository()
	_ = repository.Seed(scope(), snapshot("parent", runs.Executing, 4))
	reservation := &testReservation{}
	runtime, leases := &testRuntime{}, &testLeases{}
	service, err := NewService(repository, BoundSchemaValidator{}, &testAuthority{}, runtime, leases, &testReconciler{clear: true}, reservation, journal.NewMemoryStore(), &testClock{now: testNow}, &testIDs{}, Limits{ChildDepth: 3, ChildFanout: 3})
	if err != nil {
		t.Fatal(err)
	}
	predecessor, err := service.CreateChild(context.Background(), write("parent", 4, "required"), CreateChild{Mode: ChildRequired})
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.RecordChildOutcome(context.Background(), scope(), predecessor.RunID, ChildOutcome{State: runs.Failed, Artifact: "artifact-lineage:required"}); err != nil {
		t.Fatal(err)
	}
	parent, _ := repository.Current(context.Background(), scope(), "parent")
	if parent.Status != runs.Failed {
		t.Fatalf("required child failure did not fail parent: %#v", parent)
	}
	// Use an independently executing parent to prove fallback order without
	// the required-child parent failure blocking child dispatch.
	_ = repository.Seed(scope(), snapshot("fallback-parent", runs.Executing, 1))
	failedChild, err := service.CreateChild(context.Background(), write("fallback-parent", 1, "predecessor"), CreateChild{Mode: ChildOptional})
	if err != nil {
		t.Fatal(err)
	}
	before := len(reservation.calls)
	failedID := failedChild.RunID
	if _, err := service.CreateChild(context.Background(), write("fallback-parent", 1, "too-early"), CreateChild{Mode: ChildFallback, PredecessorRunID: &failedID}); err == nil || len(reservation.calls) != before {
		t.Fatalf("fallback reserved before failure: calls=%v err=%v", reservation.calls, err)
	}
	if err := repository.RecordChildOutcome(context.Background(), scope(), failedID, ChildOutcome{State: runs.Failed}); err != nil {
		t.Fatal(err)
	}
	fallback, err := service.CreateChild(context.Background(), write("fallback-parent", 1, "fallback"), CreateChild{Mode: ChildFallback, PredecessorRunID: &failedID})
	if err != nil || fallback.Mode != ChildFallback || fallback.PredecessorRunID == nil || *fallback.PredecessorRunID != failedID {
		t.Fatalf("eligible fallback did not dispatch: %#v err=%v", fallback, err)
	}
	if len(reservation.calls) != before+1 || len(runtime.children) != 3 {
		t.Fatalf("fallback reservation/dispatch order missing calls=%v children=%v", reservation.calls, runtime.children)
	}
	if err := repository.RecordChildOutcome(context.Background(), scope(), fallback.RunID, ChildOutcome{State: runs.Completed, Artifact: "https://not-lineage.example"}); err == nil {
		t.Fatal("non-lineage child artifact was accepted")
	}
}

func TestCancellationPropagatesToAllChildDescendants(t *testing.T) {
	repository := NewMemoryRepository()
	_ = repository.Seed(scope(), snapshot("root", runs.Executing, 1))
	service, runtime, leases := newTestService(t, repository, &testClock{now: testNow}, &testAuthority{}, &testReconciler{clear: true}, &testReservation{})
	child, err := service.CreateChild(context.Background(), write("root", 1, "child"), CreateChild{Mode: ChildRequired})
	if err != nil {
		t.Fatal(err)
	}
	childSnapshot, _ := repository.Current(context.Background(), scope(), child.RunID)
	childSnapshot.Status = runs.Executing
	childSnapshot.Version = 2
	_ = repository.Seed(scope(), childSnapshot)
	grandchild, err := service.CreateChild(context.Background(), write(child.RunID, 2, "grandchild"), CreateChild{Mode: ChildOptional})
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.Cancel(context.Background(), write("root", 1, "cancel"))
	if err != nil || result.Snapshot.Status != runs.Cancelled {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	stopped := map[runs.ID]bool{}
	for _, id := range runtime.stopped {
		stopped[id] = true
	}
	if !stopped["root"] || !stopped[child.RunID] || !stopped[grandchild.RunID] {
		t.Fatalf("stopped workflows=%v", stopped)
	}
	if len(leases.revoked) != 3 {
		t.Fatalf("descendant leases not revoked: %v", leases.revoked)
	}
}

type testAlerts struct {
	lock  sync.Mutex
	count int
}

func (a *testAlerts) Alert(context.Context, string, runs.Scope, runs.ID, runs.State) error {
	a.lock.Lock()
	defer a.lock.Unlock()
	a.count++
	return nil
}

func TestDwellMonitorCoversEveryNonterminalStateWithoutTransition(t *testing.T) {
	repository := NewMemoryRepository()
	policies := map[runs.State]DwellPolicy{}
	for index, state := range nonterminalStates() {
		id := runs.ID(fmt.Sprintf("run-%d", index))
		item := snapshot(id, state, 1)
		item.UpdatedAt = testNow.Add(-10 * time.Minute)
		_ = repository.Seed(scope(), item)
		policies[state] = DwellPolicy{Deadline: 5 * time.Minute, Owner: "agent-oncall"}
	}
	terminal := snapshot("terminal", runs.Completed, 1)
	terminal.UpdatedAt = testNow.Add(-time.Hour)
	_ = repository.Seed(scope(), terminal)
	clock := &testClock{now: testNow}
	alerts := &testAlerts{}
	monitor, err := NewMonitor(repository, alerts, clock, policies)
	if err != nil {
		t.Fatal(err)
	}
	count, err := monitor.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if count != len(nonterminalStates()) || alerts.count != count {
		t.Fatalf("count=%d alerts=%d", count, alerts.count)
	}
	again, _ := monitor.Scan(context.Background())
	if again != 0 {
		t.Fatal("stuck event was not idempotent")
	}
	for index, state := range nonterminalStates() {
		current, _ := repository.Current(context.Background(), scope(), runs.ID(fmt.Sprintf("run-%d", index)))
		if current.Status != state || current.Version != 1 {
			t.Fatalf("dwell invented outcome for %s", state)
		}
	}
}
