package domaincommit

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/applyauth"
	"github.com/ancyloce/anvilkit-agent-service/internal/pagixclient"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/runs"
)

var commitNow = time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)

type fixedClock struct{}

func (fixedClock) Now() time.Time { return commitNow }

type ids struct{ next int }

func (i *ids) OperationID() (string, error) {
	i.next++
	return "operation-" + string(rune('0'+i.next)), nil
}

type fakeIssuer struct {
	calls int
	err   error
}

func (i *fakeIssuer) Issue(_ context.Context, command applyauth.Command) (applyauth.Authorization, error) {
	i.calls++
	if i.err != nil {
		return applyauth.Authorization{}, i.err
	}
	digest := func(c string) string { return "sha256:" + strings.Repeat(c, 64) }
	payload := applyauth.Payload{RunID: command.RunID, ActionDigest: digest("a"), ArtifactDigest: digest("b"), BaseRevision: "revision-1"}
	return applyauth.Authorization{ID: applyauth.AuthorizationID("authorization-" + string(rune('0'+i.calls))), Compact: "header.payload.signature", Payload: payload}, nil
}

type runStore struct {
	lock  sync.Mutex
	value runs.Run
}

func (r *runStore) Current(context.Context, Scope, runs.ID) (runs.Run, error) {
	r.lock.Lock()
	defer r.lock.Unlock()
	return r.value, nil
}
func (r *runStore) Transition(_ context.Context, _ Scope, _ runs.ID, expected uint64, command runs.Command) (runs.Run, error) {
	r.lock.Lock()
	defer r.lock.Unlock()
	if r.value.Version != expected {
		return runs.Run{}, problem.New(problem.CodeVersionConflict, "")
	}
	updated, _, err := r.value.Apply(command)
	if err == nil {
		r.value = updated
	}
	return updated, err
}

type fakePagix struct {
	lock       sync.Mutex
	commands   int
	events     map[string]pagixclient.DomainEvent
	effect     pagixclient.DomainOutcome
	hasEffect  bool
	persistErr error
}

func (p *fakePagix) Persist(_ context.Context, command pagixclient.DomainCommand) (pagixclient.DomainOutcome, error) {
	p.lock.Lock()
	defer p.lock.Unlock()
	p.commands++
	return p.effect, p.persistErr
}
func (p *fakePagix) Reconcile(context.Context, string, string) (pagixclient.DomainOutcome, bool, error) {
	p.lock.Lock()
	defer p.lock.Unlock()
	return p.effect, p.hasEffect, nil
}
func (p *fakePagix) Consume(_ context.Context, event pagixclient.DomainEvent) (pagixclient.DomainOutcome, bool, error) {
	p.lock.Lock()
	defer p.lock.Unlock()
	if p.events == nil {
		p.events = map[string]pagixclient.DomainEvent{}
	}
	if prior, ok := p.events[event.MessageID]; ok {
		if prior != event {
			return pagixclient.DomainOutcome{}, false, problem.New(problem.CodeIdempotencyConflict, "")
		}
		return event.Outcome, false, nil
	}
	p.events[event.MessageID] = event
	return event.Outcome, true, nil
}

func approvedRun(t *testing.T) runs.Run {
	t.Helper()
	run, err := runs.New("run-01")
	if err != nil {
		t.Fatal(err)
	}
	commands := []runs.CommandKind{runs.BeginPreparation, runs.PreparationReady, runs.BeginExecution, runs.BeginValidation, runs.SubmitForReview, runs.RequestApproval}
	for _, kind := range commands {
		command := runs.Command{Kind: kind}
		if kind == runs.SubmitForReview {
			command.Validation = runs.ValidationProof{Valid: true, BOMDigest: "sha256:" + strings.Repeat("a", 64), SchemaDigest: "sha256:" + strings.Repeat("b", 64), ValidatorVersion: "runtime-v1", CatalogDigest: "sha256:" + strings.Repeat("c", 64)}
		}
		run, _, err = run.Apply(command)
		if err != nil {
			t.Fatal(err)
		}
	}
	if run.State != runs.AwaitingApproval {
		t.Fatalf("state=%s", run.State)
	}
	return run
}
func input(version uint64) Start {
	digest := "sha256:" + strings.Repeat("c", 64)
	return Start{Scope: Scope{WorkspaceID: "workspace-01", ProjectID: "project-01"}, RunID: "run-01", ExpectedRunVersion: version, Authorization: applyauth.Command{WorkspaceID: "workspace-01", ProjectID: "project-01", RunID: "run-01", ApprovalRequestID: "approval-01", ArtifactID: "artifact-01"}, Metadata: pagixclient.Metadata{WorkloadIdentity: "spiffe://agent", Traceparent: "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01", WorkspaceID: "workspace-01", ProjectID: "project-01", ActorID: "actor-01", Operation: "page-persistence", IdempotencyKey: "apply-01", RequestDigest: digest}, ExpectedRevision: "revision-1"}
}
func coordinator(t *testing.T, pagix *fakePagix, issuer *fakeIssuer) (*Coordinator, *MemoryStore, *runStore) {
	t.Helper()
	store := NewMemoryStore()
	runsStore := &runStore{value: approvedRun(t)}
	value, err := New(store, runsStore, issuer, pagix, &ids{}, fixedClock{})
	if err != nil {
		t.Fatal(err)
	}
	return value, store, runsStore
}

func TestStartRecordsIdentityBeforeOneCommandAndOnlyEventCompletes(t *testing.T) {
	pagix := &fakePagix{persistErr: problem.New(problem.CodeDomainOutcomeUncertain, "")}
	issuer := &fakeIssuer{}
	service, store, runsStore := coordinator(t, pagix, issuer)
	start := input(runsStore.value.Version)
	operation, err := service.Start(context.Background(), start)
	var details problem.Details
	if !errors.As(err, &details) || details.Code != string(problem.CodeDomainOutcomeUncertain) {
		t.Fatalf("wanted uncertainty: %v", err)
	}
	if operation.Status != Awaiting || runsStore.value.State != runs.AwaitingDomainConfirmation || pagix.commands != 1 {
		t.Fatalf("operation=%#v state=%s commands=%d", operation, runsStore.value.State, pagix.commands)
	}
	// A missing/restored workflow checkpoint calls Start again. The durable active
	// operation wins; no authorization or domain command is reissued.
	replayed, err := service.Start(context.Background(), start)
	if err != nil || replayed.ID != operation.ID || pagix.commands != 1 || issuer.calls != 1 {
		t.Fatalf("restore replay=%#v commands=%d issues=%d err=%v", replayed, pagix.commands, issuer.calls, err)
	}
	if _, err := service.Reconcile(context.Background(), start.Scope, start.RunID); err != nil {
		t.Fatal(err)
	}
	if runsStore.value.State != runs.AwaitingDomainConfirmation {
		t.Fatal("effect lookup manufactured terminal state")
	}
	event := pagixclient.DomainEvent{MessageID: "event-01", OperationID: operation.ID, AuthorizationID: string(operation.AuthorizationID), Traceparent: start.Metadata.Traceparent, Outcome: pagixclient.DomainOutcome{OperationID: operation.ID, AuthorizationID: string(operation.AuthorizationID), Kind: pagixclient.OutcomeApplied, Recorded: true}}
	updated, accepted, err := service.HandleEvent(context.Background(), start.Scope, event)
	if err != nil || !accepted || updated.State != runs.Completed {
		t.Fatalf("event state=%s accepted=%v err=%v", updated.State, accepted, err)
	}
	record, _ := store.Get(context.Background(), start.Scope, operation.ID)
	if record.Status != Applied || !record.AuthorizationConsumed {
		t.Fatalf("final operation=%#v", record)
	}
	_, accepted, err = service.HandleEvent(context.Background(), start.Scope, event)
	if err != nil || accepted {
		t.Fatalf("duplicate event accepted=%v err=%v", accepted, err)
	}
}

func TestConflictConsumesAuthorizationAndRequiresRenewedReview(t *testing.T) {
	pagix := &fakePagix{}
	issuer := &fakeIssuer{}
	service, store, runsStore := coordinator(t, pagix, issuer)
	start := input(runsStore.value.Version)
	operation, err := service.Start(context.Background(), start)
	if err != nil {
		t.Fatal(err)
	}
	event := pagixclient.DomainEvent{MessageID: "event-conflict", OperationID: operation.ID, AuthorizationID: string(operation.AuthorizationID), Traceparent: start.Metadata.Traceparent, Outcome: pagixclient.DomainOutcome{OperationID: operation.ID, AuthorizationID: string(operation.AuthorizationID), Kind: pagixclient.OutcomeConflict, Recorded: true}}
	updated, _, err := service.HandleEvent(context.Background(), start.Scope, event)
	if err != nil || updated.State != runs.Conflict {
		t.Fatalf("conflict=%s err=%v", updated.State, err)
	}
	record, _ := store.Get(context.Background(), start.Scope, operation.ID)
	if !record.AuthorizationConsumed || record.Status != Conflicted {
		t.Fatalf("authorization not consumed: %#v", record)
	}
	start.ExpectedRunVersion = updated.Version
	if _, err := service.Start(context.Background(), start); err == nil {
		t.Fatal("repair committed without renewed review")
	}
}

func TestEveryGatewayPreconditionFailsBeforeDomainCommand(t *testing.T) {
	cases := map[string]func(*Start){"workspace": func(v *Start) { v.Scope.WorkspaceID = "" }, "project": func(v *Start) { v.Scope.ProjectID = "" }, "run": func(v *Start) { v.RunID = "" }, "version": func(v *Start) { v.ExpectedRunVersion = 0 }, "scope-binding": func(v *Start) { v.Authorization.WorkspaceID = "other" }, "revision": func(v *Start) { v.ExpectedRevision = "" }}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			pagix := &fakePagix{}
			issuer := &fakeIssuer{}
			service, _, runsStore := coordinator(t, pagix, issuer)
			start := input(runsStore.value.Version)
			mutate(&start)
			if _, err := service.Start(context.Background(), start); err == nil {
				t.Fatal("missing gateway proof accepted")
			}
			if pagix.commands != 0 {
				t.Fatalf("domain commands=%d", pagix.commands)
			}
		})
	}
	pagix := &fakePagix{}
	issuer := &fakeIssuer{err: problem.New(problem.CodeApplyAuthorizationDenied, "")}
	service, _, runsStore := coordinator(t, pagix, issuer)
	if _, err := service.Start(context.Background(), input(runsStore.value.Version)); err == nil || pagix.commands != 0 {
		t.Fatalf("failed issuance reached domain: commands=%d err=%v", pagix.commands, err)
	}
}

func TestCancellationDuringCommitReportsReconciliation(t *testing.T) {
	service, _, runsStore := coordinator(t, &fakePagix{}, &fakeIssuer{})
	start := input(runsStore.value.Version)
	_, _ = service.Start(context.Background(), start)
	err := service.Cancel(context.Background(), start.Scope, start.RunID)
	var details problem.Details
	if !errors.As(err, &details) || details.Code != string(problem.CodeCancellationUnreconciled) || runsStore.value.State == runs.Cancelled {
		t.Fatalf("cancel=%v state=%s", err, runsStore.value.State)
	}
}
