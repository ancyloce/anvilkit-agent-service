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
	reconciles int
	events     map[string]pagixclient.DomainEvent
	effect     pagixclient.DomainOutcome
	hasEffect  bool
}

func (p *fakePagix) Reconcile(context.Context, string, string) (pagixclient.DomainOutcome, bool, error) {
	p.lock.Lock()
	defer p.lock.Unlock()
	p.reconciles++
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

func TestStartRecordsIdentityBeforeIssuanceAndOnlyEventCompletes(t *testing.T) {
	pagix := &fakePagix{}
	issuer := &fakeIssuer{}
	service, store, runsStore := coordinator(t, pagix, issuer)
	start := input(runsStore.value.Version)
	operation, err := service.Start(context.Background(), start)
	// Nothing is uncertain on the first pass: a capability was issued, not an
	// effect attempted. Studio carries it to the domain owner, so the run waits
	// at the submit boundary for the authoritative outcome.
	if err != nil {
		t.Fatalf("issuance reported an effect it never attempted: %v", err)
	}
	if operation.Status != Awaiting || runsStore.value.State != runs.AwaitingDomainConfirmation {
		t.Fatalf("operation=%#v state=%s", operation, runsStore.value.State)
	}
	// A missing/restored workflow checkpoint calls Start again. The durable active
	// operation wins; no second authorization is issued.
	replayed, err := service.Start(context.Background(), start)
	if err != nil || replayed.ID != operation.ID || issuer.calls != 1 {
		t.Fatalf("restore replay=%#v issues=%d err=%v", replayed, issuer.calls, err)
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

func TestEveryGatewayPreconditionFailsBeforeAnyCapabilityIsIssued(t *testing.T) {
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
			// The capability is what leaves this service, so "nothing happened"
			// means nothing was issued. Asserting against a command count would
			// assert nothing at all: no command is sent on any path.
			if issuer.calls != 0 {
				t.Fatalf("a capability was issued past a failed precondition: issues=%d", issuer.calls)
			}
		})
	}
	pagix := &fakePagix{}
	issuer := &fakeIssuer{err: problem.New(problem.CodeApplyAuthorizationDenied, "")}
	service, _, runsStore := coordinator(t, pagix, issuer)
	if _, err := service.Start(context.Background(), input(runsStore.value.Version)); err == nil {
		t.Fatalf("a denied issuance was reported as success: err=%v", err)
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

type flakyFinalizeStore struct {
	*MemoryStore
	failOnce bool
}

func (s *flakyFinalizeStore) Finalize(ctx context.Context, scope Scope, id string, status Status, now time.Time) error {
	if s.failOnce {
		s.failOnce = false
		return errors.New("injected finalize failure")
	}
	return s.MemoryStore.Finalize(ctx, scope, id, status, now)
}

func TestDuplicateAuthoritativeEventRepairsPartialLocalFinalization(t *testing.T) {
	pagix := &fakePagix{}
	issuer := &fakeIssuer{}
	base := NewMemoryStore()
	store := &flakyFinalizeStore{MemoryStore: base, failOnce: true}
	runsStore := &runStore{value: approvedRun(t)}
	service, err := New(store, runsStore, issuer, pagix, &ids{}, fixedClock{})
	if err != nil {
		t.Fatal(err)
	}
	start := input(runsStore.value.Version)
	operation, err := service.Start(context.Background(), start)
	if err != nil {
		t.Fatal(err)
	}
	event := pagixclient.DomainEvent{MessageID: "event-repair", OperationID: operation.ID, AuthorizationID: string(operation.AuthorizationID), Traceparent: start.Metadata.Traceparent, Outcome: pagixclient.DomainOutcome{OperationID: operation.ID, AuthorizationID: string(operation.AuthorizationID), Kind: pagixclient.OutcomeApplied, Revision: "revision-2", EventID: "event-repair", Recorded: true}}
	if _, accepted, err := service.HandleEvent(context.Background(), start.Scope, event); err == nil || !accepted || runsStore.value.State != runs.Completed {
		t.Fatalf("first delivery accepted=%v state=%s err=%v", accepted, runsStore.value.State, err)
	}
	updated, accepted, err := service.HandleEvent(context.Background(), start.Scope, event)
	if err != nil || accepted || updated.State != runs.Completed {
		t.Fatalf("repair delivery accepted=%v state=%s err=%v", accepted, updated.State, err)
	}
	record, err := base.Get(context.Background(), start.Scope, operation.ID)
	if err != nil || record.Status != Applied || !record.AuthorizationConsumed {
		t.Fatalf("repaired operation=%#v err=%v", record, err)
	}
}

func TestRecordedOperationResumesAndIssuedOperationReconcilesFirst(t *testing.T) {
	for _, status := range []Status{Recorded, Issued} {
		t.Run(string(status), func(t *testing.T) {
			pagix := &fakePagix{}
			issuer := &fakeIssuer{}
			store := NewMemoryStore()
			runsStore := &runStore{value: approvedRun(t)}
			start := input(runsStore.value.Version)
			operation := Operation{Scope: start.Scope, RunID: start.RunID, ID: "operation-restart", AuthorizationID: "authorization-restart", AuthorizationJWS: "header.payload.signature", ActionDigest: "sha256:" + strings.Repeat("a", 64), ArtifactDigest: "sha256:" + strings.Repeat("b", 64), ExpectedRevision: start.ExpectedRevision, IdempotencyKey: start.Metadata.IdempotencyKey, RequestDigest: start.Metadata.RequestDigest, Status: status, CreatedAt: commitNow, UpdatedAt: commitNow}
			if status == Issued {
				var err error
				runsStore.value, _, err = runsStore.value.Apply(runs.Command{Kind: runs.Approve, Commit: runs.CommitProof{ApprovalRechecked: true, ArtifactEligible: true, ActionBindingExact: true, AuthorizationDurable: true, AuthorizationID: string(operation.AuthorizationID), DomainOperationID: operation.ID, ActionDigest: operation.ActionDigest, ArtifactDigest: operation.ArtifactDigest}})
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := store.Create(context.Background(), operation); err != nil {
				t.Fatal(err)
			}
			service, err := New(store, runsStore, issuer, pagix, &ids{}, fixedClock{})
			if err != nil {
				t.Fatal(err)
			}
			resumed, err := service.Start(context.Background(), start)
			if resumed.Status != Awaiting || runsStore.value.State != runs.AwaitingDomainConfirmation || issuer.calls != 0 {
				t.Fatalf("resumed=%#v state=%s issues=%d err=%v", resumed, runsStore.value.State, issuer.calls, err)
			}
			// A recorded operation has not yet had its capability handed out, so
			// resuming issues nothing new, asks nothing of the owner, and simply
			// takes the run to the boundary.
			if status == Recorded && (err != nil || pagix.reconciles != 0) {
				t.Fatalf("recorded reconciles=%d err=%v", pagix.reconciles, err)
			}
			if status == Issued {
				var details problem.Details
				// An issued operation's capability may already have been redeemed,
				// so the resume asks the authoritative owner what happened and
				// reports the outcome as unknown until it answers.
				if !errors.As(err, &details) || details.Code != string(problem.CodeDomainOutcomeUncertain) || pagix.reconciles != 1 {
					t.Fatalf("issued reconciles=%d err=%v", pagix.reconciles, err)
				}
			}
			changed := start
			changed.Metadata.RequestDigest = "sha256:" + strings.Repeat("d", 64)
			if _, err := service.Start(context.Background(), changed); err == nil {
				t.Fatal("changed restart identity accepted")
			}
		})
	}
}
