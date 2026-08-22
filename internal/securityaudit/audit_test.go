package securityaudit

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/journal"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
)

type testTime struct {
	value time.Time
	err   error
}

func (t *testTime) Now(context.Context) (time.Time, error) { return t.value, t.err }

type localTime struct{ value time.Time }

func (t *localTime) Now() time.Time { return t.value }

func auditRecord(id string) Record {
	return Record{ID: id, Action: "epoch-change", Actor: "operator", Workload: "restore-controller", Reason: "PITR", Ticket: "SEC-1", NewDigest: "sha256:" + strings.Repeat("a", 64), Traceparent: "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01", Scope: Scope{WorkspaceID: "workspace", ProjectID: "project", ResourceID: "epoch"}}
}

func TestProtectedAuditFailureBlocksPrivilegedMutationButTelemetryDoesNotAuthorize(t *testing.T) {
	now := time.Unix(700, 0).UTC()
	source, local := &testTime{value: now}, &localTime{value: now}
	clock, _ := NewAuthoritativeClock(source, local, time.Second)
	sink := &MemorySink{}
	alerts := &MemoryAlerts{}
	service, _ := NewService(sink, clock, alerts, journal.NewMemoryStore())
	sink.SetUnavailable(true)
	mutated := false
	if err := service.PrivilegedMutation(context.Background(), auditRecord("audit-1"), func(context.Context) error { mutated = true; return nil }); err == nil || mutated {
		t.Fatal("mutation ran without protected audit")
	}
	// Ordinary telemetry has no input to the authorization decision. Restoring
	// protected audit availability is sufficient even if telemetry is absent.
	sink.SetUnavailable(false)
	if err := service.PrivilegedMutation(context.Background(), auditRecord("audit-1"), func(context.Context) error { mutated = true; return nil }); err != nil || !mutated {
		t.Fatalf("audited mutation failed: %v", err)
	}
}

func TestPrivilegedMutationCannotAcknowledgeWithoutReceiptJournal(t *testing.T) {
	now := time.Unix(700, 0).UTC()
	clock, _ := NewAuthoritativeClock(&testTime{value: now}, &localTime{value: now}, time.Second)
	receipts := journal.NewMemoryStore()
	receipts.SetAvailable(false)
	service, _ := NewService(&MemorySink{}, clock, &MemoryAlerts{}, receipts)
	mutated := false
	if err := service.PrivilegedMutation(context.Background(), auditRecord("audit-journal"), func(context.Context) error { mutated = true; return nil }); err == nil || !mutated {
		t.Fatal("privileged mutation did not return an unknown/unacknowledged outcome after journal failure")
	}
}

func TestTamperDetectionAlertsAndAuditReadIsAudited(t *testing.T) {
	now := time.Unix(700, 0).UTC()
	clock, _ := NewAuthoritativeClock(&testTime{value: now}, &localTime{value: now}, time.Second)
	sink := &MemorySink{}
	alerts := &MemoryAlerts{}
	service, _ := NewService(sink, clock, alerts, journal.NewMemoryStore())
	if err := service.PrivilegedMutation(context.Background(), auditRecord("audit-1"), func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	access := auditRecord("audit-access-1")
	access.NewDigest = "sha256:" + strings.Repeat("b", 64)
	records, err := service.Read(context.Background(), access)
	if err != nil || len(records) != 4 || records[2].Action != "audit-access" || records[3].Outcome != "applied" {
		t.Fatalf("records=%#v err=%v", records, err)
	}
	sink.Corrupt(0)
	if err := service.Verify(context.Background()); err == nil || len(alerts.Values) != 1 {
		t.Fatalf("tamper err=%v alerts=%#v", err, alerts.Values)
	}
}

func TestAuthoritativeTimeSkewRollbackAndOutageFailClosed(t *testing.T) {
	now := time.Unix(700, 0).UTC()
	source, local := &testTime{value: now}, &localTime{value: now}
	clock, _ := NewAuthoritativeClock(source, local, time.Second)
	if err := clock.ValidateWindow(context.Background(), now.Add(-time.Minute), now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	source.value = now.Add(-time.Second)
	local.value = source.value
	if _, err := clock.Now(context.Background()); err == nil {
		t.Fatal("clock rollback accepted")
	}
	source.value = now.Add(10 * time.Second)
	local.value = now
	if _, err := clock.Now(context.Background()); err == nil {
		t.Fatal("excess skew accepted")
	}
	source.err = errors.New("time service down")
	if _, err := clock.Now(context.Background()); err == nil {
		t.Fatal("time outage accepted")
	}
}

func TestEveryPrivilegedActionFamilyProducesBoundRecord(t *testing.T) {
	now := time.Unix(700, 0).UTC()
	clock, _ := NewAuthoritativeClock(&testTime{value: now}, &localTime{value: now}, time.Second)
	sink := &MemorySink{}
	service, _ := NewService(sink, clock, &MemoryAlerts{}, journal.NewMemoryStore())
	actions := []string{"epoch-change", "restore-stage", "policy-disable", "key-revocation", "authorization-issuance", "deletion-legal-hold", "release-exception"}
	for index, action := range actions {
		record := auditRecord("audit-family-" + action)
		record.Action = action
		if err := service.PrivilegedMutation(context.Background(), record, func(context.Context) error { return nil }); err != nil {
			t.Fatalf("action %d %s: %v", index, action, err)
		}
	}
	records, err := sink.Read(context.Background())
	if err != nil || len(records) != 2*len(actions) {
		t.Fatalf("records=%#v err=%v", records, err)
	}
	for _, record := range records {
		if record.UTC.IsZero() || record.Digest == "" || record.Outcome == "" || record.Actor == "" || record.Reason == "" || record.Traceparent == "" || record.Scope.ResourceID == "" {
			t.Fatalf("unbound audit record: %#v", record)
		}
	}
}

// A refusal the target decided is a decision: it is recorded as the outcome,
// and a retry is told the same refusal without touching the target again.
func TestARefusedMutationIsRecordedAndNeverReapplied(t *testing.T) {
	now := time.Unix(700, 0).UTC()
	clock, _ := NewAuthoritativeClock(&testTime{value: now}, &localTime{value: now}, time.Second)
	sink := &MemorySink{}
	service, _ := NewService(sink, clock, &MemoryAlerts{}, journal.NewMemoryStore())
	calls := 0
	record := auditRecord("audit-refused")
	refusal := problem.New(problem.CodeVersionConflict, "")
	if err := service.PrivilegedMutation(context.Background(), record, func(context.Context) error { calls++; return refusal }); err == nil {
		t.Fatal("refused target mutation reported success")
	}
	records, _ := sink.Read(context.Background())
	if len(records) != 2 || records[1].Outcome != "failed" || calls != 1 {
		t.Fatalf("records=%#v calls=%d", records, calls)
	}
	// The refusal is closed on the record, and the record carries what it
	// decided: a retry is answered with the governed result the mutation
	// actually produced, not merely with the fact that something was refused.
	err := service.PrivilegedMutation(context.Background(), record, func(context.Context) error { calls++; return nil })
	assertGoverned(t, err, problem.CodeVersionConflict)
	if calls != 1 {
		t.Fatalf("a closed refusal was reopened: calls=%d", calls)
	}
}

// assertGoverned reports whether an error carries exactly the governed code.
func assertGoverned(t *testing.T, err error, code problem.Code) {
	t.Helper()
	var details problem.Details
	if !errors.As(err, &details) || details.Code != string(code) {
		t.Fatalf("err=%v, want the governed result %s", err, code)
	}
}

// A receipt that could not be appended is the one interruption that used to
// lose the decision. The governed operation had already refused, the refusal
// was already recorded, and the retry — finding an outcome it must not
// re-apply — answered with a generic refusal instead of the result the
// operation reached. The caller was told its request was refused and never
// told why, so a version precondition that failed was indistinguishable from
// an access denial.
func TestARetryAfterAnUnacknowledgedRefusalReturnsTheOriginalGovernedResult(t *testing.T) {
	now := time.Unix(700, 0).UTC()
	clock, _ := NewAuthoritativeClock(&testTime{value: now}, &localTime{value: now}, time.Second)
	sink := &MemorySink{}
	receipts := journal.NewMemoryStore()
	service, _ := NewService(sink, clock, &MemoryAlerts{}, receipts)
	record := auditRecord("audit-unacknowledged-refusal")
	calls := 0
	refused := func(context.Context) error { calls++; return problem.New(problem.CodeArtifactAccessDenied, "") }

	receipts.SetAvailable(false)
	err := service.PrivilegedMutation(context.Background(), record, refused)
	if err == nil || calls != 1 {
		t.Fatalf("the unacknowledged decision reported success: calls=%d err=%v", calls, err)
	}
	// The receipt is what failed, so that is what the first attempt reports.
	var details problem.Details
	if errors.As(err, &details) && details.Code == string(problem.CodeArtifactAccessDenied) {
		t.Fatal("an unacknowledged decision was reported as if it were closed")
	}

	receipts.SetAvailable(true)
	err = service.PrivilegedMutation(context.Background(), record, refused)
	assertGoverned(t, err, problem.CodeArtifactAccessDenied)
	if calls != 1 {
		t.Fatalf("the retry re-applied a refused mutation: calls=%d", calls)
	}
	records, _ := sink.Read(context.Background())
	if len(records) != 2 || records[1].Outcome != "failed" || records[1].Result != string(problem.CodeArtifactAccessDenied) {
		t.Fatalf("the refusal was duplicated or its result was lost: %#v", records)
	}
}

// Concurrent attempts at one decision converge: the mutation is idempotent, so
// whichever attempts reach it produce the same governed result, exactly one
// outcome is recorded, and every caller is answered with that same result.
func TestConcurrentRetriesConvergeOnOneRecordedResult(t *testing.T) {
	now := time.Unix(700, 0).UTC()
	clock, _ := NewAuthoritativeClock(&testTime{value: now}, &localTime{value: now}, time.Second)
	sink := &MemorySink{}
	service, _ := NewService(sink, clock, &MemoryAlerts{}, journal.NewMemoryStore())
	record := auditRecord("audit-concurrent-refusal")
	const attempts = 8
	results := make([]error, attempts)
	start := make(chan struct{})
	var group sync.WaitGroup
	for index := range attempts {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			results[index] = service.PrivilegedMutation(context.Background(), record, func(context.Context) error {
				return problem.New(problem.CodeVersionConflict, "")
			})
		}()
	}
	close(start)
	group.Wait()
	for _, err := range results {
		assertGoverned(t, err, problem.CodeVersionConflict)
	}
	records, _ := sink.Read(context.Background())
	if len(records) != 2 || records[0].Outcome != "authorized-to-apply" || records[1].Outcome != "failed" {
		t.Fatalf("concurrent attempts duplicated the decision: %#v", records)
	}
}

// hidingSink answers one identity as absent however many times it is looked
// up, which is the durable state a read that raced an append leaves an attempt
// holding: the outcome exists, and this attempt cannot see it.
type hidingSink struct {
	*MemorySink
	hidden string
}

func (s *hidingSink) Lookup(ctx context.Context, id string) (Record, bool, error) {
	if id == s.hidden {
		return Record{}, false, nil
	}
	return s.MemorySink.Lookup(ctx, id)
}

// An attempt that cannot see the recorded outcome still cannot overwrite it.
// It runs the mutation, reaches a different governed result, and is told the
// decision is already closed with another one — the recorded result stands
// untouched and the conflict is reported rather than silently resolved.
func TestAConflictingRetryCannotOverwriteTheRecordedResult(t *testing.T) {
	now := time.Unix(700, 0).UTC()
	clock, _ := NewAuthoritativeClock(&testTime{value: now}, &localTime{value: now}, time.Second)
	memory := &MemorySink{}
	service, _ := NewService(memory, clock, &MemoryAlerts{}, journal.NewMemoryStore())
	record := auditRecord("audit-conflicting-retry")
	assertGoverned(t, service.PrivilegedMutation(context.Background(), record, func(context.Context) error {
		return problem.New(problem.CodeVersionConflict, "")
	}), problem.CodeVersionConflict)

	blind, _ := NewService(&hidingSink{MemorySink: memory, hidden: record.ID + ":outcome"}, clock, &MemoryAlerts{}, journal.NewMemoryStore())
	err := blind.PrivilegedMutation(context.Background(), record, func(context.Context) error {
		return problem.New(problem.CodeArtifactAccessDenied, "")
	})
	assertGoverned(t, err, problem.CodeIdempotencyConflict)
	records, _ := memory.Read(context.Background())
	if len(records) != 2 || records[1].Result != string(problem.CodeVersionConflict) {
		t.Fatalf("the recorded result was altered or duplicated: %#v", records)
	}
}

// A record written before refusals carried their governed result still closes
// its decision: it is reported as a refusal whose result cannot be recovered,
// never as a success.
func TestARecordedRefusalWithoutAResultStillClosesTheDecision(t *testing.T) {
	now := time.Unix(700, 0).UTC()
	clock, _ := NewAuthoritativeClock(&testTime{value: now}, &localTime{value: now}, time.Second)
	sink := &MemorySink{}
	service, _ := NewService(sink, clock, &MemoryAlerts{}, journal.NewMemoryStore())
	record := auditRecord("audit-resultless-refusal")
	authorized := record
	authorized.UTC, authorized.Outcome = now, "authorized-to-apply"
	if _, _, err := sink.Append(context.Background(), authorized); err != nil {
		t.Fatal(err)
	}
	outcome := authorized
	outcome.ID, outcome.Outcome = record.ID+":outcome", "failed"
	if _, _, err := sink.Append(context.Background(), outcome); err != nil {
		t.Fatal(err)
	}
	var closed RefusedDecision
	err := service.PrivilegedMutation(context.Background(), record, func(context.Context) error {
		t.Error("a closed refusal was reopened")
		return nil
	})
	if !errors.As(err, &closed) || closed.RecordID != record.ID {
		t.Fatalf("err=%v, want a closed refusal naming %s", err, record.ID)
	}
}

// A failure that decided nothing closes nothing. An unreachable target says
// only that the attempt did not finish, and an outcome written on that guess
// would be the answer every later retry received — so no outcome is recorded
// and the next attempt is free to find out for itself.
func TestAnIndeterminateFailureLeavesTheDecisionOpen(t *testing.T) {
	now := time.Unix(700, 0).UTC()
	clock, _ := NewAuthoritativeClock(&testTime{value: now}, &localTime{value: now}, time.Second)
	sink := &MemorySink{}
	service, _ := NewService(sink, clock, &MemoryAlerts{}, journal.NewMemoryStore())
	calls := 0
	record := auditRecord("audit-indeterminate")
	if err := service.PrivilegedMutation(context.Background(), record, func(context.Context) error { calls++; return errors.New("target unreachable") }); err == nil {
		t.Fatal("an unreachable target reported success")
	}
	records, _ := sink.Read(context.Background())
	if len(records) != 1 || records[0].Outcome != "authorized-to-apply" {
		t.Fatalf("an indeterminate failure closed the decision: %#v", records)
	}
	if err := service.PrivilegedMutation(context.Background(), record, func(context.Context) error { calls++; return nil }); err != nil || calls != 2 {
		t.Fatalf("the retry could not apply the mutation: calls=%d err=%v", calls, err)
	}
	records, _ = sink.Read(context.Background())
	if len(records) != 2 || records[1].Outcome != "applied" {
		t.Fatalf("the applied outcome was not recorded: %#v", records)
	}
}

// A privileged mutation can be interrupted between any two of its steps, and
// the retry has to resume from wherever it stopped. Each case below is the
// durable state one interruption leaves behind, written into the sink exactly
// as the interrupted attempt would have left it, and then handed to a fresh
// attempt at the same decision.
//
// The first case is the one that used to lose the mutation outright: a
// recorded authorization was read as a duplicate decision and refused, so the
// change it authorized could never be made by anyone, ever.
func TestAnInterruptedPrivilegedMutationResumesWhereItStopped(t *testing.T) {
	now := time.Unix(700, 0).UTC()
	authorized := auditRecord("audit-resumed")
	authorized.UTC = now
	authorized.Outcome = "authorized-to-apply"
	applied := authorized
	applied.ID = authorized.ID + ":outcome"
	applied.Outcome = "applied"

	for _, testCase := range []struct {
		name string
		// recorded is what the interrupted attempt left in the protected audit.
		recorded []Record
		// effectApplied is whether the change itself already landed.
		effectApplied bool
		// wantCalls is how many times the retry must run the mutation.
		wantCalls int
	}{
		{
			name:     "after the authorization was recorded, before the mutation",
			recorded: []Record{authorized}, effectApplied: false, wantCalls: 1,
		},
		{
			name:     "after the mutation, before the outcome was recorded",
			recorded: []Record{authorized}, effectApplied: true, wantCalls: 1,
		},
		{
			name:     "after the outcome was recorded, before the receipt",
			recorded: []Record{authorized, applied}, effectApplied: true, wantCalls: 0,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			clock, _ := NewAuthoritativeClock(&testTime{value: now}, &localTime{value: now}, time.Second)
			sink := &MemorySink{}
			for _, record := range testCase.recorded {
				if _, inserted, err := sink.Append(context.Background(), record); err != nil || !inserted {
					t.Fatalf("seed the interrupted state: inserted=%v err=%v", inserted, err)
				}
			}
			receipts := journal.NewMemoryStore()
			service, _ := NewService(sink, clock, &MemoryAlerts{}, receipts)
			// The change is idempotent under its own decision identity, which
			// is what every mutation carried through the protected audit is
			// required to be: it applies once and recognises its own work.
			effect := testCase.effectApplied
			calls := 0
			if err := service.PrivilegedMutation(context.Background(), auditRecord("audit-resumed"), func(context.Context) error {
				calls++
				effect = true
				return nil
			}); err != nil {
				t.Fatalf("the retry did not converge: %v", err)
			}
			if calls != testCase.wantCalls {
				t.Fatalf("mutation calls=%d, want %d", calls, testCase.wantCalls)
			}
			if !effect {
				t.Fatal("the mutation was lost: it is neither applied nor re-applied")
			}
			records, _ := sink.Read(context.Background())
			if len(records) != 2 || records[0].ID != authorized.ID || records[1].ID != applied.ID || records[1].Outcome != "applied" {
				t.Fatalf("the decision did not close exactly once: %#v", records)
			}
			facts, err := receipts.List(context.Background())
			if err != nil || len(facts) != 1 {
				t.Fatalf("receipts=%d err=%v, want the decision's one receipt", len(facts), err)
			}
		})
	}
}

// A different decision claiming an identity that is already taken is still a
// conflict. Resuming is for the same decision; it is not a way for one change
// to inherit another's recorded authorization.
func TestADifferentDecisionCannotResumeARecordedOne(t *testing.T) {
	now := time.Unix(700, 0).UTC()
	clock, _ := NewAuthoritativeClock(&testTime{value: now}, &localTime{value: now}, time.Second)
	sink := &MemorySink{}
	service, _ := NewService(sink, clock, &MemoryAlerts{}, journal.NewMemoryStore())
	if err := service.PrivilegedMutation(context.Background(), auditRecord("audit-claimed"), func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	other := auditRecord("audit-claimed")
	other.Reason = "a different reason for a different decision"
	mutated := false
	var details problem.Details
	err := service.PrivilegedMutation(context.Background(), other, func(context.Context) error { mutated = true; return nil })
	if !errors.As(err, &details) || details.Code != string(problem.CodeIdempotencyConflict) || mutated {
		t.Fatalf("a foreign decision resumed a recorded one: mutated=%v err=%v", mutated, err)
	}
}

func TestAuditBindingAndStrictExpiryValidation(t *testing.T) {
	now := time.Unix(700, 0).UTC()
	clock, _ := NewAuthoritativeClock(&testTime{value: now}, &localTime{value: now}, time.Second)
	service, _ := NewService(&MemorySink{}, clock, &MemoryAlerts{}, journal.NewMemoryStore())
	invalid := auditRecord("audit-invalid")
	invalid.Scope.WorkspaceID = ""
	if err := service.PrivilegedMutation(context.Background(), invalid, func(context.Context) error { return nil }); err == nil {
		t.Fatal("unscoped audit record accepted")
	}
	if err := clock.ValidateWindow(context.Background(), now.Add(-time.Minute), now); err == nil {
		t.Fatal("expiry was extended by skew allowance")
	}
}

// A decision can outlive the process that authorized it. What a successor may
// do with it is bounded: it finishes what is recorded, it proves the record is
// the decision it means to finish, and it never authorizes anything itself.
func TestResumingADecisionAdoptsItRatherThanAuthorizingASecondOne(t *testing.T) {
	ctx := context.Background()

	t.Run("a successor finishes an authorized decision under its recorded terms", func(t *testing.T) {
		service, sink := auditService(t)
		decision := authorizedDecision("decision.resume.applied")
		// The first process authorized the decision and stopped before its
		// outcome could be recorded.
		if err := service.PrivilegedMutation(ctx, decision, func(context.Context) error {
			return errStoppedHere
		}); !errors.Is(err, errStoppedHere) {
			t.Fatalf("the interruption did not land where it was meant to: %v", err)
		}
		var adopted Record
		if err := service.ResumeMutation(ctx, decision.ID, admitAnything, func(_ context.Context, record Record) error {
			adopted = record
			return nil
		}); err != nil {
			t.Fatalf("a successor could not finish an authorized decision: %v", err)
		}
		// The successor acted under the original decision's terms, not its own.
		if adopted.Actor != decision.Actor || adopted.Reason != decision.Reason || adopted.Ticket != decision.Ticket {
			t.Fatalf("the successor did not adopt the recorded decision: %#v", adopted)
		}
		// Exactly two records stand: the original authorization and its
		// outcome. A successor that authorized its own decision would have
		// added a third, or conflicted with the first.
		outcome, found, err := sink.Lookup(ctx, decision.ID+":outcome")
		if err != nil || !found {
			t.Fatalf("the outcome was not recorded: found=%v err=%v", found, err)
		}
		if outcome.Outcome != "applied" || outcome.Actor != decision.Actor {
			t.Fatalf("the outcome does not belong to the original decision: %#v", outcome)
		}
		authorization, _, err := sink.Lookup(ctx, decision.ID)
		if err != nil {
			t.Fatal(err)
		}
		if authorization.Actor != decision.Actor || authorization.Reason != decision.Reason {
			t.Fatalf("the recorded authorization was rewritten: %#v", authorization)
		}
	})

	t.Run("a successor cannot resume what was never authorized", func(t *testing.T) {
		service, _ := auditService(t)
		err := service.ResumeMutation(ctx, "decision.resume.absent", admitAnything, func(context.Context, Record) error {
			t.Fatal("a mutation ran under no recorded decision")
			return nil
		})
		var unrecorded UnrecordedDecision
		if !errors.As(err, &unrecorded) || unrecorded.RecordID != "decision.resume.absent" {
			t.Fatalf("an unrecorded decision was resumed: %v", err)
		}
	})

	t.Run("a successor must recognise the decision it is finishing", func(t *testing.T) {
		service, _ := auditService(t)
		decision := authorizedDecision("decision.resume.unrelated")
		if err := service.PrivilegedMutation(ctx, decision, func(context.Context) error { return nil }); err != nil {
			t.Fatal(err)
		}
		refused := errors.New("this is not the decision I am finishing")
		err := service.ResumeMutation(ctx, decision.ID, func(Record) error { return refused }, func(context.Context, Record) error {
			t.Fatal("a mutation ran under a decision the successor refused")
			return nil
		})
		// The admission is answered even though the decision is already
		// closed and there was nothing left to apply: a closed decision is
		// exactly where a silent success would otherwise hide.
		if !errors.Is(err, refused) {
			t.Fatalf("an unrecognised decision was adopted: %v", err)
		}
	})
}

// errStoppedHere is an indeterminate failure: it carries no governed problem
// details, so no outcome is recorded and the decision stays open, which is
// what a crash leaves behind.
var errStoppedHere = errors.New("the process stopped here")

func admitAnything(Record) error { return nil }

func authorizedDecision(id string) Record {
	return Record{
		ID:          id,
		Action:      "artifact-deleted",
		Actor:       "operator-01",
		Workload:    "agent-service.artifact-custody",
		Reason:      "court-ordered-destruction",
		Ticket:      "change-0007",
		OldDigest:   "sha256:" + strings.Repeat("a", 64),
		Traceparent: "00-" + strings.Repeat("1", 32) + "-" + strings.Repeat("2", 16) + "-01",
		Scope:       Scope{WorkspaceID: "workspace-01", ProjectID: "project-01", ResourceID: "artifact-01"},
	}
}

// auditService is the real protected audit protocol over an in-memory sink and
// a fixed authoritative clock.
func auditService(t *testing.T) (*Service, *MemorySink) {
	t.Helper()
	now := time.Unix(700, 0).UTC()
	clock, err := NewAuthoritativeClock(&testTime{value: now}, &localTime{value: now}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	sink := &MemorySink{}
	service, err := NewService(sink, clock, &MemoryAlerts{}, journal.NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	return service, sink
}
