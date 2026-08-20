package runs

import (
	"errors"
	"reflect"
	"testing"

	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
)

func TestExactStateVocabulary(t *testing.T) {
	want := []State{"created", "preparing", "planning", "awaiting_input", "executing", "validating", "awaiting_review", "awaiting_approval", "committing", "awaiting_domain_confirmation", "conflict", "cancelling", "failed", "completed", "cancelled", "refused", "discarded"}
	if !reflect.DeepEqual(States(), want) || len(States()) != 17 {
		t.Fatalf("persisted states changed: %v", States())
	}
	for _, state := range States() {
		if state == "Reconnecting" || state == "reconnecting" {
			t.Fatal("Studio overlay became persisted state")
		}
	}
}

func TestEveryStateByEveryCommandMatchesExactMatrix(t *testing.T) {
	expected := map[State]map[CommandKind]State{
		Created:                    {BeginPreparation: Preparing, RequestCancellation: Cancelling},
		Preparing:                  {PreparationReady: Planning, RecordFailure: Failed, RecordRefusal: Refused, RequestCancellation: Cancelling},
		Planning:                   {RequestInput: AwaitingInput, BeginExecution: Executing, RecordFailure: Failed, RecordRefusal: Refused, RequestCancellation: Cancelling},
		AwaitingInput:              {AcceptInput: Planning, RecordFailure: Failed, RequestCancellation: Cancelling},
		Executing:                  {BeginValidation: Validating, RecordFailure: Failed, RequestCancellation: Cancelling},
		Validating:                 {SubmitForReview: AwaitingReview, RecordFailure: Failed, RecordRefusal: Refused, RequestCancellation: Cancelling},
		AwaitingReview:             {Revise: Executing, RequestApproval: AwaitingApproval, AcceptArtifact: Completed, RecordFailure: Failed, Discard: Discarded, RequestCancellation: Cancelling},
		AwaitingApproval:           {Approve: Committing, RejectApproval: AwaitingReview, RecordFailure: Failed, RequestCancellation: Cancelling},
		Committing:                 {BeginDomainConfirmation: AwaitingDomainConfirmation, RecordFailure: Failed},
		AwaitingDomainConfirmation: {ConfirmDomain: Completed, RecordDomainConflict: Conflict, RecordDomainRejection: Failed, RecordFailure: Failed},
		Conflict:                   {Rebase: Executing, RecordFailure: Failed, RequestCancellation: Cancelling},
		Cancelling:                 {ReconcileCancellation: Cancelled},
		Failed:                     {Retry: Preparing}, Completed: {}, Cancelled: {}, Refused: {}, Discarded: {},
	}
	proof := CommitProof{ApprovalRechecked: true, ArtifactEligible: true, ActionBindingExact: true, AuthorizationDurable: true, AuthorizationID: "authorization", DomainOperationID: "operation", ActionDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ArtifactDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
	validation := ValidationProof{Valid: true, BOMDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", SchemaDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", ValidatorVersion: "runtime-v1", CatalogDigest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}
	reconciliation := DomainReconciliation{Reconciled: true, DomainOperationID: "domain.operation"}
	for _, state := range States() {
		for _, kind := range Commands() {
			run := Run{ID: "run", State: state, Version: 7, ExecutionGeneration: 2}
			command := Command{Kind: kind, Commit: proof, Validation: validation, Reconciliation: reconciliation, RetryEligible: true}
			if kind == RecordDomainRejection {
				domainFailure := problem.New(problem.CodeDomainRejected, "")
				command.Failure = &domainFailure
			}
			updated, transition, err := run.Apply(command)
			wanted, allowed := expected[state][kind]
			if allowed {
				if err != nil || updated.State != wanted || updated.Version != 8 || transition.Current != wanted {
					t.Errorf("%s + %s: got state=%s transition=%#v err=%v want=%s", state, kind, updated.State, transition, err, wanted)
				}
			} else {
				if err == nil || !reflect.DeepEqual(updated, run) {
					t.Errorf("%s + %s unexpectedly mutated: %#v err=%v", state, kind, updated, err)
				}
			}
		}
	}
}

func TestAwaitingReviewRequiresPinnedValidationEvidence(t *testing.T) {
	run := Run{ID: "run", State: Validating, Version: 1, ExecutionGeneration: 1}
	if updated, _, err := run.Apply(Command{Kind: SubmitForReview}); err == nil || !reflect.DeepEqual(updated, run) {
		t.Fatal("unvalidated candidate reached review")
	}
	proof := ValidationProof{Valid: true, BOMDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", SchemaDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", ValidatorVersion: "runtime-v1", CatalogDigest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}
	updated, _, err := run.Apply(Command{Kind: SubmitForReview, Validation: proof})
	if err != nil || updated.State != AwaitingReview {
		t.Fatalf("validated candidate rejected: %#v %v", updated, err)
	}
}

func TestCommitRequiresAllImmutableProofs(t *testing.T) {
	base := CommitProof{ApprovalRechecked: true, ArtifactEligible: true, ActionBindingExact: true, AuthorizationDurable: true, AuthorizationID: "authorization", DomainOperationID: "operation", ActionDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ArtifactDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
	cases := []CommitProof{{}, func() CommitProof { value := base; value.ApprovalRechecked = false; return value }(), func() CommitProof { value := base; value.ArtifactEligible = false; return value }(), func() CommitProof { value := base; value.ActionBindingExact = false; return value }(), func() CommitProof { value := base; value.AuthorizationDurable = false; return value }(), func() CommitProof { value := base; value.AuthorizationID = ""; return value }(), func() CommitProof { value := base; value.DomainOperationID = ""; return value }(), func() CommitProof { value := base; value.ActionDigest = ""; return value }(), func() CommitProof { value := base; value.ArtifactDigest = ""; return value }()}
	run := Run{ID: "run", State: AwaitingApproval, Version: 1, ExecutionGeneration: 1}
	for index, proof := range cases {
		updated, _, err := run.Apply(Command{Kind: Approve, Commit: proof})
		if err == nil || !reflect.DeepEqual(updated, run) {
			t.Fatalf("case %d entered commit: %#v %v", index, updated, err)
		}
	}
	updated, _, err := run.Apply(Command{Kind: Approve, Commit: base})
	if err != nil || updated.State != Committing {
		t.Fatalf("valid proof rejected: %#v %v", updated, err)
	}
}

func TestDomainRejectionMustBeStableAndNonRetryable(t *testing.T) {
	run := Run{ID: "run", State: AwaitingDomainConfirmation, Version: 4, ExecutionGeneration: 1}
	retryable := problem.New(problem.CodeProviderUnavailable, "")
	if updated, _, err := run.Apply(Command{Kind: RecordDomainRejection, Failure: &retryable}); err == nil || !reflect.DeepEqual(updated, run) {
		t.Fatal("retryable domain rejection mutated the run")
	}
	domain := problem.New(problem.CodeDomainRejected, "")
	updated, _, err := run.Apply(Command{Kind: RecordDomainRejection, Failure: &domain})
	if err != nil || updated.State != Failed || updated.Problem == nil || updated.Problem.Retryability != "never" {
		t.Fatalf("stable domain rejection failed: %#v %v", updated, err)
	}
}

func TestTerminalAndRetryProtections(t *testing.T) {
	for _, state := range []State{Completed, Cancelled, Refused, Discarded} {
		run := Run{ID: "run", State: state, Version: 3, ExecutionGeneration: 2}
		for _, command := range Commands() {
			updated, _, err := run.Apply(Command{Kind: command, RetryEligible: true})
			if err == nil || !reflect.DeepEqual(updated, run) {
				t.Fatalf("terminal %s accepted %s", state, command)
			}
		}
	}
	run := Run{ID: "run", State: Failed, Version: 3, ExecutionGeneration: 2, Problem: ptr(problem.New(problem.CodeProviderUnavailable, ""))}
	updated, _, err := run.Apply(Command{Kind: Retry})
	if err == nil || !reflect.DeepEqual(updated, run) {
		t.Fatal("ineligible retry mutated failed run")
	}
	updated, _, err = run.Apply(Command{Kind: Retry, RetryEligible: true})
	if err != nil || updated.ExecutionGeneration != 3 || updated.Problem != nil {
		t.Fatalf("eligible retry failed: %#v %v", updated, err)
	}
}

func ptr(value problem.Details) *problem.Details { return &value }

// The failure edge out of the submit boundary exists so a run whose governed
// effect may already have happened is never stranded — but it must never be
// usable on belief alone. Only the authoritative owner's answer that no effect
// exists makes it legal.
func TestFailingOutOfTheSubmitBoundaryRequiresReconciliationProof(t *testing.T) {
	run := Run{ID: "run", State: AwaitingDomainConfirmation, Version: 9, ExecutionGeneration: 1}
	for _, test := range []struct {
		name  string
		proof DomainReconciliation
	}{
		{name: "no proof at all", proof: DomainReconciliation{}},
		{name: "owner never consulted", proof: DomainReconciliation{EffectApplied: false, DomainOperationID: "domain.operation"}},
		{name: "the effect was applied", proof: DomainReconciliation{Reconciled: true, EffectApplied: true, DomainOperationID: "domain.operation"}},
		{name: "no operation identity", proof: DomainReconciliation{Reconciled: true}},
	} {
		t.Run(test.name, func(t *testing.T) {
			failure := problem.New(problem.CodeDomainOutcomeUncertain, "")
			updated, _, err := run.Apply(Command{Kind: RecordFailure, Failure: &failure, Reconciliation: test.proof})
			var details problem.Details
			if err == nil || !reflect.DeepEqual(updated, run) {
				t.Fatalf("an unproven failure left the submit boundary: %#v err=%v", updated, err)
			}
			if !errorsAs(err, &details) || details.Code != string(problem.CodeCommitProofMissing) {
				t.Fatalf("error = %v, want %s", err, problem.CodeCommitProofMissing)
			}
		})
	}
	failure := problem.New(problem.CodeDomainOutcomeUncertain, "")
	updated, transition, err := run.Apply(Command{Kind: RecordFailure, Failure: &failure, Reconciliation: DomainReconciliation{Reconciled: true, DomainOperationID: "domain.operation"}})
	if err != nil || updated.State != Failed || transition.Current != Failed {
		t.Fatalf("a reconciled failure was refused: %#v err=%v", updated, err)
	}
}

// Committing is short of the submit boundary: nothing can have been caused
// yet, so the run may fail there without consulting anyone.
func TestFailingBeforeTheSubmitBoundaryNeedsNoReconciliation(t *testing.T) {
	run := Run{ID: "run", State: Committing, Version: 9, ExecutionGeneration: 1}
	failure := problem.New(problem.CodeAuthorityStale, "")
	updated, _, err := run.Apply(Command{Kind: RecordFailure, Failure: &failure})
	if err != nil || updated.State != Failed {
		t.Fatalf("a run stopped before submission could not record its failure: %#v err=%v", updated, err)
	}
}

func errorsAs(err error, target *problem.Details) bool {
	return errors.As(err, target)
}
