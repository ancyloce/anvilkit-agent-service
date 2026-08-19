// Package runs owns the pure AgentRun aggregate and exact persisted lifecycle.
package runs

import (
	"fmt"
	"strings"

	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
)

type ID string
type State string

const (
	Created                    State = "created"
	Preparing                  State = "preparing"
	Planning                   State = "planning"
	AwaitingInput              State = "awaiting_input"
	Executing                  State = "executing"
	Validating                 State = "validating"
	AwaitingReview             State = "awaiting_review"
	AwaitingApproval           State = "awaiting_approval"
	Committing                 State = "committing"
	AwaitingDomainConfirmation State = "awaiting_domain_confirmation"
	Conflict                   State = "conflict"
	Cancelling                 State = "cancelling"
	Failed                     State = "failed"
	Completed                  State = "completed"
	Cancelled                  State = "cancelled"
	Refused                    State = "refused"
	Discarded                  State = "discarded"
)

func States() []State {
	return []State{Created, Preparing, Planning, AwaitingInput, Executing, Validating, AwaitingReview, AwaitingApproval, Committing, AwaitingDomainConfirmation, Conflict, Cancelling, Failed, Completed, Cancelled, Refused, Discarded}
}

type CommandKind string

const (
	BeginPreparation        CommandKind = "begin-preparation"
	PreparationReady        CommandKind = "preparation-ready"
	RequestInput            CommandKind = "request-input"
	AcceptInput             CommandKind = "accept-input"
	BeginExecution          CommandKind = "begin-execution"
	BeginValidation         CommandKind = "begin-validation"
	SubmitForReview         CommandKind = "submit-for-review"
	Revise                  CommandKind = "revise"
	RequestApproval         CommandKind = "request-approval"
	AcceptArtifact          CommandKind = "accept-artifact"
	Approve                 CommandKind = "approve"
	RejectApproval          CommandKind = "reject-approval"
	BeginDomainConfirmation CommandKind = "begin-domain-confirmation"
	ConfirmDomain           CommandKind = "confirm-domain"
	RecordDomainConflict    CommandKind = "record-domain-conflict"
	RecordDomainRejection   CommandKind = "record-domain-rejection"
	Rebase                  CommandKind = "rebase"
	RequestCancellation     CommandKind = "request-cancellation"
	ReconcileCancellation   CommandKind = "reconcile-cancellation"
	RecordFailure           CommandKind = "record-failure"
	RecordRefusal           CommandKind = "record-refusal"
	Retry                   CommandKind = "retry"
	Discard                 CommandKind = "discard"
)

func Commands() []CommandKind {
	return []CommandKind{BeginPreparation, PreparationReady, RequestInput, AcceptInput, BeginExecution, BeginValidation, SubmitForReview, Revise, RequestApproval, AcceptArtifact, Approve, RejectApproval, BeginDomainConfirmation, ConfirmDomain, RecordDomainConflict, RecordDomainRejection, Rebase, RequestCancellation, ReconcileCancellation, RecordFailure, RecordRefusal, Retry, Discard}
}

type CommitProof struct {
	ApprovalRechecked, ArtifactEligible, ActionBindingExact, AuthorizationDurable bool
	AuthorizationID, DomainOperationID, ActionDigest, ArtifactDigest              string
}
type ValidationProof struct {
	Valid                                                    bool
	BOMDigest, SchemaDigest, ValidatorVersion, CatalogDigest string
}

func (p ValidationProof) Validate() error {
	if !p.Valid || !validDigest(p.BOMDigest) || !validDigest(p.SchemaDigest) || p.ValidatorVersion == "" || !validDigest(p.CatalogDigest) {
		return fmt.Errorf("pinned validation proof is incomplete")
	}
	return nil
}

func (p CommitProof) Validate() error {
	if !p.ApprovalRechecked || !p.ArtifactEligible || !p.ActionBindingExact || !p.AuthorizationDurable || p.AuthorizationID == "" || len(p.AuthorizationID) > 128 || p.DomainOperationID == "" || len(p.DomainOperationID) > 128 || !validDigest(p.ActionDigest) || !validDigest(p.ArtifactDigest) {
		return fmt.Errorf("commit proof is incomplete")
	}
	return nil
}

type Command struct {
	Kind          CommandKind
	Commit        CommitProof
	Validation    ValidationProof
	RetryEligible bool
	Failure       *problem.Details
	Traceparent   string
}
type Run struct {
	ID                  ID
	State               State
	Version             uint64
	ExecutionGeneration uint64
	Problem             *problem.Details
}
type Transition struct {
	Previous, Current            State
	Version, ExecutionGeneration uint64
	EventType                    string
}

func New(id ID) (Run, error) {
	if id == "" {
		return Run{}, fmt.Errorf("run ID is required")
	}
	return Run{ID: id, State: Created, Version: 1, ExecutionGeneration: 1}, nil
}
func (r Run) Apply(command Command) (Run, Transition, error) {
	next, ok := allowedTarget(r.State, command.Kind)
	if !ok {
		details := problem.New(problem.CodeInvalidTransition, "")
		details.Detail = fmt.Sprintf("command %s is not allowed from %s", command.Kind, r.State)
		return r, Transition{}, details
	}
	if command.Kind == Approve {
		if err := command.Commit.Validate(); err != nil {
			details := problem.New(problem.CodeCommitProofMissing, "")
			details.Detail = err.Error()
			return r, Transition{}, details
		}
	}
	if command.Kind == SubmitForReview {
		if err := command.Validation.Validate(); err != nil {
			return r, Transition{}, problem.New(problem.CodeContractInvalid, "")
		}
	}
	if command.Kind == Retry && !command.RetryEligible {
		details := problem.New(problem.CodeRetryIneligible, "")
		return r, Transition{}, details
	}
	if command.Kind == RecordDomainRejection && (command.Failure == nil || command.Failure.Code != string(problem.CodeDomainRejected) || command.Failure.Retryability != "never") {
		details := problem.New(problem.CodeDomainRejected, "")
		details.Detail = "domain rejection must carry the stable non-retryable domain problem"
		return r, Transition{}, details
	}
	updated := r
	updated.State = next
	updated.Version++
	if command.Kind == Retry {
		updated.ExecutionGeneration++
		updated.Problem = nil
	}
	if command.Kind == RecordFailure || command.Kind == RecordDomainRejection {
		failure := problem.New(problem.CodeInternal, "")
		if command.Failure != nil {
			failure = *command.Failure
		}
		updated.Problem = &failure
	}
	return updated, Transition{Previous: r.State, Current: next, Version: updated.Version, ExecutionGeneration: updated.ExecutionGeneration, EventType: "run.state-changed"}, nil
}

func validDigest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != 71 {
		return false
	}
	for _, character := range value[7:] {
		if !strings.ContainsRune("0123456789abcdef", character) {
			return false
		}
	}
	return true
}

func allowedTarget(state State, command CommandKind) (State, bool) {
	switch command {
	case BeginPreparation:
		return Preparing, state == Created
	case PreparationReady:
		return Planning, state == Preparing
	case RequestInput:
		return AwaitingInput, state == Planning
	case AcceptInput:
		return Planning, state == AwaitingInput
	case BeginExecution:
		return Executing, state == Planning
	case BeginValidation:
		return Validating, state == Executing
	case SubmitForReview:
		return AwaitingReview, state == Validating
	case Revise:
		return Executing, state == AwaitingReview
	case RequestApproval:
		return AwaitingApproval, state == AwaitingReview
	case AcceptArtifact:
		return Completed, state == AwaitingReview
	case Approve:
		return Committing, state == AwaitingApproval
	case RejectApproval:
		return AwaitingReview, state == AwaitingApproval
	case BeginDomainConfirmation:
		return AwaitingDomainConfirmation, state == Committing
	case ConfirmDomain:
		return Completed, state == AwaitingDomainConfirmation
	case RecordDomainConflict:
		return Conflict, state == AwaitingDomainConfirmation
	case RecordDomainRejection:
		return Failed, state == AwaitingDomainConfirmation
	case Rebase:
		return Executing, state == Conflict
	case RequestCancellation:
		return Cancelling, state == Created || state == Preparing || state == Planning || state == AwaitingInput || state == Executing || state == Validating || state == AwaitingReview || state == AwaitingApproval || state == Conflict
	case ReconcileCancellation:
		return Cancelled, state == Cancelling
	case RecordFailure:
		// awaiting_input and awaiting_approval fail on durable expiry
		// (design 0005 §5: "expired" edges).
		return Failed, state == Preparing || state == Planning || state == Executing || state == Validating || state == AwaitingInput || state == AwaitingApproval
	case RecordRefusal:
		return Refused, state == Preparing || state == Planning || state == Validating
	case Retry:
		return Preparing, state == Failed
	case Discard:
		return Discarded, state == AwaitingReview
	default:
		return "", false
	}
}
