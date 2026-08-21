// Package problem defines the serializable error boundary used by the service.
package problem

import (
	"encoding/json"
	"fmt"
	"strings"
)

type Code string

const (
	CodeInvalidTransition          Code = "RUN_TRANSITION_INVALID"
	CodeCommitProofMissing         Code = "COMMIT_PROOF_MISSING"
	CodeRetryIneligible            Code = "RETRY_INELIGIBLE"
	CodeInputRequestStale          Code = "INPUT_REQUEST_STALE"
	CodeInputAlreadyResponded      Code = "INPUT_ALREADY_RESPONDED"
	CodeInputRequestExpired        Code = "INPUT_REQUEST_EXPIRED"
	CodeInputSchemaInvalid         Code = "INPUT_SCHEMA_INVALID"
	CodeApprovalRequestStale       Code = "APPROVAL_REQUEST_STALE"
	CodeApprovalAlreadyDecided     Code = "APPROVAL_ALREADY_DECIDED"
	CodeApprovalRequestExpired     Code = "APPROVAL_REQUEST_EXPIRED"
	CodeCancellationUnreconciled   Code = "CANCELLATION_UNRECONCILED"
	CodeChildLimitExceeded         Code = "CHILD_LIMIT_EXCEEDED"
	CodeChildPredecessorIneligible Code = "CHILD_PREDECESSOR_INELIGIBLE"
	CodeNoEligibleProvider         Code = "NO_ELIGIBLE_PROVIDER"
	CodeProviderLimitExceeded      Code = "PROVIDER_LIMIT_EXCEEDED"
	CodeAuthorityStale             Code = "AUTHORITY_STALE"
	CodeToolDispatchDenied         Code = "TOOL_DISPATCH_DENIED"
	CodeBudgetDenied               Code = "BUDGET_DENIED"
	CodeValidationUnavailable      Code = "VALIDATION_UNAVAILABLE"
	CodeArtifactAccessDenied       Code = "ARTIFACT_ACCESS_DENIED"
	CodeApplyAuthorizationDenied   Code = "APPLY_AUTHORIZATION_DENIED"
	CodeDomainOutcomeUncertain     Code = "DOMAIN_OUTCOME_UNCERTAIN"
	CodeTaskDispatchDenied         Code = "TASK_DISPATCH_DENIED"
	CodeWorkerFenceStale           Code = "WORKER_FENCE_STALE"
	CodeAdmissionOverloaded        Code = "ADMISSION_OVERLOADED"
	CodeLimitExceeded              Code = "LIMIT_EXCEEDED"
	CodeCircuitOpen                Code = "CIRCUIT_OPEN"
	CodeVersionConflict            Code = "VERSION_CONFLICT"
	CodePreconditionRequired       Code = "PRECONDITION_REQUIRED"
	CodeIdempotencyConflict        Code = "IDEMPOTENCY_CONFLICT"
	CodeIdempotencyKeyReused       Code = "IDEMPOTENCY_KEY_REUSED"
	CodeRequestInvalid             Code = "REQUEST_INVALID"
	CodeResourceNotFound           Code = "RESOURCE_NOT_FOUND"
	CodeCursorExpired              Code = "EVENT_CURSOR_EXPIRED"
	CodeEventInvalid               Code = "EVENT_INVALID"
	CodeProviderUnavailable        Code = "PROVIDER_UNAVAILABLE"
	CodeContractInvalid            Code = "CONTRACT_INVALID"
	CodePolicyDenied               Code = "POLICY_DENIED"
	CodeWorkerFailed               Code = "WORKER_FAILED"
	CodeArtifactInvalid            Code = "ARTIFACT_INVALID"
	CodeDomainRejected             Code = "DOMAIN_REJECTED"
	CodeTelemetryDegraded          Code = "TELEMETRY_DEGRADED"
	CodeInfrastructureUnavailable  Code = "INFRASTRUCTURE_UNAVAILABLE"
	CodeAuthenticationInvalid      Code = "AUTHENTICATION_INVALID"
	CodeAuthorizationDenied        Code = "AUTHORIZATION_DENIED"
	CodeInternal                   Code = "INTERNAL_ERROR"
)

type Definition struct {
	Code                      Code
	Type, Title, Retryability string
	Status                    int
}

func Codes() []Code {
	return []Code{CodeInvalidTransition, CodeCommitProofMissing, CodeRetryIneligible, CodeInputRequestStale, CodeInputAlreadyResponded, CodeInputRequestExpired, CodeInputSchemaInvalid, CodeApprovalRequestStale, CodeApprovalAlreadyDecided, CodeApprovalRequestExpired, CodeCancellationUnreconciled, CodeChildLimitExceeded, CodeChildPredecessorIneligible, CodeNoEligibleProvider, CodeProviderLimitExceeded, CodeAuthorityStale, CodeToolDispatchDenied, CodeBudgetDenied, CodeValidationUnavailable, CodeArtifactAccessDenied, CodeApplyAuthorizationDenied, CodeDomainOutcomeUncertain, CodeTaskDispatchDenied, CodeWorkerFenceStale, CodeAdmissionOverloaded, CodeLimitExceeded, CodeCircuitOpen, CodeVersionConflict, CodePreconditionRequired, CodeIdempotencyConflict, CodeIdempotencyKeyReused, CodeRequestInvalid, CodeResourceNotFound, CodeCursorExpired, CodeEventInvalid, CodeProviderUnavailable, CodeContractInvalid, CodePolicyDenied, CodeWorkerFailed, CodeArtifactInvalid, CodeDomainRejected, CodeTelemetryDegraded, CodeInfrastructureUnavailable, CodeAuthenticationInvalid, CodeAuthorizationDenied, CodeInternal}
}

func Lookup(code Code) (Definition, bool) {
	var definition Definition
	switch code {
	case CodeInvalidTransition:
		definition = Definition{code, "urn:anvilkit:problem:run-transition-invalid", "Run transition is not allowed", "never", 409}
	case CodeCommitProofMissing:
		definition = Definition{code, "urn:anvilkit:problem:commit-proof-missing", "Commit prerequisites are incomplete", "never", 409}
	case CodeRetryIneligible:
		definition = Definition{code, "urn:anvilkit:problem:retry-ineligible", "Run is not eligible for retry", "never", 409}
	case CodeInputRequestStale:
		definition = Definition{code, "urn:anvilkit:problem:input-request-stale", "Input request version is stale", "never", 409}
	case CodeInputAlreadyResponded:
		definition = Definition{code, "urn:anvilkit:problem:input-already-responded", "Input request already has a response", "never", 409}
	case CodeInputRequestExpired:
		definition = Definition{code, "urn:anvilkit:problem:input-request-expired", "Input request has expired", "never", 409}
	case CodeInputSchemaInvalid:
		definition = Definition{code, "urn:anvilkit:problem:input-schema-invalid", "Input response violates its schema", "never", 422}
	case CodeApprovalRequestStale:
		definition = Definition{code, "urn:anvilkit:problem:approval-request-stale", "Approval request version is stale", "never", 409}
	case CodeApprovalAlreadyDecided:
		definition = Definition{code, "urn:anvilkit:problem:approval-already-decided", "Approval request already has a decision", "never", 409}
	case CodeApprovalRequestExpired:
		definition = Definition{code, "urn:anvilkit:problem:approval-request-expired", "Approval request has expired", "never", 409}
	case CodeCancellationUnreconciled:
		definition = Definition{code, "urn:anvilkit:problem:cancellation-unreconciled", "Cancellation remains under reconciliation", "operator-action", 409}
	case CodeChildLimitExceeded:
		definition = Definition{code, "urn:anvilkit:problem:child-limit-exceeded", "Child run bound is exceeded", "safe-after-backoff", 429}
	case CodeChildPredecessorIneligible:
		definition = Definition{code, "urn:anvilkit:problem:child-predecessor-ineligible", "Fallback predecessor is not eligible", "never", 409}
	case CodeNoEligibleProvider:
		definition = Definition{code, "urn:anvilkit:problem:no-eligible-provider", "No provider is eligible", "never", 422}
	case CodeProviderLimitExceeded:
		definition = Definition{code, "urn:anvilkit:problem:provider-limit-exceeded", "Provider invocation exceeded a bound", "never", 422}
	case CodeAuthorityStale:
		definition = Definition{code, "urn:anvilkit:problem:authority-stale", "Current authority no longer permits the operation", "never", 403}
	case CodeToolDispatchDenied:
		definition = Definition{code, "urn:anvilkit:problem:tool-dispatch-denied", "Tool proposal is not authorized", "never", 403}
	case CodeBudgetDenied:
		definition = Definition{code, "urn:anvilkit:problem:budget-denied", "Budget reservation or settlement was denied", "never", 409}
	case CodeValidationUnavailable:
		definition = Definition{code, "urn:anvilkit:problem:validation-unavailable", "Contract validation is unavailable", "safe-after-backoff", 503}
	case CodeArtifactAccessDenied:
		definition = Definition{code, "urn:anvilkit:problem:artifact-access-denied", "Artifact is not eligible for access", "never", 403}
	case CodeApplyAuthorizationDenied:
		definition = Definition{code, "urn:anvilkit:problem:apply-authorization-denied", "Apply authorization issuance was denied", "never", 409}
	case CodeDomainOutcomeUncertain:
		definition = Definition{code, "urn:anvilkit:problem:domain-outcome-uncertain", "Domain outcome requires reconciliation", "safe-after-backoff", 503}
	case CodeTaskDispatchDenied:
		definition = Definition{code, "urn:anvilkit:problem:task-dispatch-denied", "Task prerequisites are incomplete", "never", 409}
	case CodeWorkerFenceStale:
		definition = Definition{code, "urn:anvilkit:problem:worker-fence-stale", "Worker result or lease is stale", "never", 409}
	case CodeAdmissionOverloaded:
		definition = Definition{code, "urn:anvilkit:problem:admission-overloaded", "Admission capacity is temporarily exhausted", "safe-after-backoff", 429}
	case CodeLimitExceeded:
		definition = Definition{code, "urn:anvilkit:problem:limit-exceeded", "A configured operation bound was exceeded", "never", 422}
	case CodeCircuitOpen:
		definition = Definition{code, "urn:anvilkit:problem:circuit-open", "Dependency circuit is open", "safe-after-backoff", 503}
	case CodeVersionConflict:
		definition = Definition{code, "urn:anvilkit:problem:version-conflict", "Version precondition failed", "never", 412}
	case CodePreconditionRequired:
		definition = Definition{code, "urn:anvilkit:problem:precondition-required", "Concurrency precondition is required", "never", 428}
	case CodeIdempotencyConflict:
		definition = Definition{code, "urn:anvilkit:problem:idempotency-conflict", "Idempotency key conflicts with its recorded request", "never", 409}
	case CodeIdempotencyKeyReused:
		definition = Definition{code, "urn:anvilkit:problem:idempotency-key-reused", "Idempotency key was reused with different canonical bytes", "never", 409}
	case CodeRequestInvalid:
		definition = Definition{code, "urn:anvilkit:problem:request-invalid", "Request is invalid", "never", 422}
	case CodeResourceNotFound:
		definition = Definition{code, "urn:anvilkit:problem:resource-not-found", "Resource was not found", "never", 404}
	case CodeCursorExpired:
		definition = Definition{code, "urn:anvilkit:problem:event-cursor-expired", "Event cursor is no longer retained", "never", 410}
	case CodeEventInvalid:
		definition = Definition{code, "urn:anvilkit:problem:event-invalid", "Event violates the bounded event contract", "never", 422}
	case CodeProviderUnavailable:
		definition = Definition{code, "urn:anvilkit:problem:provider-unavailable", "Provider is temporarily unavailable", "safe-after-backoff", 503}
	case CodeContractInvalid:
		definition = Definition{code, "urn:anvilkit:problem:contract-invalid", "Contract validation failed", "never", 422}
	case CodePolicyDenied:
		definition = Definition{code, "urn:anvilkit:problem:policy-denied", "Policy denied the operation", "never", 403}
	case CodeWorkerFailed:
		definition = Definition{code, "urn:anvilkit:problem:worker-failed", "Worker execution failed", "operator-action", 503}
	case CodeArtifactInvalid:
		definition = Definition{code, "urn:anvilkit:problem:artifact-invalid", "Artifact is not eligible", "never", 422}
	case CodeDomainRejected:
		definition = Definition{code, "urn:anvilkit:problem:domain-rejected", "Authoritative domain rejected the operation", "never", 409}
	case CodeTelemetryDegraded:
		definition = Definition{code, "urn:anvilkit:problem:telemetry-degraded", "Telemetry delivery is degraded", "never", 503}
	case CodeInfrastructureUnavailable:
		definition = Definition{code, "urn:anvilkit:problem:infrastructure-unavailable", "Required infrastructure is unavailable", "safe-after-backoff", 503}
	case CodeAuthenticationInvalid:
		definition = Definition{code, "urn:anvilkit:problem:authentication-invalid", "Authentication failed", "never", 401}
	case CodeAuthorizationDenied:
		definition = Definition{code, "urn:anvilkit:problem:authorization-denied", "Authorization failed", "never", 403}
	case CodeInternal:
		definition = Definition{code, "urn:anvilkit:problem:internal", "Internal service error", "never", 500}
	default:
		return Definition{}, false
	}
	return definition, true
}

func New(code Code, traceID string) Details {
	definition, ok := Lookup(code)
	if !ok {
		definition, _ = Lookup(CodeInternal)
	}
	return Details{Kind: "ProblemDetails", Type: definition.Type, Title: definition.Title, Status: definition.Status, Code: string(definition.Code), Retryability: definition.Retryability, TraceID: NormalizeTraceID(traceID), FieldErrors: []FieldError{}}
}

// Details is the service-side projection of ProblemDetails. It deliberately
// contains only contract-serializable values.
type Details struct {
	Kind         string            `json:"kind"`
	Code         string            `json:"code"`
	Retryability string            `json:"retryability"`
	Message      string            `json:"message"`
	FieldErrors  []FieldError      `json:"fieldErrors"`
	Stage        string            `json:"stage,omitempty"`
	RunID        string            `json:"runId,omitempty"`
	TraceID      string            `json:"traceId,omitempty"`
	Type         string            `json:"-"`
	Title        string            `json:"-"`
	Status       int               `json:"-"`
	Detail       string            `json:"-"`
	Fields       map[string]string `json:"-"`
}

type FieldError struct {
	Code, InstancePath, SchemaPath, Message string
}

func (f FieldError) MarshalJSON() ([]byte, error) {
	type wire struct {
		Code         string `json:"code"`
		InstancePath string `json:"instancePath"`
		SchemaPath   string `json:"schemaPath"`
		Message      string `json:"message"`
	}
	return json.Marshal(wire(f))
}

// MarshalJSON prevents transport-only status and internal diagnostic fields
// from escaping the closed ProblemDetails contract.
func (p Details) MarshalJSON() ([]byte, error) {
	message := p.Message
	if p.Detail != "" {
		message = p.Detail
	}
	if message == "" {
		message = p.Title
	}
	fieldErrors := p.FieldErrors
	if fieldErrors == nil {
		fieldErrors = []FieldError{}
	}
	type wire struct {
		Kind         string       `json:"kind"`
		Code         string       `json:"code"`
		Retryability string       `json:"retryability"`
		Message      string       `json:"message"`
		FieldErrors  []FieldError `json:"fieldErrors"`
		Stage        string       `json:"stage,omitempty"`
		RunID        string       `json:"runId,omitempty"`
		TraceID      string       `json:"traceId,omitempty"`
	}
	return json.Marshal(wire{Kind: p.Kind, Code: p.Code, Retryability: p.Retryability, Message: message, FieldErrors: fieldErrors, Stage: p.Stage, RunID: p.RunID, TraceID: NormalizeTraceID(p.TraceID)})
}

// UnmarshalJSON reconstructs the structured details from the closed wire
// contract. The registry supplies the fields the wire shape deliberately
// omits (type, title, status), so a Details value that crosses a durable
// boundary and is replayed later keeps the diagnostic detail its producer
// recorded and re-marshals byte-identically.
func (p *Details) UnmarshalJSON(raw []byte) error {
	var wire struct {
		Kind         string       `json:"kind"`
		Code         string       `json:"code"`
		Retryability string       `json:"retryability"`
		Message      string       `json:"message"`
		FieldErrors  []FieldError `json:"fieldErrors"`
		Stage        string       `json:"stage"`
		RunID        string       `json:"runId"`
		TraceID      string       `json:"traceId"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		return err
	}
	restored := Details{
		Kind:         wire.Kind,
		Code:         wire.Code,
		Retryability: wire.Retryability,
		Message:      wire.Message,
		FieldErrors:  wire.FieldErrors,
		Stage:        wire.Stage,
		RunID:        wire.RunID,
		TraceID:      wire.TraceID,
	}
	if restored.FieldErrors == nil {
		restored.FieldErrors = []FieldError{}
	}
	if definition, known := Lookup(Code(wire.Code)); known {
		restored.Type, restored.Title, restored.Status = definition.Type, definition.Title, definition.Status
		if restored.Retryability == "" {
			restored.Retryability = definition.Retryability
		}
	}
	// MarshalJSON projects Detail onto message and falls back to the
	// registry title; restoring Detail only when the message carries more
	// than the title keeps that projection idempotent.
	if wire.Message != "" && wire.Message != restored.Title {
		restored.Detail = wire.Message
	}
	*p = restored
	return nil
}

func NormalizeTraceID(value string) string {
	parts := strings.Split(value, "-")
	if len(parts) == 4 && len(parts[1]) == 32 {
		value = parts[1]
	}
	if len(value) != 32 {
		return ""
	}
	for _, character := range value {
		if !strings.ContainsRune("0123456789abcdef", character) {
			return ""
		}
	}
	return value
}

func (p Details) Error() string {
	if p.Detail == "" {
		return fmt.Sprintf("%s: %s", p.Code, p.Title)
	}
	return fmt.Sprintf("%s: %s", p.Code, p.Detail)
}

// InvalidConfiguration returns the stable startup-validation problem.
func InvalidConfiguration(field, detail string) Details {
	return Details{
		Kind:         "ProblemDetails",
		Type:         "urn:anvilkit:problem:configuration-invalid",
		Title:        "Invalid service configuration",
		Status:       500,
		Code:         "CONFIG_INVALID",
		Detail:       detail,
		Retryability: "operator-action",
		FieldErrors:  []FieldError{},
		Fields:       map[string]string{field: detail},
	}
}

// Internal converts an unknown implementation failure at a durable boundary.
func Internal(traceID string) Details {
	return New(CodeInternal, traceID)
}
