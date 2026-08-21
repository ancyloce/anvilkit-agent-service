package problem

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	contractguard "github.com/ancyloce/anvilkit-agent-service/internal/contracts"
)

func TestProblemDetailsUsesClosedCandidateContractShape(t *testing.T) {
	details := New(CodeVersionConflict, "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01")
	details.Detail = "precondition did not match"
	raw, err := json.Marshal(details)
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	want := []string{"kind", "code", "retryability", "message", "fieldErrors", "traceId"}
	if len(payload) != len(want) {
		t.Fatalf("unexpected ProblemDetails fields: %s", raw)
	}
	for _, field := range want {
		if _, ok := payload[field]; !ok {
			t.Fatalf("missing %s: %s", field, raw)
		}
	}
	if payload["traceId"] != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("traceparent was not projected to traceId: %s", raw)
	}
	guard, err := contractguard.NewGuard("../..")
	if err != nil {
		t.Fatal(err)
	}
	findings := guard.Validate(context.Background(), contractguard.APIIn, "anvilkit://schema/problem-details?digest=sha256:d42f44ad527b3a165aca0c56ab00b2b01ea28e3f7bb8346850a5334a7f438087", raw)
	if len(findings) != 0 {
		t.Fatalf("ProblemDetails validation failed: %#v raw=%s", findings, raw)
	}
}

func TestShippedProblemCodeRegistryIsFrozen(t *testing.T) {
	want := []Code{"RUN_TRANSITION_INVALID", "COMMIT_PROOF_MISSING", "RETRY_INELIGIBLE", "INPUT_REQUEST_STALE", "INPUT_ALREADY_RESPONDED", "INPUT_REQUEST_EXPIRED", "INPUT_SCHEMA_INVALID", "APPROVAL_REQUEST_STALE", "APPROVAL_ALREADY_DECIDED", "APPROVAL_REQUEST_EXPIRED", "CANCELLATION_UNRECONCILED", "CHILD_LIMIT_EXCEEDED", "CHILD_PREDECESSOR_INELIGIBLE", "NO_ELIGIBLE_PROVIDER", "PROVIDER_LIMIT_EXCEEDED", "AUTHORITY_STALE", "TOOL_DISPATCH_DENIED", "BUDGET_DENIED", "VALIDATION_UNAVAILABLE", "ARTIFACT_ACCESS_DENIED", "APPLY_AUTHORIZATION_DENIED", "DOMAIN_OUTCOME_UNCERTAIN", "TASK_DISPATCH_DENIED", "WORKER_FENCE_STALE", "ADMISSION_OVERLOADED", "LIMIT_EXCEEDED", "CIRCUIT_OPEN", "VERSION_CONFLICT", "PRECONDITION_REQUIRED", "IDEMPOTENCY_CONFLICT", "IDEMPOTENCY_KEY_REUSED", "REQUEST_INVALID", "RESOURCE_NOT_FOUND", "EVENT_CURSOR_EXPIRED", "EVENT_INVALID", "PROVIDER_UNAVAILABLE", "CONTRACT_INVALID", "POLICY_DENIED", "WORKER_FAILED", "ARTIFACT_INVALID", "DOMAIN_REJECTED", "TELEMETRY_DEGRADED", "INFRASTRUCTURE_UNAVAILABLE", "AUTHENTICATION_INVALID", "AUTHORIZATION_DENIED", "INTERNAL_ERROR"}
	if !reflect.DeepEqual(Codes(), want) {
		t.Fatalf("problem registry changed: got %v want %v", Codes(), want)
	}
	for _, code := range Codes() {
		definition, ok := Lookup(code)
		if !ok || definition.Code != code || definition.Retryability == "" || definition.Status < 400 {
			t.Fatalf("invalid definition for %s: %#v", code, definition)
		}
	}
}

func TestClassifierCoversEveryFailureFamily(t *testing.T) {
	const traceID = "0123456789abcdef0123456789abcdef"
	cases := map[Family]Action{FamilyProvider: ActionRetry, FamilyContract: ActionAck, FamilyPolicy: ActionAck, FamilyWorker: ActionDLQ, FamilyArtifact: ActionAck, FamilyConflict: ActionAck, FamilyDomain: ActionAck, FamilyTelemetry: ActionAck, FamilyInfrastructure: ActionRetry, FamilyAuthentication: ActionAck, FamilyAuthorization: ActionAck}
	for family, action := range cases {
		classified := Classify(Failure{Family: family, Err: errors.New("cause")}, traceID)
		if classified.Action != action || classified.Problem.TraceID != traceID || classified.Problem.Retryability == "" {
			t.Fatalf("family %s: %#v", family, classified)
		}
	}
	unknown := Classify(errors.New("unknown"), traceID)
	if unknown.Problem.Code != string(CodeInternal) || unknown.Problem.Retryability != "never" || unknown.Action != ActionDLQ {
		t.Fatalf("unknown error was not fail-safe: %#v", unknown)
	}
}

// TestGovernedIdempotencyCodesStayDistinct pins the ADR-021 §4 split. Reuse of
// a key with different canonical bytes has its own governed code because it is
// the only idempotency fault the caller can fix by sending the command it
// originally committed to; every other one is about circumstances the caller
// did not change. Collapsing them would leave a client unable to tell the two
// apart from the code alone.
func TestGovernedIdempotencyCodesStayDistinct(t *testing.T) {
	reused, known := Lookup(CodeIdempotencyKeyReused)
	if !known {
		t.Fatal("IDEMPOTENCY_KEY_REUSED is not in the shipped registry")
	}
	conflict, known := Lookup(CodeIdempotencyConflict)
	if !known {
		t.Fatal("IDEMPOTENCY_CONFLICT is not in the shipped registry")
	}
	if reused.Status != 409 || conflict.Status != 409 {
		t.Fatalf("both idempotency faults answer 409: reused=%d conflict=%d", reused.Status, conflict.Status)
	}
	if reused.Code == conflict.Code || reused.Type == conflict.Type || reused.Title == conflict.Title {
		t.Fatalf("the two idempotency faults are not distinguishable: %+v vs %+v", reused, conflict)
	}
	if reused.Retryability != "never" {
		t.Fatalf("retryability = %q, want never: a reused key is fixed by sending the original command", reused.Retryability)
	}
}
