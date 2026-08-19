package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	contractguard "github.com/ancyloce/anvilkit-agent-service/internal/contracts"
	"github.com/ancyloce/anvilkit-agent-service/internal/events"
	"github.com/ancyloce/anvilkit-agent-service/internal/interrupts"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/runs"
	"github.com/jackc/pgx/v5/pgconn"
)

const agentEventSchema = "anvilkit://schema/agent-event?digest=sha256:2fdd8937381427507e721675ebbd66144595a193b53ba460534e9712df9b774a"

func TestMarshalEventProducesReplayableContractEnvelope(t *testing.T) {
	write := interrupts.Write{
		Scope:       runs.Scope{WorkspaceID: "workspace.synthetic.001", ProjectID: "project.synthetic.001", ActorID: "actor.synthetic.001"},
		RunID:       "child-run",
		Traceparent: "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01",
	}
	snapshot := runs.Snapshot{ContractBOM: json.RawMessage(`{"repository":"anvilkit/contracts","bomDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","ociManifestDigest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","evidenceManifestDigest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}`)}
	raw, err := marshalEvent(write, snapshot, 1, "child-run:1", "run.created", map[string]string{
		"parentRunId": "parent-run",
		"rootRunId":   "root-run",
		"state":       string(runs.Created),
	}, time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if err := events.ValidateEnvelope(raw, events.DefaultBounds(), "child-run:1", "child-run", 1); err != nil {
		t.Fatalf("event is not replayable: %v\n%s", err, raw)
	}
	guard, err := contractguard.NewGuard("../../..")
	if err != nil {
		t.Fatal(err)
	}
	if err := guard.Require(context.Background(), contractguard.EventIn, agentEventSchema, raw); err != nil {
		t.Fatalf("event violates AgentEvent: %v\n%s", err, raw)
	}
}

func TestMarshalEventRejectsUnknownEventType(t *testing.T) {
	_, err := marshalEvent(interrupts.Write{RunID: "run"}, runs.Snapshot{}, 1, "event", "run.stuck", nil, time.Now())
	if err == nil {
		t.Fatal("unknown AgentEvent event type was accepted")
	}
}

func TestControlEventsMapToFrozenAgentEventTypes(t *testing.T) {
	tests := map[string]string{
		"approval.decided":           "run.state-changed",
		"run.cancellation-requested": "run.state-changed",
		"run.stuck":                  "run.problem-recorded",
	}
	for controlType, expected := range tests {
		actual, err := wireTypeForControlEvent(controlType)
		if err != nil || actual != expected {
			t.Errorf("wire type for %q = %q, %v; want %q", controlType, actual, err, expected)
		}
	}
	if _, err := wireTypeForControlEvent("unknown"); err == nil {
		t.Fatal("unknown control event type was accepted")
	}
}

func TestTranslateClassifiesPostgresUniqueViolation(t *testing.T) {
	err := translate(&pgconn.PgError{Code: "23505", ConstraintName: "input_requests_workspace_id_project_id_run_id_request_version_key"})
	var details problem.Details
	if !errors.As(err, &details) || details.Code != string(problem.CodeIdempotencyConflict) {
		t.Fatalf("unique violation translated to %v", err)
	}
}
