package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	contractguard "github.com/ancyloce/anvilkit-agent-service/internal/contracts"
	"github.com/ancyloce/anvilkit-agent-service/internal/events"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/runs"

	"github.com/jackc/pgx/v5/pgconn"
)

func testContractBOM() json.RawMessage {
	return json.RawMessage(`{"repository":"anvilkit/contracts","bomDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","ociManifestDigest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","evidenceManifestDigest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}`)
}

// Every event this store persists is rendered by the repository-owned
// projector; this pins that the projector's output for the store's shapes is
// replayable and contract-valid.
func TestProjectedInterruptEventsAreReplayableContractEnvelopes(t *testing.T) {
	guard, err := contractguard.NewGuard("../../..")
	if err != nil {
		t.Fatal(err)
	}
	occurred := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	projections := map[string]events.Projection{
		"child created": {
			WorkspaceID: "workspace.synthetic.001",
			ProjectID:   "project.synthetic.001",
			RunID:       "child-run",
			Sequence:    1,
			EventID:     "child-run:1",
			Type:        events.TypeRunCreated,
			OccurredAt:  occurred,
			Subject:     events.SystemSubject(),
			Traceparent: "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01",
			ContractBOM: testContractBOM(),
			Payload:     events.ChildCreatedPayload("parent-run", "root-run", string(runs.Created)),
		},
		"input requested": {
			WorkspaceID: "workspace.synthetic.001",
			ProjectID:   "project.synthetic.001",
			RunID:       "run-input",
			Sequence:    3,
			EventID:     "run-input:control:3",
			Type:        events.TypeInputRequested,
			OccurredAt:  occurred,
			Subject:     events.SystemSubject(),
			Traceparent: "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01",
			ContractBOM: testContractBOM(),
			Payload:     events.InputRequestedPayload("request.input01", 1, "2026-08-14T12:15:00.000Z"),
		},
		"approval requested": {
			WorkspaceID: "workspace.synthetic.001",
			ProjectID:   "project.synthetic.001",
			RunID:       "run-approval",
			Sequence:    5,
			EventID:     "run-approval:control:5",
			Type:        events.TypeApprovalRequested,
			OccurredAt:  occurred,
			Subject:     events.SystemSubject(),
			Traceparent: "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01",
			ContractBOM: testContractBOM(),
			Payload:     events.ApprovalRequestedPayload("request.approve01", "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1, "2026-08-14T12:15:00.000Z"),
		},
		"problem recorded": {
			WorkspaceID: "workspace.synthetic.001",
			ProjectID:   "project.synthetic.001",
			RunID:       "run-stuck",
			Sequence:    7,
			EventID:     "run-stuck:control:7",
			Type:        events.TypeProblemRecorded,
			OccurredAt:  occurred,
			Subject:     events.SystemSubject(),
			Traceparent: "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01",
			ContractBOM: testContractBOM(),
			Payload:     events.ProblemPayload("RUN_STUCK", string(runs.Executing)),
		},
	}
	for name, projection := range projections {
		raw, err := events.Project(projection, events.DefaultBounds())
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := events.ValidateEnvelope(raw, events.DefaultBounds(), projection.EventID, projection.RunID, projection.Sequence); err != nil {
			t.Fatalf("%s is not replayable: %v\n%s", name, err, raw)
		}
		if err := guard.Require(context.Background(), contractguard.EventIn, events.AgentEventSchemaURI, raw); err != nil {
			t.Fatalf("%s violates AgentEvent: %v\n%s", name, err, raw)
		}
	}
}

// Internal control vocabulary must never reach the public wire: the projector
// refuses any type outside the six-event registry, so a control name like
// run.stuck cannot be emitted directly.
func TestProjectorRejectsInternalVocabulary(t *testing.T) {
	for _, internal := range []string{"run.stuck", "approval.decided", "run.cancellation-requested", "agent.turn-completed"} {
		_, err := events.Project(events.Projection{
			WorkspaceID: "workspace",
			ProjectID:   "project",
			RunID:       "run",
			Sequence:    1,
			EventID:     "run:1",
			Type:        internal,
			OccurredAt:  time.Now(),
			Subject:     events.SystemSubject(),
			Traceparent: "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01",
			ContractBOM: testContractBOM(),
			Payload:     map[string]string{"state": "executing"},
		}, events.DefaultBounds())
		if err == nil {
			t.Fatalf("internal vocabulary %q reached the public projector", internal)
		}
	}
}

func TestTranslateClassifiesPostgresUniqueViolation(t *testing.T) {
	err := translate(&pgconn.PgError{Code: "23505", ConstraintName: "input_requests_workspace_id_project_id_run_id_request_version_key"})
	var details problem.Details
	if !errors.As(err, &details) || details.Code != string(problem.CodeIdempotencyConflict) {
		t.Fatalf("unique violation translated to %v", err)
	}
}
