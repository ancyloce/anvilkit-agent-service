package events

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func provenanceProducer(t *testing.T) EvidenceProducer {
	t.Helper()
	producer, err := ProjectionProducer("agent-runs", nil, projectionBOM(), json.RawMessage(`{"policyId":"policy.1"}`))
	if err != nil {
		t.Fatal(err)
	}
	return producer
}

// A projection assembled by a caller carries no provenance, so it cannot be
// projected at all. Provenance is not a field a writer fills in correctly by
// convention — it is derived while the source evidence is built, and a
// projection that skipped that step has no account of where it came from.
func TestAProjectionWithoutItsSourceEvidenceCannotBeProjected(t *testing.T) {
	_, err := Project(Projection{
		WorkspaceID: "workspace.1",
		ProjectID:   "project.1",
		RunID:       "run.1",
		Sequence:    7,
		EventID:     "event.1",
		Type:        TypeStateChanged,
		OccurredAt:  time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC),
		Subject:     SystemSubject(),
		Traceparent: projectionTraceparent,
		ContractBOM: projectionBOM(),
		Payload:     StateChangedPayload("preparing", "planning"),
	}, DefaultBounds())
	if err == nil || !strings.Contains(err.Error(), "ProjectionEvidence") {
		t.Fatalf("projection error = %v, want a refusal naming the path provenance comes from", err)
	}
}

// The evidence a projection is projected from and the reference the projection
// carries are two halves of one binding, and both are derived: the evidence
// names the public event it produced, and the projection names that evidence.
func TestProjectionEvidenceBindsTheRecordAndTheReference(t *testing.T) {
	source, bound, err := ProjectionEvidence(Projection{
		WorkspaceID: "workspace.1",
		ProjectID:   "project.1",
		RunID:       "run.1",
		Sequence:    7,
		EventID:     "event.1",
		Type:        TypeStateChanged,
		OccurredAt:  time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC),
		Subject:     SystemSubject(),
		Traceparent: projectionTraceparent,
		ContractBOM: projectionBOM(),
		Payload:     StateChangedPayload("preparing", "planning"),
	}, provenanceProducer(t), ProjectionCorrelation{WorkflowID: "run.1:g1"})
	if err != nil {
		t.Fatal(err)
	}
	derived, err := ProjectionEvidenceID("event.1")
	if err != nil {
		t.Fatal(err)
	}
	if source.EvidenceID != derived || source.PublicEventID != "event.1" {
		t.Fatalf("source evidence=%q publicEvent=%q, want the derived binding", source.EvidenceID, source.PublicEventID)
	}
	if source.RunID != "run.1" || source.WorkspaceID != "workspace.1" || source.ProjectID != "project.1" {
		t.Fatalf("source evidence is not correlated to the projected run: %+v", source)
	}
	// The evidence is internal by construction: a public type could never be
	// recorded as the internal fact a public event was projected from.
	if PublicEventType(source.Type) {
		t.Fatalf("source evidence type %q is a public event type", source.Type)
	}
	rendered, err := Project(bound, DefaultBounds())
	if err != nil {
		t.Fatal(err)
	}
	digest, err := ProjectorDigest()
	if err != nil {
		t.Fatal(err)
	}
	if rendered.EvidenceID != derived || rendered.ProjectorDigest != digest {
		t.Fatalf("projected provenance=(%q,%q), want the derived reference and the live ruleset identity", rendered.EvidenceID, rendered.ProjectorDigest)
	}
}

// Every public type has exactly one internal namespace its source fact is
// recorded under, and nothing outside the registry has one at all.
func TestEveryPublicTypeHasOneInternalEvidenceNamespace(t *testing.T) {
	seen := map[string]string{}
	for _, publicType := range PublicEventTypes() {
		evidenceType, err := ProjectionEvidenceType(publicType)
		if err != nil {
			t.Fatalf("%s: %v", publicType, err)
		}
		if PublicEventType(evidenceType) {
			t.Fatalf("%s maps to the public type %q", publicType, evidenceType)
		}
		if previous, repeated := seen[evidenceType]; repeated {
			t.Fatalf("%s and %s share the internal namespace %q", previous, publicType, evidenceType)
		}
		seen[evidenceType] = publicType
	}
	for _, unregistered := range []string{"run.stuck", "model.call-completed", "approval.decided", ""} {
		if _, err := ProjectionEvidenceType(unregistered); err == nil {
			t.Fatalf("%q was given an internal evidence namespace", unregistered)
		}
	}
}
