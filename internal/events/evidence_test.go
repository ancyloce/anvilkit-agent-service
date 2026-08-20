package events

import (
	"context"
	"strings"
	"testing"
	"time"
)

func validEvidence(id string) Evidence {
	return Evidence{
		WorkspaceID: "workspace.1",
		ProjectID:   "project.1",
		RunID:       "run.1",
		EvidenceID:  id,
		Type:        "commit.authorization-issued",
		OccurredAt:  time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC),
		Producer: EvidenceProducer{
			Component:         "agent-executor",
			DefinitionDigest:  "sha256:" + strings.Repeat("d", 64),
			PolicyDigest:      "sha256:" + strings.Repeat("a", 64),
			ContractBOMDigest: "sha256:" + strings.Repeat("c", 64),
		},
		Classification: "internal",
		Retention:      "audit",
		Traceparent:    "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01",
		Payload:        map[string]string{"authorizationId": "authorization.1"},
	}
}

// Evidence sequences are independent, per-run, and idempotent by evidence
// identity: a durable-operation replay converges on the recorded sequence.
func TestEvidenceSequencesAreIndependentAndIdempotent(t *testing.T) {
	store := NewMemoryEvidence()
	first, err := store.AppendEvidence(context.Background(), validEvidence("evidence.1"))
	if err != nil || first != 1 {
		t.Fatalf("first append sequence=%d err=%v", first, err)
	}
	second, err := store.AppendEvidence(context.Background(), validEvidence("evidence.2"))
	if err != nil || second != 2 {
		t.Fatalf("second append sequence=%d err=%v", second, err)
	}
	replayed, err := store.AppendEvidence(context.Background(), validEvidence("evidence.1"))
	if err != nil || replayed != 1 {
		t.Fatalf("replayed append sequence=%d err=%v, want the recorded 1", replayed, err)
	}
	other := validEvidence("evidence.other-run")
	other.RunID = "run.2"
	otherSequence, err := store.AppendEvidence(context.Background(), other)
	if err != nil || otherSequence != 1 {
		t.Fatalf("independent run sequence=%d err=%v", otherSequence, err)
	}
}

// Evidence reads are access-audited: an anonymous or purposeless read is not
// a mode.
func TestEvidenceReadsRequireAccessorAndPurpose(t *testing.T) {
	store := NewMemoryEvidence()
	if _, err := store.AppendEvidence(context.Background(), validEvidence("evidence.1")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReadEvidence(context.Background(), Scope{WorkspaceID: "workspace.1", ProjectID: "project.1"}, "run.1", "", "debug", 10); err == nil {
		t.Fatal("an anonymous evidence read was allowed")
	}
	if _, err := store.ReadEvidence(context.Background(), Scope{WorkspaceID: "workspace.1", ProjectID: "project.1"}, "run.1", "operator", "", 10); err == nil {
		t.Fatal("a purposeless evidence read was allowed")
	}
	records, err := store.ReadEvidence(context.Background(), Scope{WorkspaceID: "workspace.1", ProjectID: "project.1"}, "run.1", "operator", "incident-debug", 10)
	if err != nil || len(records) != 1 {
		t.Fatalf("audited read records=%d err=%v", len(records), err)
	}
	if len(store.Reads) != 1 || store.Reads[0] != "operator:incident-debug" {
		t.Fatalf("access audit=%v", store.Reads)
	}
}

// The evidence contract fails closed: unregistered namespaces,
// classifications, retention categories, and prohibited payload content never
// reach storage.
func TestEvidenceValidationFailsClosed(t *testing.T) {
	unregistered := validEvidence("evidence.bad-type")
	unregistered.Type = "run.state-changed"
	if err := ValidateEvidence(unregistered); err == nil {
		t.Fatal("a public event type was accepted as an evidence namespace")
	}
	classified := validEvidence("evidence.bad-class")
	classified.Classification = "open"
	if err := ValidateEvidence(classified); err == nil {
		t.Fatal("an unregistered classification was accepted")
	}
	retained := validEvidence("evidence.bad-retention")
	retained.Retention = "forever"
	if err := ValidateEvidence(retained); err == nil {
		t.Fatal("an unregistered retention category was accepted")
	}
	leaking := validEvidence("evidence.leak")
	leaking.Payload = map[string]string{"note": "the system prompt said"}
	if err := ValidateEvidence(leaking); err == nil {
		t.Fatal("prohibited payload content was accepted")
	}
}

// Rendered evidence and rendered public events are different kinds: one can
// never deserialize as the other.
func TestEvidenceAndPublicEventsAreDisjointShapes(t *testing.T) {
	rendered, err := RenderEvidence(validEvidence("evidence.1"), 1, time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateBytes(rendered, DefaultBounds()); err == nil {
		t.Fatal("rendered evidence validated as a public event")
	}
	if !strings.Contains(string(rendered), `"kind":"AgentEvidence"`) || !strings.Contains(string(rendered), `"evidenceSequence":1`) {
		t.Fatalf("rendered evidence lacks its kind or sequence: %s", rendered)
	}
}
