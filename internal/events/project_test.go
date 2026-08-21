package events

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	contractguard "github.com/ancyloce/anvilkit-agent-service/internal/contracts"
)

const projectionTraceparent = "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"

func projectionBOM() []byte {
	return []byte(`{"repository":"anvilkit/contracts","bomDigest":"sha256:` + strings.Repeat("a", 64) + `","ociManifestDigest":"sha256:` + strings.Repeat("b", 64) + `","evidenceManifestDigest":"sha256:` + strings.Repeat("c", 64) + `"}`)
}

func lifecycleProjection() Projection {
	return Projection{
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
	}
}

// Projection is deterministic: the same internal facts render byte-identical
// public bytes every time and on every process, so replaying a run's history
// reproduces exactly the events consumers already saw.
func TestProjectionIsDeterministicAcrossRepeatedRenders(t *testing.T) {
	first, err := Project(lifecycleProjection(), DefaultBounds())
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 32; attempt++ {
		repeated, err := Project(lifecycleProjection(), DefaultBounds())
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(first, repeated) {
			t.Fatalf("projection is not deterministic:\n%s\n%s", first, repeated)
		}
	}
}

// Every projected event satisfies the pinned canonical AgentEvent contract,
// which is the same proof the durable store demands before persistence.
func TestProjectedEventsSatisfyTheCanonicalContract(t *testing.T) {
	guard, err := contractguard.NewGuard("../..")
	if err != nil {
		t.Fatal(err)
	}
	artifact := lifecycleProjection()
	artifact.Type = TypeArtifactAvailable
	artifact.Payload = nil
	artifact.Artifact = &EventArtifact{ArtifactID: "artifact.1", Digest: "sha256:" + strings.Repeat("d", 64), MediaType: "application/json", SizeBytes: 12}
	child := lifecycleProjection()
	child.Type = TypeRunCreated
	child.Payload = ChildCreatedPayload("run.parent", "run.root", "created")
	input := lifecycleProjection()
	input.Type = TypeInputRequested
	input.Subject = UserSubject("actor.1")
	input.Payload = InputRequestedPayload("request.1", 3, "2026-08-20T12:30:00.000Z")
	approval := lifecycleProjection()
	approval.Type = TypeApprovalRequested
	approval.Payload = ApprovalRequestedPayload("request.2", "sha256:"+strings.Repeat("e", 64), 4, "2026-08-20T12:30:00.000Z")
	recorded := lifecycleProjection()
	recorded.Type = TypeProblemRecorded
	recorded.Payload = ProblemPayload("BUDGET_DENIED", "failed")
	for _, projection := range []Projection{lifecycleProjection(), artifact, child, input, approval, recorded} {
		rendered, err := Project(projection, DefaultBounds())
		if err != nil {
			t.Fatalf("%s: %v", projection.Type, err)
		}
		if err := guard.Require(context.Background(), contractguard.EventIn, AgentEventSchemaURI, rendered); err != nil {
			t.Fatalf("%s violates the canonical contract: %v\n%s", projection.Type, err, rendered)
		}
	}
}

// Nothing outside the six-type registry can be projected. Internal control
// vocabulary is the case that matters: every internal Evidence namespace is
// refused by name, so a debugging step can never become externally
// observable by being projected "just this once".
func TestInternalControlVocabularyCannotBeProjected(t *testing.T) {
	internal := []string{
		"agent.turn-completed", "model.call-started", "tool.invoked", "validation.failed",
		"artifact.finalized", "approval.decided", "commit.authorization-issued",
		"domain.effect-confirmed", "recovery.epoch-advanced",
	}
	for _, candidate := range append(internal, "run.unknown", "", "RUN.CREATED") {
		projection := lifecycleProjection()
		projection.Type = candidate
		if _, err := Project(projection, DefaultBounds()); err == nil {
			t.Fatalf("%q was projected onto the public wire", candidate)
		}
		if PublicEventType(candidate) {
			t.Fatalf("%q is reported as a registered public event type", candidate)
		}
	}
}

// The projector fails closed on every other allowlist rule: an unregistered
// subject kind, an unattributed event, and an envelope that carries both a
// payload and an artifact reference.
func TestProjectionAllowlistFailsClosed(t *testing.T) {
	unregisteredSubject := lifecycleProjection()
	unregisteredSubject.Subject = Subject{Type: "service-account", ID: "worker.1"}
	unattributed := lifecycleProjection()
	unattributed.Subject = Subject{Type: "system", ID: ""}
	both := lifecycleProjection()
	both.Artifact = &EventArtifact{ArtifactID: "artifact.1", Digest: "sha256:" + strings.Repeat("d", 64), MediaType: "application/json", SizeBytes: 12}
	neither := lifecycleProjection()
	neither.Payload = nil
	for name, projection := range map[string]Projection{
		"unregistered subject": unregisteredSubject,
		"unattributed event":   unattributed,
		"payload and artifact": both,
		"neither body":         neither,
	} {
		if _, err := Project(projection, DefaultBounds()); err == nil {
			t.Fatalf("%s was projected", name)
		}
	}
}

// Sensitive material never reaches the public wire, whatever a producer puts
// in a payload: the projector applies the same prohibited-content denylist
// the durable read path applies, so redaction cannot be bypassed by writing
// through the projector.
func TestProjectionRedactsProhibitedContent(t *testing.T) {
	for _, leak := range []string{"the system prompt text", "a signedURL", "canvas state", "componentSource", "an API secret"} {
		projection := lifecycleProjection()
		projection.Payload = map[string]string{"previousState": "preparing", "state": leak}
		if _, err := Project(projection, DefaultBounds()); err == nil {
			t.Fatalf("a payload carrying %q reached the public wire", leak)
		}
	}
	// A prohibited field *name* cannot even be a registered vocabulary field,
	// so the projector refuses it at the vocabulary check. The denylist still
	// guards the read path, where bytes come from storage rather than from a
	// constructor.
	keyed := lifecycleProjection()
	keyed.Payload = map[string]string{"prompt": "planning"}
	if _, err := Project(keyed, DefaultBounds()); err == nil {
		t.Fatal("a prohibited payload field name reached the public wire")
	}
	stored := strings.Replace(validBoundedEvent, `"payload":{"state":"created"}`, `"payload":{"prompt":"leaked"}`, 1)
	if err := ValidateBytes([]byte(stored), DefaultBounds()); err == nil {
		t.Fatal("stored bytes carrying a prohibited field name were admitted on the read path")
	}
}

// The payload vocabulary is a rule the projector enforces, not a description
// of what it happens to emit: an extra, missing, or renamed field is refused,
// so a new public field cannot reach the wire without changing the registry
// the projector's pinned identity is computed from.
func TestProjectionRefusesPayloadsOutsideTheRegisteredVocabulary(t *testing.T) {
	extra := lifecycleProjection()
	extra.Payload = map[string]string{"previousState": "preparing", "state": "planning", "controlType": "internal"}
	missing := lifecycleProjection()
	missing.Payload = map[string]string{"state": "planning"}
	renamed := lifecycleProjection()
	renamed.Payload = map[string]string{"priorState": "preparing", "state": "planning"}
	foreign := lifecycleProjection()
	foreign.Payload = ProblemPayload("BUDGET_DENIED", "failed")
	artifactPayload := lifecycleProjection()
	artifactPayload.Type = TypeArtifactAvailable
	artifactPayload.Payload = StateChangedPayload("preparing", "planning")
	for name, projection := range map[string]Projection{
		"extra field":                  extra,
		"missing field":                missing,
		"renamed field":                renamed,
		"another type's vocabulary":    foreign,
		"payload on an artifact event": artifactPayload,
	} {
		if _, err := Project(projection, DefaultBounds()); err == nil {
			t.Fatalf("%s reached the public wire", name)
		}
	}
	// Every registered vocabulary still projects.
	for _, registered := range PublicEventTypes() {
		for _, vocabulary := range PublicPayloadVocabularies()[registered] {
			projection := lifecycleProjection()
			projection.Type = registered
			projection.Payload = map[string]string{}
			for _, field := range vocabulary {
				projection.Payload[field] = "v"
			}
			if _, err := Project(projection, DefaultBounds()); err != nil {
				t.Fatalf("registered vocabulary %v for %s was refused: %v", vocabulary, registered, err)
			}
		}
	}
}

// A projected event's body identity is bound to the envelope the store
// retains, so a run, event, or sequence identity cannot diverge between the
// bytes and the row that holds them.
func TestProjectedEventIdentityIsBoundToItsEnvelope(t *testing.T) {
	rendered, err := Project(lifecycleProjection(), DefaultBounds())
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateEnvelope(rendered, DefaultBounds(), "event.1", "run.1", 7); err != nil {
		t.Fatalf("the projected event failed its own envelope validation: %v", err)
	}
	for name, check := range map[string]func() error{
		"foreign event identity": func() error { return ValidateEnvelope(rendered, DefaultBounds(), "event.2", "run.1", 7) },
		"foreign run identity":   func() error { return ValidateEnvelope(rendered, DefaultBounds(), "event.1", "run.2", 7) },
		"foreign sequence":       func() error { return ValidateEnvelope(rendered, DefaultBounds(), "event.1", "run.1", 8) },
	} {
		if err := check(); err == nil {
			t.Fatalf("%s was accepted against the retained envelope", name)
		}
	}
}

// The projector's ruleset has one stable identity. Pinning it here is what
// turns any widening of the public surface — a new event type, a new payload
// field, a relaxed denylist — into a reviewed change rather than a silent
// one. Update this value only together with the governance decision that
// widened the registry.
func TestProjectorRulesetIdentityIsPinned(t *testing.T) {
	digest, err := ProjectorDigest()
	if err != nil {
		t.Fatal(err)
	}
	const pinned = "sha256:fac27f038df5df07c270a8051340f10b10cc1338806ee06b00c43edc77a5682b"
	if digest != pinned {
		t.Fatalf("projector ruleset digest=%s, want the pinned %s", digest, pinned)
	}
	if len(PublicEventTypes()) != 6 {
		t.Fatalf("the public registry holds %d types, want the governed six", len(PublicEventTypes()))
	}
	for _, registered := range PublicEventTypes() {
		if !PublicEventType(registered) {
			t.Fatalf("%q is listed in the registry but not recognized by it", registered)
		}
	}
}
