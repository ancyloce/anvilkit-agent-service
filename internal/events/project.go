package events

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/canonical"
)

// AgentEventSchemaURI pins the canonical AgentEvent contract every projected
// public event is validated against.
const AgentEventSchemaURI = "anvilkit://schema/agent-event?digest=sha256:2fdd8937381427507e721675ebbd66144595a193b53ba460534e9712df9b774a"

// The closed public event registry (ADR-020 §1). Internal step names never
// enter it; an unknown type fails projection rather than reaching the wire.
const (
	TypeRunCreated        = "run.created"
	TypeStateChanged      = "run.state-changed"
	TypeInputRequested    = "run.input-requested"
	TypeApprovalRequested = "run.approval-requested"
	TypeArtifactAvailable = "run.artifact-available"
	TypeProblemRecorded   = "run.problem-recorded"
)

// PublicEventType reports whether the value is one of the six registered
// public lifecycle event types.
func PublicEventType(value string) bool {
	switch value {
	case TypeRunCreated, TypeStateChanged, TypeInputRequested, TypeApprovalRequested, TypeArtifactAvailable, TypeProblemRecorded:
		return true
	default:
		return false
	}
}

// Subject is the public actor-or-system reference an event carries.
type Subject struct {
	Type string
	ID   string
}

// UserSubject attributes an event to the authenticated actor; SystemSubject
// attributes it to the service itself.
func UserSubject(actorID string) Subject { return Subject{Type: "user", ID: actorID} }
func SystemSubject() Subject             { return Subject{Type: "system", ID: "agent-service"} }

// EventArtifact is the bounded public artifact reference an
// run.artifact-available event carries.
type EventArtifact struct {
	ArtifactID string
	Digest     string
	MediaType  string
	SizeBytes  int64
}

// Projection describes one public event through the repository-owned
// allowlist: only the fields below can ever reach the public wire, and the
// payload maps below are the only payload vocabularies the projector accepts.
type Projection struct {
	WorkspaceID string
	ProjectID   string
	RunID       string
	Sequence    uint64
	EventID     string
	Type        string
	OccurredAt  time.Time
	Subject     Subject
	Traceparent string
	ContractBOM json.RawMessage
	Payload     map[string]string
	Artifact    *EventArtifact
	// evidenceID names the authoritative internal AgentEvidence record this
	// public event is projected from (ADR-020 §2). It is unexported and set
	// only by ProjectionEvidence, which derives it while building that record:
	// no caller, in production or in a test, can hand the projector an
	// evidence reference of its own choosing, and a projection that has not
	// been through ProjectionEvidence carries none and cannot be projected.
	evidenceID string
}

// Projected is one rendered public event together with the provenance every
// projection carries (ADR-020 §2): the authoritative Evidence the fact came
// from and the identity of the repository-owned ruleset that produced it.
// Both travel with the bytes so a durable writer records them beside the
// event rather than reconstructing them later.
type Projected struct {
	Bytes           []byte
	EvidenceID      string
	ProjectorDigest string
}

// CreatedPayload, StateChangedPayload, InputRequestedPayload,
// ApprovalRequestedPayload, and ProblemPayload are the complete public payload
// vocabularies. Internal vocabulary — control types, step names, provider or
// tool identifiers — never enters a public payload.
func CreatedPayload(state string) map[string]string {
	return map[string]string{"state": state}
}

func ChildCreatedPayload(parentRunID, rootRunID, state string) map[string]string {
	return map[string]string{"parentRunId": parentRunID, "rootRunId": rootRunID, "state": state}
}

func StateChangedPayload(previous, current string) map[string]string {
	return map[string]string{"previousState": previous, "state": current}
}

// InputRequestedPayload and ApprovalRequestedPayload carry the request
// identity together with the required version a responder must present
// (requestVersion for input responses, decisionVersion for approval
// decisions), so a client can drive the complete workflow from the governed
// public surface alone.
func InputRequestedPayload(requestID string, requestVersion uint64, expiresAt string) map[string]string {
	return map[string]string{"requestId": requestID, "requestVersion": strconv.FormatUint(requestVersion, 10), "expiresAt": expiresAt}
}

func ApprovalRequestedPayload(requestID, actionDigest string, decisionVersion uint64, expiresAt string) map[string]string {
	return map[string]string{"requestId": requestID, "actionDigest": actionDigest, "decisionVersion": strconv.FormatUint(decisionVersion, 10), "expiresAt": expiresAt}
}

func ProblemPayload(code, state string) map[string]string {
	return map[string]string{"code": code, "state": state}
}

// Project renders the canonical public event envelope. It is the only path
// internal facts take to the public wire: the type must be registered, the
// subject bounded, and the rendered bytes must survive the same envelope
// validation the read path applies. Everything not named in the Projection is
// projected away by construction.
func Project(projection Projection, bounds Bounds) (Projected, error) {
	if !PublicEventType(projection.Type) {
		return Projected{}, fmt.Errorf("public event projection: %q is not a registered public event type", projection.Type)
	}
	if projection.Subject.Type != "user" && projection.Subject.Type != "system" {
		return Projected{}, fmt.Errorf("public event projection: subject type %q is not registered", projection.Subject.Type)
	}
	if projection.Subject.ID == "" {
		return Projected{}, fmt.Errorf("public event projection: a subject identity is required")
	}
	if !opaqueIdentity(projection.evidenceID) {
		return Projected{}, fmt.Errorf("public event projection: a bounded source evidence reference is required; project through ProjectionEvidence")
	}
	if (projection.Payload != nil) == (projection.Artifact != nil) {
		return Projected{}, fmt.Errorf("public event projection: exactly one of payload or artifact reference is required")
	}
	// The payload's field set must be one the registry declares for this
	// event type. Without this the projector would accept any bounded map,
	// and a new field could reach the public wire without touching the
	// registry the projector's pinned identity is computed from.
	if projection.Payload != nil && !registeredPayload(projection.Type, projection.Payload) {
		return Projected{}, fmt.Errorf("public event projection: %q has no registered payload vocabulary matching the projected fields", projection.Type)
	}
	digest, err := ProjectorDigest()
	if err != nil {
		return Projected{}, err
	}
	envelope := map[string]any{
		"kind":                 "AgentEvent",
		"eventId":              projection.EventID,
		"runId":                projection.RunID,
		"workspaceId":          projection.WorkspaceID,
		"projectId":            projection.ProjectID,
		"sequence":             projection.Sequence,
		"eventType":            projection.Type,
		"occurredAt":           projection.OccurredAt.UTC().Format("2006-01-02T15:04:05.000Z"),
		"subject":              map[string]string{"subjectType": projection.Subject.Type, "subjectId": projection.Subject.ID},
		"traceContext":         map[string]string{"traceparent": projection.Traceparent},
		"contractBomReference": projection.ContractBOM,
	}
	if projection.Payload != nil {
		envelope["payload"] = projection.Payload
	}
	if projection.Artifact != nil {
		envelope["artifactReference"] = map[string]any{
			"artifactId": projection.Artifact.ArtifactID,
			"digest":     projection.Artifact.Digest,
			"mediaType":  projection.Artifact.MediaType,
			"sizeBytes":  projection.Artifact.SizeBytes,
		}
	}
	rendered, err := json.Marshal(envelope)
	if err != nil {
		return Projected{}, fmt.Errorf("render public event: %w", err)
	}
	if err := ValidateEnvelope(rendered, bounds, projection.EventID, projection.RunID, projection.Sequence); err != nil {
		return Projected{}, fmt.Errorf("validate projected public event: %w", err)
	}
	return Projected{Bytes: rendered, EvidenceID: projection.evidenceID, ProjectorDigest: digest}, nil
}

// PublicEventTypes lists the closed public registry in registry order. It is
// the projector's allowlist, readable by anything that has to prove nothing
// outside it is externally observable.
func PublicEventTypes() []string {
	return []string{TypeRunCreated, TypeStateChanged, TypeInputRequested, TypeApprovalRequested, TypeArtifactAvailable, TypeProblemRecorded}
}

// PublicSubjectTypes lists the registered subject kinds a public event may
// be attributed to.
func PublicSubjectTypes() []string { return []string{"system", "user"} }

// PublicPayloadVocabularies reports, per public event type, every field set a
// payload of that type may carry on the public wire. It is derived from the
// payload constructors themselves rather than restated beside them, so the
// reported vocabulary cannot drift away from the one the projector emits —
// and Project enforces it, so the vocabulary is a rule rather than a
// description. run.artifact-available carries no payload at all: it is
// projected through its bounded artifact reference.
func PublicPayloadVocabularies() map[string][][]string {
	return map[string][][]string{
		TypeRunCreated:        {payloadFields(CreatedPayload("")), payloadFields(ChildCreatedPayload("", "", ""))},
		TypeStateChanged:      {payloadFields(StateChangedPayload("", ""))},
		TypeInputRequested:    {payloadFields(InputRequestedPayload("", 0, ""))},
		TypeApprovalRequested: {payloadFields(ApprovalRequestedPayload("", "", 0, ""))},
		TypeProblemRecorded:   {payloadFields(ProblemPayload("", ""))},
		TypeArtifactAvailable: nil,
	}
}

func payloadFields(payload map[string]string) []string {
	fields := make([]string, 0, len(payload))
	for field := range payload {
		fields = append(fields, field)
	}
	sort.Strings(fields)
	return fields
}

// registeredPayload reports whether a payload's field set is one of the
// vocabularies registered for its event type.
func registeredPayload(eventType string, payload map[string]string) bool {
	for _, vocabulary := range PublicPayloadVocabularies()[eventType] {
		if len(vocabulary) != len(payload) {
			continue
		}
		matched := true
		for _, field := range vocabulary {
			if _, present := payload[field]; !present {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}

// ProjectorDigest is the identity of the repository-owned projection ruleset
// (ADR-020 §2): the closed event registry, the registered subject kinds, the
// complete public payload vocabularies, the prohibited-content categories,
// and the pinned AgentEvent contract that fixes the envelope itself. It is
// computed from the live rules, so widening what the projector can put on the
// public wire always changes it — and a pinned digest turns that into a
// reviewed change rather than a silent one.
func ProjectorDigest() (string, error) {
	ruleset, err := json.Marshal(map[string]any{
		"eventTypes":          PublicEventTypes(),
		"subjectTypes":        PublicSubjectTypes(),
		"payloadVocabularies": PublicPayloadVocabularies(),
		"prohibitedContent":   ProhibitedContentCategories(),
		"envelopeContract":    AgentEventSchemaURI,
	})
	if err != nil {
		return "", fmt.Errorf("render projector ruleset: %w", err)
	}
	digest, err := canonical.Digest(ruleset)
	if err != nil {
		return "", fmt.Errorf("digest projector ruleset: %w", err)
	}
	return digest, nil
}
