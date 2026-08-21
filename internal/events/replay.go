package events

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	contractvalidator "github.com/ancyloce/anvilkit-agent-service/contracts/validator"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
)

// Event is one durable public event as it is stored and replayed, including
// the provenance every projection carries (ADR-020 §2). The provenance is on
// the read path deliberately: a public fact whose source evidence and
// projection ruleset cannot be named from the stored row is not traceable,
// and a property nothing can observe is a property nothing can hold.
type Event struct {
	ID, RunID string
	Sequence  uint64
	Bytes     []byte
	// EvidenceID names the authoritative AgentEvidence this event was
	// projected from; ProjectorDigest is the identity of the ruleset that
	// produced it.
	EvidenceID      string
	ProjectorDigest string
	CreatedAt       time.Time
}
type ReplayRequest struct {
	Scope               Scope
	RunID, AfterEventID string
	Limit               int
}
type ReplayPage struct {
	Events          []Event
	CurrentCursor   string
	CurrentSequence uint64
	HasMore         bool
}

// AgentRunSnapshotSchemaURI pins the canonical AgentRunSnapshot contract the
// governed recovery response is proved against before it leaves the service.
const AgentRunSnapshotSchemaURI = "anvilkit://schema/agent-run-snapshot?digest=sha256:a75079baf5ecfa347ef501e113ac96abaedb8bdbcf0c06a1cfe568e065ac55db"

// AgentRunSnapshotKind is the canonical kind every rendered snapshot carries.
const AgentRunSnapshotKind = "AgentRunSnapshot"

type ArtifactProjection struct {
	ID                 string `json:"artifactId"`
	State              string `json:"state"`
	Digest             string `json:"digest"`
	SecurityGeneration uint64 `json:"securityGeneration"`
}

// SnapshotProjection is the run snapshot an expired-cursor client recovers
// through: the authoritative run resource, its governed artifact projections,
// and the durable public cursor to resume from.
type SnapshotProjection struct {
	Run       json.RawMessage
	Artifacts []ArtifactProjection
	Cursor    string
}

// MarshalJSON renders the canonical AgentRunSnapshot document. The kind and
// the artifact array are supplied here rather than carried as fields, so no
// caller can render a snapshot that misdeclares what it is or omits the
// artifact collection entirely. An absent cursor is omitted, which the
// contract reads as a run with no durable public event yet.
func (s SnapshotProjection) MarshalJSON() ([]byte, error) {
	artifacts := s.Artifacts
	if artifacts == nil {
		artifacts = []ArtifactProjection{}
	}
	type wire struct {
		Kind      string               `json:"kind"`
		Run       json.RawMessage      `json:"run"`
		Artifacts []ArtifactProjection `json:"artifacts"`
		Cursor    string               `json:"cursor,omitempty"`
	}
	return json.Marshal(wire{Kind: AgentRunSnapshotKind, Run: s.Run, Artifacts: artifacts, Cursor: s.Cursor})
}

// UnmarshalJSON reads the canonical document back, so a decoded snapshot and
// the one that was rendered are the same value.
func (s *SnapshotProjection) UnmarshalJSON(raw []byte) error {
	var wire struct {
		Run       json.RawMessage      `json:"run"`
		Artifacts []ArtifactProjection `json:"artifacts"`
		Cursor    string               `json:"cursor"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		return err
	}
	s.Run, s.Artifacts, s.Cursor = wire.Run, wire.Artifacts, wire.Cursor
	return nil
}

type Reader interface {
	Replay(context.Context, ReplayRequest) (ReplayPage, error)
	Snapshot(context.Context, Scope, string) (SnapshotProjection, error)
	Wait(context.Context, Scope, string, uint64, time.Duration) error
}

type Bounds struct{ MaximumBytes, MaximumFields, MaximumFieldBytes int }

func DefaultBounds() Bounds {
	return Bounds{MaximumBytes: 64 * 1024, MaximumFields: 32, MaximumFieldBytes: 512}
}

func (b Bounds) Validate() error {
	if b.MaximumBytes < 1 || b.MaximumFields < 1 || b.MaximumFieldBytes < 1 {
		return fmt.Errorf("event bounds must be positive")
	}
	return nil
}

func ValidateBytes(raw []byte, bounds Bounds) error {
	if err := bounds.Validate(); err != nil {
		return eventProblem(err.Error())
	}
	if len(raw) == 0 || len(raw) > bounds.MaximumBytes {
		return eventProblem("event exceeds byte bound")
	}
	if _, err := contractvalidator.Admit(raw); err != nil {
		return eventProblem("event violates strict JSON admission")
	}
	if prohibitedContent(string(raw)) {
		return eventProblem("event carries prohibited content")
	}
	var event struct {
		Kind                 string            `json:"kind"`
		EventID              string            `json:"eventId"`
		RunID                string            `json:"runId"`
		WorkspaceID          string            `json:"workspaceId"`
		ProjectID            string            `json:"projectId"`
		Sequence             uint64            `json:"sequence"`
		EventType            string            `json:"eventType"`
		OccurredAt           string            `json:"occurredAt"`
		Subject              json.RawMessage   `json:"subject"`
		TraceContext         json.RawMessage   `json:"traceContext"`
		ContractBOMReference json.RawMessage   `json:"contractBomReference"`
		TaskID               string            `json:"taskId,omitempty"`
		Payload              map[string]string `json:"payload,omitempty"`
		ArtifactReference    json.RawMessage   `json:"artifactReference,omitempty"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&event); err != nil {
		return eventProblem("event is not a JSON object")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return eventProblem("event must contain exactly one JSON object")
	}
	if event.Kind == "" || event.EventID == "" || event.RunID == "" || event.WorkspaceID == "" || event.ProjectID == "" || event.Sequence == 0 || event.EventType == "" || event.OccurredAt == "" || len(event.Subject) == 0 || len(event.TraceContext) == 0 || len(event.ContractBOMReference) == 0 {
		return eventProblem("event omits required correlation fields")
	}
	if !PublicEventType(event.EventType) {
		return eventProblem("event type is not in the public registry")
	}
	if event.Payload != nil {
		if len(event.Payload) > bounds.MaximumFields {
			return eventProblem("event payload has too many fields")
		}
		for key, value := range event.Payload {
			if len(key) > bounds.MaximumFieldBytes || len(value) > bounds.MaximumFieldBytes {
				return eventProblem("event payload fields must be bounded strings")
			}
		}
	}
	if event.Payload != nil && len(event.ArtifactReference) != 0 {
		return eventProblem("event cannot inline payload and artifact reference together")
	}
	return nil
}

func ValidateEnvelope(raw []byte, bounds Bounds, eventID, runID string, sequence uint64) error {
	if err := ValidateBytes(raw, bounds); err != nil {
		return err
	}
	var retained struct {
		EventID  string `json:"eventId"`
		RunID    string `json:"runId"`
		Sequence uint64 `json:"sequence"`
	}
	if err := json.Unmarshal(raw, &retained); err != nil {
		return eventProblem("event identity cannot be decoded")
	}
	if retained.EventID != eventID || retained.RunID != runID || sequence != 0 && retained.Sequence != sequence {
		return eventProblem("event body identity does not match its retained envelope")
	}
	return nil
}
func eventProblem(detail string) problem.Details {
	value := problem.New(problem.CodeEventInvalid, "")
	value.Detail = detail
	return value
}
func CursorExpired() problem.Details {
	value := problem.New(problem.CodeCursorExpired, "")
	value.Detail = "fetch the current run/artifact snapshot and resume from its cursor"
	value.Fields = map[string]string{"recovery": "snapshot-and-resume"}
	return value
}
func ValidateContiguous(events []Event, after uint64) error {
	expected := after + 1
	for _, event := range events {
		if event.Sequence != expected {
			return fmt.Errorf("event sequence gap: got %d want %d", event.Sequence, expected)
		}
		expected++
	}
	return nil
}
