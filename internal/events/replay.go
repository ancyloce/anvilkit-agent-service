package events

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
)

type Event struct {
	ID, RunID string
	Sequence  uint64
	Bytes     []byte
	CreatedAt time.Time
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
type ArtifactProjection struct {
	ID, State, Digest  string `json:",omitempty"`
	SecurityGeneration uint64 `json:",omitempty"`
}
type SnapshotProjection struct {
	Run       json.RawMessage      `json:"run"`
	Artifacts []ArtifactProjection `json:"artifacts"`
	Cursor    string               `json:"cursor"`
}
type Reader interface {
	Replay(context.Context, ReplayRequest) (ReplayPage, error)
	Snapshot(context.Context, Scope, string) (SnapshotProjection, error)
	Wait(context.Context, Scope, string, uint64, time.Duration) error
}

type Bounds struct{ MaximumBytes, MaximumFields, MaximumFieldBytes int }

func ValidateBytes(raw []byte, bounds Bounds) error {
	if bounds.MaximumBytes < 1 || len(raw) == 0 || len(raw) > bounds.MaximumBytes {
		return eventProblem("event exceeds byte bound")
	}
	for _, prohibited := range []string{"prompt", "puckData", "canvas", "pageIR", "componentSource", "imageBytes", "signedURL", "continuation", "secret"} {
		if strings.Contains(strings.ToLower(string(raw)), strings.ToLower(prohibited)) {
			return eventProblem("event carries prohibited content")
		}
	}
	var event struct {
		APIVersion           string            `json:"apiVersion"`
		Kind                 string            `json:"kind"`
		EventID              string            `json:"eventId"`
		RunID                string            `json:"runId"`
		Sequence             uint64            `json:"sequence"`
		EventType            string            `json:"eventType"`
		OccurredAt           string            `json:"occurredAt"`
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
	if event.APIVersion == "" || event.Kind == "" || event.EventID == "" || event.RunID == "" || event.Sequence == 0 || event.EventType == "" || event.OccurredAt == "" || len(event.TraceContext) == 0 || len(event.ContractBOMReference) == 0 {
		return eventProblem("event omits required correlation fields")
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
