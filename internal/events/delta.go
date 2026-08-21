package events

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// AgentStreamDeltaSchemaURI pins the canonical AgentStreamDelta contract.
const AgentStreamDeltaSchemaURI = "anvilkit://schema/agent-stream-delta?digest=sha256:0d64114cedd078202f1046fbadd7291544a590b9019422af77ce2f8c4cb8f590"

// Delta is one provisional stream fact (ADR-020 §4). It is not an AgentEvent
// and is never stored: it may be dropped, combined, or sampled, it can never
// advance the durable public cursor, and clients recover final state from
// durable events only.
type Delta struct {
	WorkspaceID string
	RunID       string
	Channel     string
	TurnID      string
	Traceparent string
	EmittedAt   time.Time
	Payload     map[string]string
}

// ValidateDelta enforces the provisional contract before anything reaches a
// subscriber: identities the canonical contract accepts, a registered
// channel, bounded payload facts, and the same prohibited-content denylist as
// every other outward shape.
//
// It is deliberately a complete precondition of the pinned AgentStreamDelta
// contract, not a looser sketch of it. A producer publishes a delta on a path
// that cannot fail the turn, so a delta that satisfies this and is then
// refused at the contract boundary would go missing in silence; keeping the
// two in step is what stops that from being possible.
func ValidateDelta(value Delta) error {
	if !opaqueIdentity(value.WorkspaceID) || !opaqueIdentity(value.RunID) {
		return fmt.Errorf("stream delta requires bounded workspace and run identities")
	}
	if value.TurnID != "" && !opaqueIdentity(value.TurnID) {
		return fmt.Errorf("stream delta turn identity is not a bounded opaque identifier")
	}
	if value.Traceparent != "" && !matches(traceparentPattern, value.Traceparent) {
		return fmt.Errorf("stream delta trace context is malformed")
	}
	switch value.Channel {
	case "token", "text", "field", "progress":
	default:
		return fmt.Errorf("stream delta channel %q is not registered", value.Channel)
	}
	if value.EmittedAt.IsZero() {
		return fmt.Errorf("stream delta requires its emission time")
	}
	if len(value.Payload) == 0 || len(value.Payload) > 16 {
		return fmt.Errorf("stream delta requires a bounded payload")
	}
	for key, field := range value.Payload {
		if key == "" || len(key) > 64 || len(field) > 1024 {
			return fmt.Errorf("stream delta payload facts must be bounded strings")
		}
		if prohibitedContent(key + " " + field) {
			return fmt.Errorf("stream delta carries prohibited content")
		}
	}
	return nil
}

// RenderDelta renders the canonical provisional wire shape. The provisional
// marker is a constant: no rendered delta can claim durability.
func RenderDelta(value Delta) ([]byte, error) {
	if err := ValidateDelta(value); err != nil {
		return nil, err
	}
	document := map[string]any{
		"kind":        "AgentStreamDelta",
		"runId":       value.RunID,
		"workspaceId": value.WorkspaceID,
		"channel":     value.Channel,
		"provisional": true,
		"emittedAt":   value.EmittedAt.UTC().Format(evidenceTimeLayout),
		"payload":     value.Payload,
	}
	if value.TurnID != "" {
		document["turnId"] = value.TurnID
	}
	if value.Traceparent != "" {
		document["traceContext"] = map[string]string{"traceparent": value.Traceparent}
	}
	rendered, err := json.Marshal(document)
	if err != nil {
		return nil, fmt.Errorf("render stream delta: %w", err)
	}
	return rendered, nil
}

// DeltaBroker fans provisional deltas to live stream subscribers. Nothing is
// stored and a subscriber that cannot keep up loses deltas silently — that is
// the contract, and final state never depends on them.
type DeltaBroker struct {
	lock        sync.Mutex
	subscribers map[string]map[int]chan []byte
	next        int
	dropped     int
	rejected    int
	validator   ContractValidator
}

// NewDeltaBroker builds the provisional channel. The contract validator is
// required: a delta reaches a live subscriber only after proving the
// canonical provisional contract, so a frame that claims durability cannot
// leave the service even if a producer renders one.
func NewDeltaBroker(validator ContractValidator) (*DeltaBroker, error) {
	if validator == nil {
		return nil, fmt.Errorf("stream delta broker: a contract validator is required")
	}
	return &DeltaBroker{subscribers: make(map[string]map[int]chan []byte), validator: validator}, nil
}

func deltaKey(workspaceID, runID string) string { return workspaceID + "\x00" + runID }

// Publish validates, renders, and delivers one delta to every live subscriber
// without ever blocking the producer: a full subscriber buffer drops the
// delta for that subscriber.
func (b *DeltaBroker) Publish(ctx context.Context, value Delta) error {
	rendered, err := RenderDelta(value)
	if err != nil {
		return err
	}
	if err := b.validator.Require(ctx, AgentStreamDeltaSchemaURI, rendered); err != nil {
		// A producer publishes on a path that must not fail the turn, so a
		// rejection here would otherwise be invisible. ValidateDelta is a
		// complete precondition of this contract, so reaching this is a
		// defect: count it so a silent streaming outage is diagnosable.
		b.lock.Lock()
		b.rejected++
		b.lock.Unlock()
		return fmt.Errorf("validate stream delta against its canonical contract: %w", err)
	}
	b.lock.Lock()
	defer b.lock.Unlock()
	for _, subscriber := range b.subscribers[deltaKey(value.WorkspaceID, value.RunID)] {
		select {
		case subscriber <- rendered:
		default:
			b.dropped++
		}
	}
	return nil
}

// Dropped reports how many deltas were dropped on full subscriber buffers.
// Rejected reports how many were refused by the canonical contract; it is
// zero unless ValidateDelta and the contract have drifted apart.
func (b *DeltaBroker) Dropped() int {
	b.lock.Lock()
	defer b.lock.Unlock()
	return b.dropped
}

func (b *DeltaBroker) Rejected() int {
	b.lock.Lock()
	defer b.lock.Unlock()
	return b.rejected
}

// Subscribe attaches a live consumer to one run's provisional channel. The
// returned cancel detaches it; pending frames are discarded.
func (b *DeltaBroker) Subscribe(workspaceID, runID string) (<-chan []byte, func()) {
	b.lock.Lock()
	defer b.lock.Unlock()
	key := deltaKey(workspaceID, runID)
	if b.subscribers[key] == nil {
		b.subscribers[key] = make(map[int]chan []byte)
	}
	id := b.next
	b.next++
	channel := make(chan []byte, 16)
	b.subscribers[key][id] = channel
	return channel, func() {
		b.lock.Lock()
		defer b.lock.Unlock()
		delete(b.subscribers[key], id)
		if len(b.subscribers[key]) == 0 {
			delete(b.subscribers, key)
		}
	}
}
