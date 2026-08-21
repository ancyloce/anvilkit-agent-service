package events

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	contractguard "github.com/ancyloce/anvilkit-agent-service/internal/contracts"
)

func validDelta() Delta {
	return Delta{
		WorkspaceID: "workspace.1",
		RunID:       "run.1",
		Channel:     "progress",
		TurnID:      "workflow-1:turn-1",
		Traceparent: "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01",
		EmittedAt:   time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC),
		Payload:     map[string]string{"turn": "1", "decision": "continue"},
	}
}

// newTestDeltaBroker builds the provisional channel over the real pinned
// contract material, so a test frame is held to exactly the contract a live
// subscriber's frame is.
func newTestDeltaBroker(t *testing.T) *DeltaBroker {
	t.Helper()
	guard, err := contractguard.NewGuard("../..")
	if err != nil {
		t.Fatal(err)
	}
	broker, err := NewDeltaBroker(guard.At(contractguard.DeltaOut))
	if err != nil {
		t.Fatal(err)
	}
	return broker
}

// Rendered deltas satisfy the canonical AgentStreamDelta contract, and the
// provisional marker is a constant: a delta claiming durability fails the
// pinned schema.
func TestRenderedDeltaSatisfiesTheCanonicalContract(t *testing.T) {
	guard, err := contractguard.NewGuard("../..")
	if err != nil {
		t.Fatal(err)
	}
	rendered, err := RenderDelta(validDelta())
	if err != nil {
		t.Fatal(err)
	}
	if err := guard.Require(context.Background(), contractguard.EventIn, AgentStreamDeltaSchemaURI, rendered); err != nil {
		t.Fatalf("rendered delta violates AgentStreamDelta: %v\n%s", err, rendered)
	}
	durable := strings.Replace(string(rendered), `"provisional":true`, `"provisional":false`, 1)
	if err := guard.Require(context.Background(), contractguard.EventIn, AgentStreamDeltaSchemaURI, []byte(durable)); err == nil {
		t.Fatal("a delta claiming durability satisfied the provisional contract")
	}
}

func TestDeltaValidationFailsClosed(t *testing.T) {
	unregistered := validDelta()
	unregistered.Channel = "durable"
	if err := ValidateDelta(unregistered); err == nil {
		t.Fatal("an unregistered delta channel was accepted")
	}
	leaking := validDelta()
	leaking.Payload = map[string]string{"partial": "the system prompt was"}
	if err := ValidateDelta(leaking); err == nil {
		t.Fatal("prohibited delta content was accepted")
	}
}

// The broker never blocks a producer: a subscriber that cannot keep up loses
// deltas, and losing them changes nothing durable.
func TestDeltaBrokerDropsOnFullSubscriberWithoutBlocking(t *testing.T) {
	broker := newTestDeltaBroker(t)
	frames, cancel := broker.Subscribe("workspace.1", "run.1")
	defer cancel()
	for i := 0; i < 24; i++ {
		if err := broker.Publish(context.Background(), validDelta()); err != nil {
			t.Fatal(err)
		}
	}
	if broker.Dropped() < 8 {
		t.Fatalf("dropped=%d, want at least 8 with a full 16-frame buffer", broker.Dropped())
	}
	frame := <-frames
	if !strings.Contains(string(frame), `"provisional":true`) {
		t.Fatalf("delivered frame is not provisional: %s", frame)
	}
}

// A delta frame carries no SSE id line, so the durable cursor recorded on
// disconnect is the last durable event — never a provisional delta.
func TestDeltaFramesNeverAdvanceTheDurableCursor(t *testing.T) {
	broker := newTestDeltaBroker(t)
	recorder := &MemoryCursorRecorder{}
	reader := &oneShotReader{event: boundedEvent("event.1", 1)}
	stream, err := NewStream(reader, allowAllStreamAuthority{}, StreamConfig{Heartbeat: time.Second, Revalidation: time.Second, ReplayLimit: 100, Bounds: Bounds{MaximumBytes: 1024, MaximumFields: 4, MaximumFieldBytes: 32}, Cursors: recorder, CursorSpool: recorder, CursorFailures: recorder, Deltas: broker})
	if err != nil {
		t.Fatal(err)
	}
	writer := newCaptureStreamWriter()
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() {
		served <- stream.Serve(ctx, writer, Scope{WorkspaceID: "workspace.1", ProjectID: "project.1"}, "run.1", "")
	}()
	deadline := time.Now().Add(3 * time.Second)
	for !strings.Contains(writer.String(), "agent-stream-delta") {
		if time.Now().After(deadline) {
			t.Fatalf("no delta frame was delivered; output:\n%s", writer.String())
		}
		_ = broker.Publish(context.Background(), validDelta())
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-served; err == nil {
		t.Fatal("a cancelled stream must return its cancellation")
	}
	output := writer.String()
	if !strings.Contains(output, "id: event.1\nevent: agent-event") {
		t.Fatalf("the durable event frame is missing:\n%s", output)
	}
	for _, frame := range strings.Split(output, "\n\n") {
		if strings.Contains(frame, "agent-stream-delta") && strings.Contains(frame, "id:") {
			t.Fatalf("a provisional delta frame carried an SSE id:\n%s", frame)
		}
	}
	recorded := recorder.Recorded()
	if len(recorded) != 1 || recorded[0].LastEventID != "event.1" {
		t.Fatalf("recorded cursor = %+v, want the durable event.1", recorded)
	}
}

// oneShotReader serves its event exactly once, then waits: the shape of a
// live stream that has caught up.
type oneShotReader struct {
	lock   sync.Mutex
	event  Event
	served bool
}

func (r *oneShotReader) Replay(context.Context, ReplayRequest) (ReplayPage, error) {
	r.lock.Lock()
	defer r.lock.Unlock()
	if r.served {
		return ReplayPage{CurrentCursor: r.event.ID, CurrentSequence: r.event.Sequence}, nil
	}
	r.served = true
	return ReplayPage{Events: []Event{r.event}, CurrentCursor: r.event.ID, CurrentSequence: r.event.Sequence}, nil
}
func (*oneShotReader) Snapshot(context.Context, Scope, string) (SnapshotProjection, error) {
	return SnapshotProjection{}, nil
}
func (*oneShotReader) Wait(ctx context.Context, _ Scope, _ string, _ uint64, timeout time.Duration) error {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// captureStreamWriter is a concurrency-safe capture of everything the stream
// wrote.
type captureStreamWriter struct {
	lock   sync.Mutex
	buffer bytes.Buffer
	header map[string][]string
}

func newCaptureStreamWriter() *captureStreamWriter {
	return &captureStreamWriter{header: map[string][]string{}}
}

func (w *captureStreamWriter) Header() http.Header { return http.Header(w.header) }
func (w *captureStreamWriter) WriteHeader(int)     {}
func (w *captureStreamWriter) Flush()              {}
func (w *captureStreamWriter) Write(raw []byte) (int, error) {
	w.lock.Lock()
	defer w.lock.Unlock()
	return w.buffer.Write(raw)
}
func (w *captureStreamWriter) String() string {
	w.lock.Lock()
	defer w.lock.Unlock()
	return w.buffer.String()
}

// The provisional channel refuses to build without contract proof, and a
// delta that reaches the broker is proven against the canonical provisional
// contract before any subscriber sees it. A frame that claims durability is
// refused at publish time, not merely at render time.
func TestProvisionalChannelRefusesDeltasClaimingDurability(t *testing.T) {
	if _, err := NewDeltaBroker(nil); err == nil {
		t.Fatal("a provisional channel was built without contract proof")
	}
	broker := newTestDeltaBroker(t)
	frames, cancel := broker.Subscribe("workspace.1", "run.1")
	defer cancel()
	durabilityClaim := validDelta()
	durabilityClaim.Payload = map[string]string{"sequence": "1", "durable": "true"}
	// The claim is only a bounded payload fact, so it delivers: a delta
	// cannot express durability through its payload at all. What it can never
	// do is carry the envelope a durable event carries.
	if err := broker.Publish(context.Background(), durabilityClaim); err != nil {
		t.Fatal(err)
	}
	frame := <-frames
	if err := ValidateBytes(frame, DefaultBounds()); err == nil {
		t.Fatalf("a provisional frame validated as a durable public event: %s", frame)
	}
	if bytes.Contains(frame, []byte(`"kind":"AgentEvent"`)) || bytes.Contains(frame, []byte(`"eventId"`)) || !bytes.Contains(frame, []byte(`"provisional":true`)) {
		t.Fatalf("provisional frame carries durable-event identity: %s", frame)
	}
	// A rendered frame that is edited to claim durability is refused by the
	// canonical contract before it can be delivered.
	guard, err := contractguard.NewGuard("../..")
	if err != nil {
		t.Fatal(err)
	}
	forged := bytes.Replace(frame, []byte(`"provisional":true`), []byte(`"provisional":false`), 1)
	if err := guard.Require(context.Background(), contractguard.DeltaOut, AgentStreamDeltaSchemaURI, forged); err == nil {
		t.Fatal("a delta claiming durability passed the provisional contract")
	}
}

// A provisional channel cannot be built from a guard that was never
// configured: the bound validator is absent rather than merely broken, so a
// miswired composition fails where it is built.
func TestProvisionalChannelRefusesAnUnboundValidator(t *testing.T) {
	var absent *contractguard.Guard
	if _, err := NewDeltaBroker(absent.At(contractguard.DeltaOut)); err == nil {
		t.Fatal("a provisional channel was built from an unconfigured guard")
	}
	guard, err := contractguard.NewGuard("../..")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewDeltaBroker(guard.At("not-a-boundary")); err == nil {
		t.Fatal("a provisional channel was built on an unregistered trust boundary")
	}
}

// Delta validation is a complete precondition of the canonical contract, so
// anything it accepts is publishable and nothing it accepts is later refused
// at the boundary — the rejection counter stays at zero.
func TestDeltaValidationIsACompletePreconditionOfTheContract(t *testing.T) {
	overlong := strings.Repeat("a", 129)
	for name, mutate := range map[string]func(*Delta){
		"overlong turn identity": func(d *Delta) { d.TurnID = overlong },
		"malformed run identity": func(d *Delta) { d.RunID = "run/1" },
		"overlong workspace":     func(d *Delta) { d.WorkspaceID = overlong },
		"malformed trace":        func(d *Delta) { d.Traceparent = "not-a-traceparent" },
	} {
		value := validDelta()
		mutate(&value)
		if err := ValidateDelta(value); err == nil {
			t.Fatalf("%s was accepted by delta validation", name)
		}
	}
	broker := newTestDeltaBroker(t)
	for _, channel := range []string{"token", "text", "field", "progress"} {
		value := validDelta()
		value.Channel = channel
		value.TurnID = strings.Repeat("t", 128)
		if err := broker.Publish(context.Background(), value); err != nil {
			t.Fatalf("a delta at the accepted bounds was refused: %v", err)
		}
	}
	if broker.Rejected() != 0 {
		t.Fatalf("the canonical contract refused %d deltas that validation accepted", broker.Rejected())
	}
}
