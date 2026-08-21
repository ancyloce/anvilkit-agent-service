package events

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
)

type allowAllStreamAuthority struct{}

func (allowAllStreamAuthority) Revalidate(context.Context) error { return nil }

// failingStreamWriter accepts a bounded number of writes then behaves like a
// stalled client whose socket write fails.
type failingStreamWriter struct {
	header http.Header
	allow  int
	writes int
}

func newFailingStreamWriter(allow int) *failingStreamWriter {
	return &failingStreamWriter{header: http.Header{}, allow: allow}
}

func (w *failingStreamWriter) Header() http.Header { return w.header }
func (w *failingStreamWriter) WriteHeader(int)     {}
func (w *failingStreamWriter) Flush()              {}
func (w *failingStreamWriter) Write(raw []byte) (int, error) {
	if w.writes >= w.allow {
		return 0, errors.New("client stalled")
	}
	w.writes++
	return len(raw), nil
}

func boundedEvent(id string, sequence uint64) Event {
	bytes := strings.Replace(validBoundedEvent, `"eventId":"event.1"`, fmt.Sprintf("%q:%q", "eventId", id), 1)
	bytes = strings.Replace(bytes, `"sequence":1`, fmt.Sprintf(`"sequence":%d`, sequence), 1)
	return Event{ID: id, RunID: "run.1", Sequence: sequence, CreatedAt: time.Now(), Bytes: []byte(bytes)}
}

// A consumer that cannot keep up is disconnected instead of holding the
// stream, and the disconnect durably records the last cursor it actually
// received.
func TestSlowConsumerDisconnectRecordsLastSentCursor(t *testing.T) {
	reader := &fixedPageReader{events: []Event{boundedEvent("event.1", 1), boundedEvent("event.2", 2)}}
	recorder := &MemoryCursorRecorder{}
	stream, err := NewStream(reader, allowAllStreamAuthority{}, StreamConfig{Heartbeat: time.Second, Revalidation: time.Second, ReplayLimit: 100, Bounds: Bounds{MaximumBytes: 1024, MaximumFields: 4, MaximumFieldBytes: 32}, Cursors: recorder})
	if err != nil {
		t.Fatal(err)
	}
	writer := newFailingStreamWriter(1)
	err = stream.Serve(context.Background(), writer, Scope{WorkspaceID: "workspace.1", ProjectID: "project.1"}, "run.1", "")
	if err == nil {
		t.Fatal("a stalled consumer must disconnect the stream")
	}
	recorded := recorder.Recorded()
	if len(recorded) != 1 || recorded[0].Reason != "slow-consumer" || recorded[0].LastEventID != "event.1" {
		t.Fatalf("recorded cursor = %+v, want slow-consumer at event.1", recorded)
	}
}

// A client that goes away records the cursor it had, so operations can see
// exactly what every ended connection observed.
func TestClientDisconnectRecordsDeliveredCursor(t *testing.T) {
	reader := onePageReader{event: boundedEvent("event.1", 1)}
	recorder := &MemoryCursorRecorder{}
	stream, err := NewStream(reader, allowAllStreamAuthority{}, StreamConfig{Heartbeat: time.Second, Revalidation: time.Second, ReplayLimit: 100, Bounds: Bounds{MaximumBytes: 1024, MaximumFields: 4, MaximumFieldBytes: 32}, Cursors: recorder})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	writer := newFailingStreamWriter(100)
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	if err := stream.Serve(ctx, writer, Scope{WorkspaceID: "workspace.1", ProjectID: "project.1"}, "run.1", ""); err == nil {
		t.Fatal("a cancelled stream must return the cancellation")
	}
	recorded := recorder.Recorded()
	if len(recorded) != 1 || recorded[0].Reason != "client-closed" || recorded[0].LastEventID != "event.1" {
		t.Fatalf("recorded cursor = %+v, want client-closed at event.1", recorded)
	}
}

// The per-instance connection cap fails closed with a stable overload
// problem; a second connection cannot degrade the first.
func TestStreamConnectionCapFailsClosed(t *testing.T) {
	reader := onePageReader{}
	stream, err := NewStream(reader, allowAllStreamAuthority{}, StreamConfig{Heartbeat: time.Second, Revalidation: time.Second, ReplayLimit: 100, Bounds: Bounds{MaximumBytes: 1024, MaximumFields: 4, MaximumFieldBytes: 32}, MaximumConnections: 1})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first := make(chan error, 1)
	go func() {
		first <- stream.Serve(ctx, newFailingStreamWriter(100), Scope{WorkspaceID: "workspace.1", ProjectID: "project.1"}, "run.1", "")
	}()
	deadline := time.Now().Add(2 * time.Second)
	for len(stream.active) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the first stream never became active")
		}
		time.Sleep(5 * time.Millisecond)
	}
	err = stream.Serve(context.Background(), newFailingStreamWriter(100), Scope{WorkspaceID: "workspace.1", ProjectID: "project.1"}, "run.1", "")
	var details problem.Details
	if !errors.As(err, &details) || details.Code != string(problem.CodeAdmissionOverloaded) {
		t.Fatalf("second stream = %v, want ADMISSION_OVERLOADED", err)
	}
	cancel()
	if err := <-first; err == nil {
		t.Fatal("the first stream must end with its cancellation")
	}
}
