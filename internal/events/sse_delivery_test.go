package events

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"
)

// deadlineWriter is a stream writer whose write-deadline support is
// configurable, so a test can state whether the deployment's protection is
// actually available.
type deadlineWriter struct {
	header    http.Header
	supported bool
	deadlines int
}

func (w *deadlineWriter) Header() http.Header { return w.header }
func (w *deadlineWriter) WriteHeader(int)     {}
func (w *deadlineWriter) Flush()              {}
func (w *deadlineWriter) Write(raw []byte) (int, error) {
	return len(raw), nil
}

func (w *deadlineWriter) SetWriteDeadline(time.Time) error {
	if !w.supported {
		return http.ErrNotSupported
	}
	w.deadlines++
	return nil
}

// flushFailingWriter accepts writes but cannot hand them to the client. It is
// the case that matters most: the bytes leave the handler, the client never
// gets them, and only the flush knows.
type flushFailingWriter struct {
	header  http.Header
	allow   int
	flushes int
}

func (w *flushFailingWriter) Header() http.Header              { return w.header }
func (w *flushFailingWriter) WriteHeader(int)                  {}
func (w *flushFailingWriter) Write(raw []byte) (int, error)    { return len(raw), nil }
func (w *flushFailingWriter) SetWriteDeadline(time.Time) error { return nil }
func (w *flushFailingWriter) FlushError() error {
	w.flushes++
	if w.flushes > w.allow {
		return errors.New("client is not reading")
	}
	return nil
}

func deliveryStream(t *testing.T, reader Reader, recorder *MemoryCursorRecorder, writeTimeout time.Duration) *Stream {
	t.Helper()
	config := StreamConfig{Heartbeat: time.Second, Revalidation: time.Second, ReplayLimit: 100, Bounds: Bounds{MaximumBytes: 1024, MaximumFields: 4, MaximumFieldBytes: 32}, WriteTimeout: writeTimeout}
	if recorder != nil {
		config.Cursors, config.CursorSpool, config.CursorFailures = recorder, recorder, recorder
	}
	stream, err := NewStream(reader, allowAllStreamAuthority{}, config)
	if err != nil {
		t.Fatal(err)
	}
	return stream
}

// A deployment that configures a write deadline gets one. A response writer
// that cannot carry a deadline fails the stream instead of serving it with the
// protection silently switched off — an unbounded stream goroutine held by a
// stalled consumer is the failure this deadline exists to prevent.
func TestUnsupportedWriteDeadlinesFailClosed(t *testing.T) {
	reader := &fixedPageReader{events: []Event{boundedEvent("event.1", 1)}}
	unsupported := &deadlineWriter{header: http.Header{}}
	err := deliveryStream(t, reader, nil, 50*time.Millisecond).Serve(context.Background(), unsupported, Scope{WorkspaceID: "workspace.1", ProjectID: "project.1"}, "run.1", "")
	if err == nil {
		t.Fatal("a stream served a write deadline it cannot enforce")
	}
	if unsupported.deadlines != 0 {
		t.Fatalf("deadlines set=%d on a writer that supports none", unsupported.deadlines)
	}

	supported := &deadlineWriter{header: http.Header{}, supported: true}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if err := deliveryStream(t, reader, nil, 50*time.Millisecond).Serve(ctx, supported, Scope{WorkspaceID: "workspace.1", ProjectID: "project.1"}, "run.1", ""); err == nil {
		t.Fatal("the stream must end with its cancellation")
	}
	if supported.deadlines == 0 {
		t.Fatal("a supported write deadline was never set")
	}
}

// A frame that was written but never flushed is a frame the client does not
// have. The stream ends, and the durable cursor stays where delivery last
// actually succeeded rather than counting the undelivered frame.
func TestFlushFailureEndsTheStreamWithoutAdvancingTheCursor(t *testing.T) {
	reader := &fixedPageReader{events: []Event{boundedEvent("event.1", 1), boundedEvent("event.2", 2)}}
	recorder := &MemoryCursorRecorder{}
	writer := &flushFailingWriter{header: http.Header{}, allow: 1}
	err := deliveryStream(t, reader, recorder, 50*time.Millisecond).Serve(context.Background(), writer, Scope{WorkspaceID: "workspace.1", ProjectID: "project.1"}, "run.1", "")
	if err == nil {
		t.Fatal("a stream whose frames never reach the client must end")
	}
	recorded := recorder.Recorded()
	if len(recorded) != 1 || recorded[0].Reason != "slow-consumer" || recorded[0].LastEventID != "event.1" {
		t.Fatalf("recorded cursor=%+v, want slow-consumer at the last delivered event.1", recorded)
	}
}

// The very first frame failing to flush records no cursor at all: a
// connection that delivered nothing must not claim it delivered something.
func TestUndeliveredFirstFrameRecordsNoCursor(t *testing.T) {
	reader := &fixedPageReader{events: []Event{boundedEvent("event.1", 1)}}
	recorder := &MemoryCursorRecorder{}
	writer := &flushFailingWriter{header: http.Header{}}
	if err := deliveryStream(t, reader, recorder, 50*time.Millisecond).Serve(context.Background(), writer, Scope{WorkspaceID: "workspace.1", ProjectID: "project.1"}, "run.1", ""); err == nil {
		t.Fatal("a stream whose first frame never reached the client must end")
	}
	recorded := recorder.Recorded()
	if len(recorded) != 1 || recorded[0].LastEventID != "" {
		t.Fatalf("recorded cursor=%+v, want an empty cursor for a connection that delivered nothing", recorded)
	}
}

// A disconnect record the authoritative store keeps refusing is retried
// briefly and then held durably. It is not reported and dropped: the record is
// the only account of what the disconnected client had, so a store outage must
// move it to the durable retry path rather than turn it into a counter.
func TestCursorPersistenceFailureEntersTheDurableRetryPath(t *testing.T) {
	reader := &fixedPageReader{events: []Event{boundedEvent("event.1", 1), boundedEvent("event.2", 2)}}
	recorder := &MemoryCursorRecorder{}
	recorder.RefuseCursorRecords(fmt.Errorf("cursor store unavailable"))
	writer := newFailingStreamWriter(1)
	if err := deliveryStream(t, reader, recorder, 0).Serve(context.Background(), writer, Scope{WorkspaceID: "workspace.1", ProjectID: "project.1"}, "run.1", ""); err == nil {
		t.Fatal("a stalled consumer must disconnect the stream")
	}
	if recorded := recorder.Recorded(); len(recorded) != 0 {
		t.Fatalf("recorded cursors=%+v, want none to have persisted", recorded)
	}
	spooled := recorder.Spooled()
	if len(spooled) != 1 || spooled[0].Reason != "slow-consumer" || spooled[0].LastEventID != "event.1" || spooled[0].RunID != "run.1" {
		t.Fatalf("durably held records=%+v, want the slow-consumer record at event.1", spooled)
	}
	if spooled[0].ConnectionID == "" {
		t.Fatalf("durably held record=%+v, want the connection identity it belongs to", spooled[0])
	}
	if failures := recorder.Failures(); len(failures) != 0 {
		t.Fatalf("reported failures=%+v, want a held record reported as lost by nobody", failures)
	}
}

// Only a record neither durable path would take is reported, and it is
// reported as a loss. The report is the last resort, never the fallback.
func TestCursorRecordIsReportedOnlyWhenBothDurablePathsRefuse(t *testing.T) {
	reader := &fixedPageReader{events: []Event{boundedEvent("event.1", 1), boundedEvent("event.2", 2)}}
	recorder := &MemoryCursorRecorder{}
	recorder.RefuseCursorRecords(fmt.Errorf("cursor store unavailable"))
	recorder.RefuseCursorSpool(fmt.Errorf("durable volume unavailable"))
	writer := newFailingStreamWriter(1)
	if err := deliveryStream(t, reader, recorder, 0).Serve(context.Background(), writer, Scope{WorkspaceID: "workspace.1", ProjectID: "project.1"}, "run.1", ""); err == nil {
		t.Fatal("a stalled consumer must disconnect the stream")
	}
	if recorded, spooled := recorder.Recorded(), recorder.Spooled(); len(recorded) != 0 || len(spooled) != 0 {
		t.Fatalf("recorded=%+v held=%+v, want neither durable path to have taken the record", recorded, spooled)
	}
	failures := recorder.Failures()
	if len(failures) != 1 || failures[0].Reason != "slow-consumer" || failures[0].LastEventID != "event.1" {
		t.Fatalf("reported failures=%+v, want the lost slow-consumer record at event.1", failures)
	}
}

// A durable cursor recorder with no durable retry path behind it is not a
// configuration this stream will serve: a store outage would silently turn the
// governed disconnect record into a lost one.
func TestDurableCursorRecorderRequiresADurableSpool(t *testing.T) {
	_, err := NewStream(&fixedPageReader{}, allowAllStreamAuthority{}, StreamConfig{
		Heartbeat: time.Second, Revalidation: time.Second, ReplayLimit: 100,
		Bounds: DefaultBounds(), Cursors: &MemoryCursorRecorder{}, CursorFailures: &MemoryCursorRecorder{},
	})
	if err == nil {
		t.Fatal("a cursor recorder without a durable spool was accepted")
	}
}

// A durable cursor recorder with nowhere to report a record neither durable
// path could take is not a configuration this stream will serve either.
func TestDurableCursorRecorderRequiresAFailureObserver(t *testing.T) {
	recorder := &MemoryCursorRecorder{}
	_, err := NewStream(&fixedPageReader{}, allowAllStreamAuthority{}, StreamConfig{
		Heartbeat: time.Second, Revalidation: time.Second, ReplayLimit: 100,
		Bounds: DefaultBounds(), Cursors: recorder, CursorSpool: recorder,
	})
	if err == nil {
		t.Fatal("a cursor recorder without a failure observer was accepted")
	}
}
