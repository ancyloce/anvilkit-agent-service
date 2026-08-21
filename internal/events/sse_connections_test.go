package events

import (
	"context"
	"regexp"
	"strings"
	"testing"
	"time"
)

// runHistoryReader serves one run's durable history honouring the caller's
// cursor, then holds open the way the durable reader does while a run is
// still live. It is the double a connection-level test needs: two connections
// must be able to read the same history independently.
type runHistoryReader struct{ events []Event }

func (r *runHistoryReader) Replay(_ context.Context, request ReplayRequest) (ReplayPage, error) {
	var after uint64
	if request.AfterEventID != "" {
		found := false
		for _, event := range r.events {
			if event.ID == request.AfterEventID {
				after, found = event.Sequence, true
				break
			}
		}
		if !found {
			return ReplayPage{}, CursorExpired()
		}
	}
	page := ReplayPage{CurrentCursor: request.AfterEventID, CurrentSequence: after}
	for _, event := range r.events {
		if event.Sequence > after {
			page.Events = append(page.Events, event)
		}
	}
	if len(page.Events) > 0 {
		last := page.Events[len(page.Events)-1]
		page.CurrentCursor, page.CurrentSequence = last.ID, last.Sequence
	}
	return page, nil
}

func (*runHistoryReader) Snapshot(context.Context, Scope, string) (SnapshotProjection, error) {
	return SnapshotProjection{}, nil
}

func (*runHistoryReader) Wait(ctx context.Context, _ Scope, _ string, _ uint64, timeout time.Duration) error {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

var streamEventFrame = regexp.MustCompile(`(?m)^id: (\S+)$`)

func deliveredCursors(output string) []string {
	var delivered []string
	for _, match := range streamEventFrame.FindAllStringSubmatch(output, -1) {
		delivered = append(delivered, match[1])
	}
	return delivered
}

func serveUntilDelivered(t *testing.T, stream *Stream, cursor string, want int) (*captureStreamWriter, func() []string) {
	t.Helper()
	writer := newCaptureStreamWriter()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = stream.Serve(ctx, writer, Scope{WorkspaceID: "workspace.1", ProjectID: "project.1"}, "run.1", cursor)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for len(deliveredCursors(writer.String())) < want {
		if time.Now().After(deadline) {
			cancel()
			<-done
			t.Fatalf("stream delivered %d of %d events; output:\n%s", len(deliveredCursors(writer.String())), want, writer.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
	return writer, func() []string {
		cancel()
		<-done
		return deliveredCursors(writer.String())
	}
}

// Two live connections to one run are independent and deterministic: each
// replays the identical durable history in the identical order, and each ends
// with its own durable cursor record under its own connection identity. A
// second connection neither steals nor duplicates the first one's stream.
func TestDuplicateConnectionsToOneRunAreIndependentAndDeterministic(t *testing.T) {
	reader := &runHistoryReader{events: []Event{boundedEvent("event.1", 1), boundedEvent("event.2", 2), boundedEvent("event.3", 3)}}
	recorder := &MemoryCursorRecorder{}
	stream, err := NewStream(reader, allowAllStreamAuthority{}, StreamConfig{Heartbeat: 50 * time.Millisecond, Revalidation: time.Second, ReplayLimit: 100, Bounds: DefaultBounds(), Cursors: recorder, CursorSpool: recorder, CursorFailures: recorder})
	if err != nil {
		t.Fatal(err)
	}
	_, firstDelivered := serveUntilDelivered(t, stream, "", 3)
	_, secondDelivered := serveUntilDelivered(t, stream, "", 3)
	first, second := firstDelivered(), secondDelivered()
	want := []string{"event.1", "event.2", "event.3"}
	for name, delivered := range map[string][]string{"first connection": first, "second connection": second} {
		if strings.Join(delivered, ",") != strings.Join(want, ",") {
			t.Fatalf("%s delivered %v, want the deterministic %v", name, delivered, want)
		}
	}
	recorded := recorder.Recorded()
	if len(recorded) != 2 {
		t.Fatalf("recorded %d connection cursors, want one per connection: %+v", len(recorded), recorded)
	}
	if recorded[0].ConnectionID == recorded[1].ConnectionID {
		t.Fatalf("both connections recorded under one identity: %+v", recorded)
	}
	for _, record := range recorded {
		if record.LastEventID != "event.3" || record.RunID != "run.1" || record.Reason != "client-closed" {
			t.Fatalf("connection cursor = %+v, want client-closed at event.3", record)
		}
	}
}

// A duplicate connection that resumes from a mid-history cursor receives
// exactly the tail after it — no replayed prefix, no gap — while a concurrent
// connection reading from the beginning is unaffected.
func TestConcurrentResumeFromDistinctCursorsIsDeterministic(t *testing.T) {
	reader := &runHistoryReader{events: []Event{boundedEvent("event.1", 1), boundedEvent("event.2", 2), boundedEvent("event.3", 3)}}
	recorder := &MemoryCursorRecorder{}
	stream, err := NewStream(reader, allowAllStreamAuthority{}, StreamConfig{Heartbeat: 50 * time.Millisecond, Revalidation: time.Second, ReplayLimit: 100, Bounds: DefaultBounds(), Cursors: recorder, CursorSpool: recorder, CursorFailures: recorder})
	if err != nil {
		t.Fatal(err)
	}
	_, fromStart := serveUntilDelivered(t, stream, "", 3)
	_, fromMiddle := serveUntilDelivered(t, stream, "event.2", 1)
	full, tail := fromStart(), fromMiddle()
	if strings.Join(full, ",") != "event.1,event.2,event.3" {
		t.Fatalf("the connection reading from the start delivered %v", full)
	}
	if strings.Join(tail, ",") != "event.3" {
		t.Fatalf("the resumed connection delivered %v, want only the tail after its cursor", tail)
	}
}

// A cursor that names no event of this run is refused as expired, and the
// refusal names the snapshot as the recovery path rather than silently
// replaying from the beginning — a client that misuses a cursor must never be
// handed a history it has already seen.
func TestCursorNamingNoEventOfTheRunIsRefusedAsExpired(t *testing.T) {
	reader := &runHistoryReader{events: []Event{boundedEvent("event.1", 1)}}
	stream, err := NewStream(reader, allowAllStreamAuthority{}, StreamConfig{Heartbeat: 50 * time.Millisecond, Revalidation: time.Second, ReplayLimit: 100, Bounds: DefaultBounds()})
	if err != nil {
		t.Fatal(err)
	}
	writer := newCaptureStreamWriter()
	err = stream.Serve(context.Background(), writer, Scope{WorkspaceID: "workspace.1", ProjectID: "project.1"}, "run.1", "event.of-another-run")
	if err == nil {
		t.Fatal("a cursor from outside the run's history was accepted")
	}
	if !strings.Contains(err.Error(), "snapshot") {
		t.Fatalf("cursor refusal = %v, want the snapshot recovery path", err)
	}
	if len(deliveredCursors(writer.String())) != 0 {
		t.Fatalf("a refused cursor still delivered events:\n%s", writer.String())
	}
}

// Concurrent connections share one instance budget: past the cap a further
// connection is refused rather than degrading every live stream.
func TestConcurrentConnectionsShareOneInstanceBudget(t *testing.T) {
	reader := &runHistoryReader{events: []Event{boundedEvent("event.1", 1)}}
	stream, err := NewStream(reader, allowAllStreamAuthority{}, StreamConfig{Heartbeat: 50 * time.Millisecond, Revalidation: time.Second, ReplayLimit: 100, Bounds: DefaultBounds(), MaximumConnections: 1})
	if err != nil {
		t.Fatal(err)
	}
	_, release := serveUntilDelivered(t, stream, "", 1)
	defer release()
	if err := stream.Serve(context.Background(), newCaptureStreamWriter(), Scope{WorkspaceID: "workspace.1", ProjectID: "project.1"}, "run.1", ""); err == nil {
		t.Fatal("a connection past the instance budget was admitted")
	}
}
