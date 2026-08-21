package events

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"
)

// revocableAuthority stays current for a fixed number of proofs and is revoked
// from the next one on. Counting the proofs is what lets a test aim revocation
// at one exact revalidation site — admission, per-event, the periodic re-proof,
// or the heartbeat — instead of hoping a wall-clock window lands there.
type revocableAuthority struct {
	lock    sync.Mutex
	allow   int
	proofs  int
	revoked error
}

func newRevocableAuthority(allow int) *revocableAuthority {
	return &revocableAuthority{allow: allow, revoked: fmt.Errorf("current authority was revoked")}
}

func (a *revocableAuthority) Revalidate(context.Context) error {
	a.lock.Lock()
	defer a.lock.Unlock()
	a.proofs++
	if a.proofs > a.allow {
		return a.revoked
	}
	return nil
}

func (a *revocableAuthority) Proofs() int {
	a.lock.Lock()
	defer a.lock.Unlock()
	return a.proofs
}

// idleReader has history to replay and then holds open the way the durable
// reader does, so a stream reaches its periodic and heartbeat re-proofs.
type idleReader struct{ events []Event }

func (r *idleReader) Replay(_ context.Context, request ReplayRequest) (ReplayPage, error) {
	page := ReplayPage{CurrentCursor: request.AfterEventID}
	for _, event := range r.events {
		if request.AfterEventID == "" || event.ID > request.AfterEventID {
			page.Events = append(page.Events, event)
		}
	}
	if len(page.Events) > 0 {
		last := page.Events[len(page.Events)-1]
		page.CurrentCursor, page.CurrentSequence = last.ID, last.Sequence
	}
	return page, nil
}

func (*idleReader) Snapshot(context.Context, Scope, string) (SnapshotProjection, error) {
	return SnapshotProjection{}, nil
}

// Wait holds until the stream's own timeout, so the select the stream is
// parked in is reached by a ticker rather than by another replay.
func (*idleReader) Wait(ctx context.Context, _ Scope, _ string, _ uint64, timeout time.Duration) error {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func revocationStream(t *testing.T, reader Reader, authority StreamAuthority, recorder *MemoryCursorRecorder, heartbeat, revalidation time.Duration) *Stream {
	t.Helper()
	stream, err := NewStream(reader, authority, StreamConfig{
		Heartbeat: heartbeat, Revalidation: revalidation, ReplayLimit: 100, Bounds: DefaultBounds(),
		Cursors: recorder, CursorSpool: recorder, CursorFailures: recorder,
	})
	if err != nil {
		t.Fatal(err)
	}
	return stream
}

// assertRevokedDisconnect proves the stream ended on revoked authority and
// that the durable disconnect record says so. The reason is the only account
// an operator or an audit has of why a client lost its stream, so a revocation
// recorded as an ordinary client close is a false record, not a lesser one.
func assertRevokedDisconnect(t *testing.T, recorder *MemoryCursorRecorder, err error, cursor string) {
	t.Helper()
	if err == nil {
		t.Fatal("a stream whose authority was revoked must end")
	}
	recorded := recorder.Recorded()
	if len(recorded) != 1 {
		t.Fatalf("recorded cursors=%+v, want exactly one disconnect record", recorded)
	}
	if recorded[0].Reason != "authority-revoked" {
		t.Fatalf("disconnect reason=%q, want authority-revoked", recorded[0].Reason)
	}
	if recorded[0].LastEventID != cursor {
		t.Fatalf("disconnect cursor=%q, want %q", recorded[0].LastEventID, cursor)
	}
}

// Admission: authority revoked before any frame is replayed. The connection
// delivered nothing, and the record says the authority went — not that the
// client closed.
func TestRevokedAuthorityAtAdmissionRecordsTheRevocation(t *testing.T) {
	recorder := &MemoryCursorRecorder{}
	reader := &idleReader{events: []Event{boundedEvent("event.1", 1)}}
	stream := revocationStream(t, reader, newRevocableAuthority(0), recorder, time.Second, time.Second)
	err := stream.Serve(context.Background(), newCaptureStreamWriter(), Scope{WorkspaceID: "workspace.1", ProjectID: "project.1"}, "run.1", "")
	assertRevokedDisconnect(t, recorder, err, "")
}

// Event loop: authority is current at admission and revoked before the second
// event of the page. The record names the last event the client actually got.
func TestRevokedAuthorityBetweenEventsRecordsTheRevocation(t *testing.T) {
	recorder := &MemoryCursorRecorder{}
	reader := &idleReader{events: []Event{boundedEvent("event.1", 1), boundedEvent("event.2", 2)}}
	// One proof admits the connection, the second admits event.1, the third —
	// the one before event.2 — is refused.
	stream := revocationStream(t, reader, newRevocableAuthority(2), recorder, time.Second, time.Second)
	err := stream.Serve(context.Background(), newCaptureStreamWriter(), Scope{WorkspaceID: "workspace.1", ProjectID: "project.1"}, "run.1", "")
	assertRevokedDisconnect(t, recorder, err, "event.1")
}

// Periodic re-proof: the stream is idle and its revalidation ticker, not a
// replay, is what discovers the revocation.
func TestRevokedAuthorityOnThePeriodicProofRecordsTheRevocation(t *testing.T) {
	recorder := &MemoryCursorRecorder{}
	reader := &idleReader{events: []Event{boundedEvent("event.1", 1)}}
	// Admission and event.1 are proven; the heartbeat is far away, so the next
	// proof is the periodic one.
	authority := newRevocableAuthority(2)
	stream := revocationStream(t, reader, authority, recorder, time.Hour, 20*time.Millisecond)
	err := stream.Serve(context.Background(), newCaptureStreamWriter(), Scope{WorkspaceID: "workspace.1", ProjectID: "project.1"}, "run.1", "")
	assertRevokedDisconnect(t, recorder, err, "event.1")
	if authority.Proofs() != 3 {
		t.Fatalf("authority proofs=%d, want the periodic re-proof to be the one refused", authority.Proofs())
	}
}

// Heartbeat re-proof: an idle stream is still a stream, so the keep-alive
// frame is written only under current authority — and a revocation discovered
// there is recorded as a revocation.
func TestRevokedAuthorityOnTheHeartbeatProofRecordsTheRevocation(t *testing.T) {
	recorder := &MemoryCursorRecorder{}
	reader := &idleReader{events: []Event{boundedEvent("event.1", 1)}}
	authority := newRevocableAuthority(2)
	stream := revocationStream(t, reader, authority, recorder, 20*time.Millisecond, time.Hour)
	writer := newCaptureStreamWriter()
	err := stream.Serve(context.Background(), writer, Scope{WorkspaceID: "workspace.1", ProjectID: "project.1"}, "run.1", "")
	assertRevokedDisconnect(t, recorder, err, "event.1")
	if authority.Proofs() != 3 {
		t.Fatalf("authority proofs=%d, want the heartbeat re-proof to be the one refused", authority.Proofs())
	}
	if body := writer.String(); len(body) == 0 {
		t.Fatal("the stream delivered nothing before the heartbeat re-proof")
	}
}

// A revoked stream whose disconnect record the store refuses still keeps the
// record: the revocation reaches the durable retry path rather than being
// reduced to a counter.
func TestRevokedDisconnectRecordSurvivesAStoreOutage(t *testing.T) {
	recorder := &MemoryCursorRecorder{}
	recorder.RefuseCursorRecords(fmt.Errorf("cursor store unavailable"))
	reader := &idleReader{events: []Event{boundedEvent("event.1", 1)}}
	stream := revocationStream(t, reader, newRevocableAuthority(2), recorder, time.Second, 20*time.Millisecond)
	if err := stream.Serve(context.Background(), newCaptureStreamWriter(), Scope{WorkspaceID: "workspace.1", ProjectID: "project.1"}, "run.1", ""); err == nil {
		t.Fatal("a stream whose authority was revoked must end")
	}
	spooled := recorder.Spooled()
	if len(spooled) != 1 || spooled[0].Reason != "authority-revoked" || spooled[0].LastEventID != "event.1" {
		t.Fatalf("durably held records=%+v, want the authority-revoked record at event.1", spooled)
	}
	if failures := recorder.Failures(); len(failures) != 0 {
		t.Fatalf("reported failures=%+v, want a held record reported as lost by nobody", failures)
	}
}

var _ http.ResponseWriter = (*captureStreamWriter)(nil)
