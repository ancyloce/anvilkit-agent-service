package spool_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ancyloce/anvilkit-agent-service/internal/events"
	"github.com/ancyloce/anvilkit-agent-service/internal/events/spool"
)

func held(t *testing.T, store *spool.Store) int {
	t.Helper()
	count, err := store.Held()
	if err != nil {
		t.Fatal(err)
	}
	return count
}

func record(connectionID, lastEventID, reason string) events.RecordedCursor {
	return events.RecordedCursor{
		Scope:        events.Scope{WorkspaceID: "workspace.1", ProjectID: "project.1"},
		RunID:        "run.1",
		ConnectionID: connectionID,
		LastEventID:  lastEventID,
		Reason:       reason,
	}
}

// The record a stream could not place survives the process that wrote it: a
// successor opening the same durable directory finds it and places it. This is
// the whole point of the spool — a disconnect record is kept, not reported.
func TestAHeldRecordIsPlacedByASuccessorProcess(t *testing.T) {
	directory := t.TempDir()
	writer, err := spool.NewStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.SpoolCursor(context.Background(), record("stream.a", "event.7", "slow-consumer")); err != nil {
		t.Fatal(err)
	}
	if got := held(t, writer); got != 1 {
		t.Fatalf("held records=%d, want the refused record kept", got)
	}

	// A successor process: a new store over the same durable directory, with
	// no memory of the one that wrote the record.
	successor, err := spool.NewStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	recorder := &events.MemoryCursorRecorder{}
	reconciler, err := spool.NewReconciler(successor, recorder)
	if err != nil {
		t.Fatal(err)
	}
	placed, err := reconciler.ReconcileOnce(context.Background())
	if err != nil || placed != 1 {
		t.Fatalf("placed=%d err=%v, want the held record placed", placed, err)
	}
	recorded := recorder.Recorded()
	if len(recorded) != 1 || recorded[0].ConnectionID != "stream.a" || recorded[0].LastEventID != "event.7" || recorded[0].Reason != "slow-consumer" || recorded[0].RunID != "run.1" {
		t.Fatalf("placed record=%+v, want the connection record exactly as it was held", recorded)
	}
	if recorded[0].Scope != (events.Scope{WorkspaceID: "workspace.1", ProjectID: "project.1"}) {
		t.Fatalf("placed scope=%+v, want the tenant the record belonged to", recorded[0].Scope)
	}
	if got := held(t, successor); got != 0 {
		t.Fatalf("held records=%d after placement, want none", got)
	}
}

// A store that is still refusing keeps the record held. Nothing is dropped and
// nothing is placed twice: the next sweep places it, and the sweep after that
// has nothing to do.
func TestARefusedPlacementKeepsTheRecordHeldForTheNextSweep(t *testing.T) {
	store, err := spool.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SpoolCursor(context.Background(), record("stream.b", "event.3", "authority-revoked")); err != nil {
		t.Fatal(err)
	}
	recorder := &events.MemoryCursorRecorder{}
	recorder.RefuseCursorRecords(errors.New("cursor store still unavailable"))
	reconciler, err := spool.NewReconciler(store, recorder)
	if err != nil {
		t.Fatal(err)
	}
	if placed, err := reconciler.ReconcileOnce(context.Background()); err == nil || placed != 0 {
		t.Fatalf("placed=%d err=%v, want a refused sweep to place nothing", placed, err)
	}
	if got := held(t, store); got != 1 {
		t.Fatalf("held records=%d, want the record still kept", got)
	}
	recorder.RefuseCursorRecords(nil)
	if placed, err := reconciler.ReconcileOnce(context.Background()); err != nil || placed != 1 {
		t.Fatalf("placed=%d err=%v, want the record placed once the store recovered", placed, err)
	}
	if placed, err := reconciler.ReconcileOnce(context.Background()); err != nil || placed != 0 {
		t.Fatalf("placed=%d err=%v, want a second sweep to place nothing again", placed, err)
	}
	if recorded := recorder.Recorded(); len(recorded) != 1 || recorded[0].Reason != "authority-revoked" {
		t.Fatalf("placed records=%+v, want exactly one authority-revoked record", recorded)
	}
}

// One connection has one disconnect record. A repeated spool of the same
// connection replaces its held record rather than accumulating accounts of
// the same disconnect.
func TestARepeatedConnectionRecordOccupiesOneHeldRecord(t *testing.T) {
	store, err := spool.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, lastEventID := range []string{"event.1", "event.2"} {
		if err := store.SpoolCursor(context.Background(), record("stream.c", lastEventID, "slow-consumer")); err != nil {
			t.Fatal(err)
		}
	}
	if got := held(t, store); got != 1 {
		t.Fatalf("held records=%d, want one record per connection", got)
	}
	recorder := &events.MemoryCursorRecorder{}
	if _, err := store.Drain(context.Background(), recorder); err != nil {
		t.Fatal(err)
	}
	if recorded := recorder.Recorded(); len(recorded) != 1 || recorded[0].LastEventID != "event.2" {
		t.Fatalf("placed records=%+v, want the connection's latest cursor", recorded)
	}
}

// Distinct connections are distinct records, and every one of them is placed.
func TestEveryHeldConnectionRecordIsPlaced(t *testing.T) {
	store, err := spool.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, connection := range []string{"stream.d", "stream.e", "stream.f"} {
		if err := store.SpoolCursor(context.Background(), record(connection, "event.9", "client-closed")); err != nil {
			t.Fatal(err)
		}
	}
	recorder := &events.MemoryCursorRecorder{}
	placed, err := store.Drain(context.Background(), recorder)
	if err != nil || placed != 3 {
		t.Fatalf("placed=%d err=%v, want every held record placed", placed, err)
	}
	if got := held(t, store); got != 0 {
		t.Fatalf("held records=%d, want none left", got)
	}
}

// An incomplete record is not a record. The spool refuses it rather than
// keeping something no reconciler could place.
func TestAnIncompleteRecordIsRefused(t *testing.T) {
	store, err := spool.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]events.RecordedCursor{
		"no tenant":     {RunID: "run.1", ConnectionID: "stream.g", Reason: "client-closed"},
		"no run":        record("stream.g", "event.1", "client-closed"),
		"no connection": record("", "event.1", "client-closed"),
		"no reason":     record("stream.g", "event.1", ""),
	} {
		if name == "no run" {
			value.RunID = ""
		}
		if err := store.SpoolCursor(context.Background(), value); err == nil {
			t.Fatalf("%s: an incomplete connection record was held", name)
		}
	}
	if got := held(t, store); got != 0 {
		t.Fatalf("held records=%d, want none", got)
	}
}

// A deployment whose durable directory is missing or unusable fails when the
// spool is built, not at the first disconnect it would have had to keep.
func TestAnUnusableDurableDirectoryFailsClosed(t *testing.T) {
	if _, err := spool.NewStore("   "); err == nil {
		t.Fatal("a spool was built without a durable directory")
	}
	blocked := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocked, []byte("occupied"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := spool.NewStore(blocked); err == nil {
		t.Fatal("a spool was built over a path that is not a directory")
	}
}
