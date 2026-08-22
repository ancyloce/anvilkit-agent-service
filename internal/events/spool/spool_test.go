package spool_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

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
	report, err := reconciler.ReconcileOnce(context.Background())
	if err != nil || report.Placed != 1 {
		t.Fatalf("report=%+v err=%v, want the held record placed", report, err)
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
	report, err := reconciler.ReconcileOnce(context.Background())
	if err != nil {
		t.Fatalf("a refused placement ended the sweep: %v", err)
	}
	if report.Placed != 0 || report.Deferred != 1 || report.FirstDeferral == nil {
		t.Fatalf("report=%+v, want the refusal deferred and named, nothing placed", report)
	}
	if got := held(t, store); got != 1 {
		t.Fatalf("held records=%d, want the record still kept", got)
	}
	recorder.RefuseCursorRecords(nil)
	if report, err := reconciler.ReconcileOnce(context.Background()); err != nil || report.Placed != 1 {
		t.Fatalf("report=%+v err=%v, want the record placed once the store recovered", report, err)
	}
	if report, err := reconciler.ReconcileOnce(context.Background()); err != nil || report.Placed != 0 {
		t.Fatalf("report=%+v err=%v, want a second sweep to place nothing again", report, err)
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
	report, err := store.Drain(context.Background(), recorder)
	if err != nil || report.Placed != 3 {
		t.Fatalf("report=%+v err=%v, want every held record placed", report, err)
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

// One unreadable record must not decide the fate of the records behind it.
// A torn or truncated file is set aside and every valid record in the same
// sweep is still placed — the failure that used to end the sweep at its first
// bad file would have held an entire backlog hostage to one of them.
func TestOneUnreadableRecordDoesNotBlockTheValidRecordsBehindIt(t *testing.T) {
	directory := t.TempDir()
	store, err := spool.NewStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, connection := range []string{"stream.h", "stream.i", "stream.j"} {
		if err := store.SpoolCursor(context.Background(), record(connection, "event.4", "slow-consumer")); err != nil {
			t.Fatal(err)
		}
	}
	// Corrupt one held record in place, as a torn write or a damaged volume
	// would leave it. Which one is corrupted is deliberately not chosen: the
	// first name the directory lists is taken, so the test does not depend on
	// the bad record being last.
	corrupted := firstHeldRecord(t, directory)
	if err := os.WriteFile(corrupted, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	recorder := &events.MemoryCursorRecorder{}
	report, err := store.Drain(context.Background(), recorder)
	if err != nil {
		t.Fatalf("an unreadable record ended the sweep: %v", err)
	}
	if report.Placed != 2 || report.Quarantined != 1 {
		t.Fatalf("report=%+v, want the two valid records placed and the unreadable one set aside", report)
	}
	if recorded := recorder.Recorded(); len(recorded) != 2 {
		t.Fatalf("placed records=%d, want both valid records placed despite the corrupt one", len(recorded))
	}
	stats, err := store.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if stats.Held != 0 || stats.Quarantined != 1 {
		t.Fatalf("stats=%+v, want nothing still held and the unreadable record retained for an operator", stats)
	}
	// The set-aside record is retained, never destroyed: it is still the only
	// account of what that client received.
	if _, err := os.Stat(strings.TrimSuffix(corrupted, ".cursor.json") + ".cursor.unreadable"); err != nil {
		t.Fatalf("the unreadable record was not retained for recovery: %v", err)
	}
	// A later sweep neither re-reports nor re-carries it.
	second, err := store.Drain(context.Background(), recorder)
	if err != nil || second.Placed != 0 || second.Quarantined != 0 {
		t.Fatalf("second report=%+v err=%v, want a set-aside record left alone", second, err)
	}
}

// A record that decodes but is not a connection record can never be placed by
// any sweep, so it is set aside on the same terms as an unreadable one rather
// than being offered to the store forever.
func TestADecodableRecordThatIsNotAConnectionRecordIsSetAside(t *testing.T) {
	directory := t.TempDir()
	store, err := spool.NewStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SpoolCursor(context.Background(), record("stream.k", "event.2", "client-closed")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "0000.cursor.json"), []byte(`{"workspaceId":"workspace.1"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	recorder := &events.MemoryCursorRecorder{}
	report, err := store.Drain(context.Background(), recorder)
	if err != nil {
		t.Fatalf("an unplaceable record ended the sweep: %v", err)
	}
	if report.Placed != 1 || report.Quarantined != 1 {
		t.Fatalf("report=%+v, want the real record placed and the incomplete one set aside", report)
	}
}

// A store that is down refuses record after record. The sweep stops offering
// it the rest of the backlog instead of walking the whole spool against an
// unreachable store, and everything it did not offer stays held.
func TestASweepStopsOfferingRecordsToADownStoreAndHoldsTheRest(t *testing.T) {
	store, err := spool.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	const total = 12
	for index := 0; index < total; index++ {
		if err := store.SpoolCursor(context.Background(), record(fmt.Sprintf("stream.down.%02d", index), "event.1", "slow-consumer")); err != nil {
			t.Fatal(err)
		}
	}
	recorder := &events.MemoryCursorRecorder{}
	recorder.RefuseCursorRecords(errors.New("cursor store unreachable"))
	report, err := store.Drain(context.Background(), recorder)
	if err != nil {
		t.Fatalf("a down store ended the sweep: %v", err)
	}
	if report.Placed != 0 || report.FirstDeferral == nil {
		t.Fatalf("report=%+v, want nothing placed and the outage named", report)
	}
	if report.Deferred != total {
		t.Fatalf("deferred=%d, want every held record accounted as deferred", report.Deferred)
	}
	if attempts := len(recorder.Recorded()); attempts != 0 {
		t.Fatalf("recorded=%d, want no record placed against a down store", attempts)
	}
	if got := held(t, store); got != total {
		t.Fatalf("held=%d, want every record still kept for the next sweep", got)
	}
	// Once the store recovers, the whole backlog is placed.
	recorder.RefuseCursorRecords(nil)
	recovered, err := store.Drain(context.Background(), recorder)
	if err != nil || recovered.Placed != total {
		t.Fatalf("recovered report=%+v err=%v, want the whole backlog placed", recovered, err)
	}
}

// The spool is bounded. Past its capacity a write is refused with a typed
// error, so the stream reports a record that is genuinely at risk instead of
// the instance filling its volume until it can write nothing at all. A record
// for a connection already held is a replacement and always fits.
func TestAFullSpoolRefusesNewRecordsButStillReplacesHeldOnes(t *testing.T) {
	store, err := spool.NewStoreWithCapacity(t.TempDir(), 2)
	if err != nil {
		t.Fatal(err)
	}
	for _, connection := range []string{"stream.l", "stream.m"} {
		if err := store.SpoolCursor(context.Background(), record(connection, "event.1", "slow-consumer")); err != nil {
			t.Fatal(err)
		}
	}
	err = store.SpoolCursor(context.Background(), record("stream.n", "event.1", "slow-consumer"))
	var full spool.SpoolFull
	if !errors.As(err, &full) {
		t.Fatalf("write past capacity err=%v, want a typed full-spool refusal", err)
	}
	if full.Held != 2 || full.Capacity != 2 {
		t.Fatalf("full-spool refusal=%+v, want the backlog and bound it refused on", full)
	}
	// The already-held connection is replaced, not counted again.
	if err := store.SpoolCursor(context.Background(), record("stream.m", "event.5", "slow-consumer")); err != nil {
		t.Fatalf("a held connection could not update its own record: %v", err)
	}
	stats, err := store.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if stats.Held != 2 || stats.Capacity != 2 {
		t.Fatalf("stats=%+v, want the bound respected and reported", stats)
	}
	if _, err := spool.NewStoreWithCapacity(t.TempDir(), 0); err == nil {
		t.Fatal("a spool was built with a non-positive capacity")
	}
}

// The backlog, its oldest waiting record, the remaining capacity, and the
// records set aside are all observable. An outage nobody can see the size of
// is one nobody can end.
func TestEverySweepReportsTheBacklogItsAgeAndItsCapacity(t *testing.T) {
	directory := t.TempDir()
	store, err := spool.NewStoreWithCapacity(directory, 8)
	if err != nil {
		t.Fatal(err)
	}
	for _, connection := range []string{"stream.o", "stream.p"} {
		if err := store.SpoolCursor(context.Background(), record(connection, "event.1", "slow-consumer")); err != nil {
			t.Fatal(err)
		}
	}
	// Age the oldest held record so the reported age is a measured one.
	oldest := firstHeldRecord(t, directory)
	aged := time.Now().Add(-90 * time.Minute)
	if err := os.Chtimes(oldest, aged, aged); err != nil {
		t.Fatal(err)
	}

	observer := &recordingSpoolObserver{}
	recorder := &events.MemoryCursorRecorder{}
	recorder.RefuseCursorRecords(errors.New("cursor store unreachable"))
	reconciler, err := spool.NewObservedReconciler(store, recorder, observer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reconciler.ReconcileOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(observer.stats) != 1 {
		t.Fatalf("observations=%d, want one per sweep", len(observer.stats))
	}
	stats, report := observer.stats[0], observer.reports[0]
	if stats.Held != 2 || stats.Capacity != 8 {
		t.Fatalf("observed stats=%+v, want the backlog and its bound", stats)
	}
	if stats.OldestAge < time.Hour {
		t.Fatalf("observed oldest age=%s, want the measured age of the oldest held record", stats.OldestAge)
	}
	if report.Deferred != 2 {
		t.Fatalf("observed report=%+v, want the deferred backlog reported", report)
	}

	// A drained spool reports an empty backlog and no age at all.
	recorder.RefuseCursorRecords(nil)
	if _, err := reconciler.ReconcileOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	drained := observer.stats[len(observer.stats)-1]
	if drained.Held != 0 || drained.OldestAge != 0 {
		t.Fatalf("observed stats after draining=%+v, want an empty backlog with no age", drained)
	}
}

// A sweep that sets a record aside says so, because a quarantined record is
// never placed by any later sweep: time does not resolve it, an operator does.
func TestASweepReportsDeferralsAndSetAsideRecordsToItsFailureObserver(t *testing.T) {
	directory := t.TempDir()
	store, err := spool.NewStore(directory)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SpoolCursor(context.Background(), record("stream.q", "event.1", "slow-consumer")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(firstHeldRecord(t, directory), []byte("{torn"), 0o600); err != nil {
		t.Fatal(err)
	}
	reconciler, err := spool.NewReconciler(store, &events.MemoryCursorRecorder{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	reported := make(chan error, 4)
	go reconciler.Run(ctx, time.Hour, func(err error) {
		select {
		case reported <- err:
		default:
		}
	})
	select {
	case err := <-reported:
		if err == nil || !strings.Contains(err.Error(), "operator recovery") {
			t.Fatalf("reported=%v, want the set-aside record reported as needing an operator", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the sweep never reported the record it set aside")
	}
	cancel()
}

// firstHeldRecord returns the path of one held record, chosen by the order the
// directory lists them so no test depends on which record it damages.
func firstHeldRecord(t *testing.T, directory string) string {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".cursor.json") {
			return filepath.Join(directory, entry.Name())
		}
	}
	t.Fatal("no held record was found")
	return ""
}

type recordingSpoolObserver struct {
	stats   []spool.Stats
	reports []spool.DrainReport
}

func (o *recordingSpoolObserver) ObserveCursorSpool(_ context.Context, stats spool.Stats, report spool.DrainReport) {
	o.stats = append(o.stats, stats)
	o.reports = append(o.reports, report)
}

// The holding bound is a bound under concurrency or it is not a bound. Every
// writer that races for the last places must see one decision: counting the
// directory and then writing outside a lock admits every concurrent writer
// that read the same under-capacity count, so a disconnect storm overruns the
// bound by exactly the number of streams that disconnected at once — which is
// precisely the moment the bound was there for.
func TestConcurrentWritersCannotExceedTheHoldingBound(t *testing.T) {
	const capacity = 4
	const writers = 32
	directory := t.TempDir()
	store, err := spool.NewStoreWithCapacity(directory, capacity)
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, writers)
	var group sync.WaitGroup
	for index := 0; index < writers; index++ {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			<-start
			results <- store.SpoolCursor(context.Background(), record(fmt.Sprintf("stream.concurrent.%d", index), "event.1", "slow-consumer"))
		}(index)
	}
	close(start)
	group.Wait()
	close(results)
	admitted, refused := 0, 0
	for err := range results {
		var full spool.SpoolFull
		switch {
		case err == nil:
			admitted++
		case errors.As(err, &full):
			refused++
		default:
			t.Fatalf("concurrent write failed for a reason other than the bound: %v", err)
		}
	}
	if admitted != capacity || refused != writers-capacity {
		t.Fatalf("admitted=%d refused=%d, want exactly %d admitted under the bound", admitted, refused, capacity)
	}
	stats, err := store.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if stats.Held != capacity {
		t.Fatalf("held=%d, want the volume to carry exactly the bound", stats.Held)
	}
}

// A bound on waiting records alone is no bound on the volume. Every record
// admitted under it can become an unreadable one, freeing its place for
// another, so a directory that keeps producing unreadable records grows
// without limit while the spool reports itself empty. The bound counts the
// files on the volume, so set-aside records consume it exactly as waiting ones
// do — and the refusal says how much of the volume they are holding.
func TestSetAsideRecordsConsumeTheVolumeBound(t *testing.T) {
	directory := t.TempDir()
	store, err := spool.NewStoreWithCapacity(directory, 2)
	if err != nil {
		t.Fatal(err)
	}
	for _, connection := range []string{"stream.bound.a", "stream.bound.b"} {
		if err := store.SpoolCursor(context.Background(), record(connection, "event.1", "slow-consumer")); err != nil {
			t.Fatal(err)
		}
	}
	// Both waiting records become unreadable ones.
	for _, name := range heldRecordNames(t, directory) {
		if err := os.WriteFile(name, []byte("{"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	report, err := store.Drain(context.Background(), &events.MemoryCursorRecorder{})
	if err != nil {
		t.Fatal(err)
	}
	if report.Quarantined != 2 || report.QuarantineFailed != 0 {
		t.Fatalf("report=%+v, want both records set aside", report)
	}
	stats, err := store.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if stats.Held != 0 || stats.Quarantined != 2 {
		t.Fatalf("stats=%+v, want nothing waiting and two files set aside", stats)
	}
	// Nothing is waiting, yet the volume is full. A bound that ignored the
	// set-aside files would admit two more records here, and two more after
	// the next sweep, without limit.
	err = store.SpoolCursor(context.Background(), record("stream.bound.c", "event.1", "slow-consumer"))
	var full spool.SpoolFull
	if !errors.As(err, &full) {
		t.Fatalf("write err=%v, want the volume bound to refuse it", err)
	}
	if full.Held != 0 || full.Quarantined != 2 || full.Capacity != 2 {
		t.Fatalf("refusal=%+v, want it to name the set-aside files holding the volume", full)
	}
}

// A record the sweep meant to set aside and could not is not a record that was
// set aside. Counting the intention reported records as safely quarantined
// while they were still sitting under their placeable name, so a volume that
// had stopped accepting renames was indistinguishable from one quietly doing
// its job. The failure is now counted and reported as itself, and the record
// stays exactly where the next sweep will find it.
func TestAFailedSetAsideIsReportedRatherThanCounted(t *testing.T) {
	directory := t.TempDir()
	store, err := spool.NewStoreWithCapacity(directory, 4)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SpoolCursor(context.Background(), record("stream.stuck", "event.1", "slow-consumer")); err != nil {
		t.Fatal(err)
	}
	path := firstHeldRecord(t, directory)
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A directory already standing at the set-aside name: renaming a file onto
	// it fails, whatever the process's privileges are.
	if err := os.Mkdir(strings.TrimSuffix(path, ".cursor.json")+".cursor.unreadable", 0o700); err != nil {
		t.Fatal(err)
	}
	report, err := store.Drain(context.Background(), &events.MemoryCursorRecorder{})
	if err != nil {
		t.Fatal(err)
	}
	if report.Quarantined != 0 || report.QuarantineFailed != 1 || report.FirstQuarantineFailure == nil {
		t.Fatalf("report=%+v, want the failed set-aside reported and not counted as done", report)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the record that could not be set aside was not left where it was: %v", err)
	}
	// The next sweep meets it again, so an operator has to be told now.
	observer := &recordingSpoolObserver{}
	reconciler, err := spool.NewObservedReconciler(store, &events.MemoryCursorRecorder{}, observer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reconciler.ReconcileOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(observer.reports) != 1 || observer.reports[0].QuarantineFailed != 1 {
		t.Fatalf("observed reports=%+v, want the failure surfaced to operations", observer.reports)
	}
}

func heldRecordNames(t *testing.T, directory string) []string {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".cursor.json") {
			names = append(names, filepath.Join(directory, entry.Name()))
		}
	}
	return names
}
