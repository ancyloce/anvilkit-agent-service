// Package spool keeps stream disconnect records on local durable storage when
// the authoritative cursor store cannot accept them, and places them there
// once it can again.
//
// The record of what a disconnected client actually received is written before
// the connection ends (design 0001 §"streaming"), so the write cannot be
// abandoned when the primary store is unreachable — and it cannot be retried
// into that same store either, because the store being unreachable is the
// reason the record is here. It is therefore written to the instance's own
// durable volume, survives the process that wrote it, and is placed by the
// reconciler below on the next start or the next successful sweep.
package spool

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/events"
)

// recordSuffix names a placed-pending record. The extension is deliberate:
// a partially written file never carries it, so a reader can never mistake a
// torn write for a record.
const recordSuffix = ".cursor.json"

// quarantineSuffix names a record the sweep could not read. A record that
// cannot be decoded is still the only account of what a client received, so it
// is set aside rather than destroyed: the sweep stops carrying it, an operator
// can still recover whatever of it survives, and — decisively — it no longer
// stands in front of every valid record behind it.
const quarantineSuffix = ".cursor.unreadable"

// defaultCapacity bounds how many record files one instance holds on its
// volume — those waiting to be placed and those set aside as unreadable
// together. The spool exists because the authoritative store is unreachable;
// an outage long enough to fill it is an operational condition, not a case to
// absorb silently. Past the bound the write is refused so the stream's failure
// observer reports a record that really is at risk, instead of the volume
// filling until nothing on the instance can write at all.
//
// The bound counts set-aside records deliberately. A bound on waiting records
// alone is no bound on the volume: every record admitted under it can become
// an unreadable one, freeing its place for another, so a directory that keeps
// producing unreadable records grows without limit while the spool reports
// itself empty. Counting both makes the file count on the volume the thing
// that is actually bounded.
const defaultCapacity = 10000

// deferredFailureBudget bounds how many consecutive records one sweep offers to
// a refusing store. A store that refuses several records in a row is down, and
// continuing to offer it the rest of the backlog only lengthens the sweep; the
// remaining records stay held for the next one.
const deferredFailureBudget = 5

// Store is the local durable holding area for disconnect records.
type Store struct {
	directory string
	capacity  int
	// place serializes the capacity decision with the write it admits. The
	// bound is only a bound if no second writer can be admitted between one
	// writer counting the directory and that writer's record appearing in it.
	place sync.Mutex
}

// NewStore prepares the durable directory and proves it is writable, so a
// deployment whose volume is missing or read-only fails at startup rather than
// at the first disconnect it would have had to record. The spool holds at most
// defaultCapacity records; NewStoreWithCapacity sets a different bound.
func NewStore(directory string) (*Store, error) {
	return NewStoreWithCapacity(directory, defaultCapacity)
}

// NewStoreWithCapacity prepares the durable directory under an explicit
// holding bound.
func NewStoreWithCapacity(directory string, capacity int) (*Store, error) {
	if strings.TrimSpace(directory) == "" {
		return nil, fmt.Errorf("stream cursor spool: a durable directory is required")
	}
	if capacity <= 0 {
		return nil, fmt.Errorf("stream cursor spool: the holding capacity must be positive")
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, fmt.Errorf("stream cursor spool: prepare durable directory: %w", err)
	}
	probe, err := os.CreateTemp(directory, "writable-*")
	if err != nil {
		return nil, fmt.Errorf("stream cursor spool: the durable directory is not writable: %w", err)
	}
	name := probe.Name()
	if err := probe.Close(); err != nil {
		return nil, fmt.Errorf("stream cursor spool: the durable directory is not writable: %w", err)
	}
	if err := os.Remove(name); err != nil {
		return nil, fmt.Errorf("stream cursor spool: the durable directory is not writable: %w", err)
	}
	return &Store{directory: directory, capacity: capacity}, nil
}

var _ events.CursorSpool = (*Store)(nil)

// SpoolCursor writes one disconnect record durably. The bytes are flushed to
// the device and only then given their final name, so a record that exists is
// always a complete one; the containing directory is flushed too, so the name
// itself survives a crash rather than only the bytes behind it.
func (s *Store) SpoolCursor(ctx context.Context, record events.RecordedCursor) error {
	if err := record.Scope.Validate(); err != nil {
		return err
	}
	if record.RunID == "" || record.ConnectionID == "" || record.Reason == "" {
		return fmt.Errorf("stream cursor spool: a complete connection record is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	raw, err := json.Marshal(persisted{
		WorkspaceID:  record.Scope.WorkspaceID,
		ProjectID:    record.Scope.ProjectID,
		RunID:        record.RunID,
		ConnectionID: record.ConnectionID,
		LastEventID:  record.LastEventID,
		Reason:       record.Reason,
	})
	if err != nil {
		return fmt.Errorf("stream cursor spool: render pending record: %w", err)
	}
	final := filepath.Join(s.directory, recordName(record))
	// The capacity decision and the write it admits are one critical section.
	// Counting the directory and then writing outside a lock lets every
	// concurrent writer read the same under-capacity count and all be
	// admitted, which is how a bounded spool overruns its bound by exactly
	// the number of writers a disconnect storm produces.
	s.place.Lock()
	defer s.place.Unlock()
	// A record already held for this connection is replaced in place, so
	// re-recording the same connection never consumes further capacity. Any
	// other write must fit inside the bound: past it the write is refused so
	// the stream reports a record at risk, rather than the volume filling
	// until the instance can write nothing at all.
	if _, statErr := os.Stat(final); statErr != nil {
		if !os.IsNotExist(statErr) {
			return fmt.Errorf("stream cursor spool: inspect held record: %w", statErr)
		}
		stats, err := s.Stats()
		if err != nil {
			return err
		}
		if stats.Held+stats.Quarantined >= s.capacity {
			return SpoolFull{Held: stats.Held, Quarantined: stats.Quarantined, Capacity: s.capacity}
		}
	}
	pending, err := os.CreateTemp(s.directory, "pending-*")
	if err != nil {
		return fmt.Errorf("stream cursor spool: open pending record: %w", err)
	}
	name := pending.Name()
	if err := writeDurably(pending, raw); err != nil {
		_ = os.Remove(name)
		return err
	}
	if err := os.Rename(name, final); err != nil {
		_ = os.Remove(name)
		return fmt.Errorf("stream cursor spool: place pending record: %w", err)
	}
	if err := syncDirectory(s.directory); err != nil {
		return err
	}
	return nil
}

// SpoolFull reports a write refused because the instance's volume already
// carries its bounded number of record files. It is a distinct type rather
// than a message so a caller can tell a full spool — an operational condition
// with a known remedy — from a volume that has failed.
//
// The set-aside count is reported beside the waiting one because the two have
// different remedies: a spool full of waiting records needs the authoritative
// store back, and a spool full of set-aside records needs an operator to
// recover and clear them.
type SpoolFull struct{ Held, Quarantined, Capacity int }

func (e SpoolFull) Error() string {
	return fmt.Sprintf("stream cursor spool is full: %d of %d record files are on the volume (%d waiting, %d set aside as unreadable)", e.Held+e.Quarantined, e.Capacity, e.Held, e.Quarantined)
}

// DrainReport accounts for one sweep. Every field is an operational fact the
// sweep learned: what it placed, what it set aside as unreadable, and what the
// authoritative store would not take yet.
type DrainReport struct {
	// Placed counts records the authoritative store accepted and the spool
	// then released.
	Placed int
	// Quarantined counts records this sweep could not decode and did set
	// aside. A record is counted here only once its rename and the directory
	// flush behind it have both succeeded, so the count is a statement about
	// the volume rather than about the sweep's intention.
	Quarantined int
	// QuarantineFailed counts records this sweep could not decode and could
	// not set aside either. They are still under their placeable name, so the
	// next sweep meets them again; until an operator intervenes they are
	// re-read and re-refused on every sweep.
	QuarantineFailed int
	// FirstQuarantineFailure is why the first record that could not be set
	// aside could not be. A volume that refuses renames is a different fault
	// from a record that cannot be decoded, and it is the one that needs
	// reporting.
	FirstQuarantineFailure error
	// Deferred counts records the authoritative store refused. They stay held
	// for the next sweep.
	Deferred int
	// FirstDeferral is why the store refused the first record it refused. It
	// names the outage rather than restating it once per held record.
	FirstDeferral error
}

// Drain places every held record into the authoritative cursor store and
// forgets each one only after the store has accepted it.
//
// One record never decides the fate of the others. A record the store refuses
// stays held and the sweep moves to the next one; a record that cannot be
// decoded is set aside under quarantineSuffix, because a single torn or
// truncated file must not stand in front of every valid record behind it —
// which is exactly what returning at the first failure used to do. The report
// says what happened to each class; the error return is reserved for a
// condition that ends the sweep itself, such as a cancelled context or a
// directory that cannot be read.
func (s *Store) Drain(ctx context.Context, recorder events.CursorRecorder) (DrainReport, error) {
	report := DrainReport{}
	if recorder == nil {
		return report, fmt.Errorf("stream cursor spool: a cursor recorder is required")
	}
	names, err := s.heldNames()
	if err != nil {
		return report, err
	}
	consecutiveRefusals := 0
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return report, err
		}
		path := filepath.Join(s.directory, name)
		raw, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			// The file exists but cannot be read: that is the record's own
			// problem, not the sweep's. Set it aside and carry on.
			s.quarantine(path, &report)
			continue
		}
		var held persisted
		if err := json.Unmarshal(raw, &held); err != nil {
			s.quarantine(path, &report)
			continue
		}
		scope := events.Scope{WorkspaceID: held.WorkspaceID, ProjectID: held.ProjectID}
		if err := scope.Validate(); err != nil || held.RunID == "" || held.ConnectionID == "" || held.Reason == "" {
			// A decodable record that is not a connection record cannot be
			// placed by any sweep. Holding it forever would hide the rest.
			s.quarantine(path, &report)
			continue
		}
		if err := recorder.RecordCursor(ctx, scope, held.RunID, held.ConnectionID, held.LastEventID, held.Reason); err != nil {
			report.Deferred++
			if report.FirstDeferral == nil {
				report.FirstDeferral = fmt.Errorf("stream cursor spool: place held record: %w", err)
			}
			consecutiveRefusals++
			if consecutiveRefusals >= deferredFailureBudget {
				// The store is down rather than this record being unplaceable.
				// The remaining records stay held for the next sweep.
				report.Deferred += len(names) - (report.Placed + report.Quarantined + report.QuarantineFailed + report.Deferred)
				return report, nil
			}
			continue
		}
		consecutiveRefusals = 0
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return report, fmt.Errorf("stream cursor spool: release placed record: %w", err)
		}
		report.Placed++
	}
	return report, nil
}

// quarantine sets one unplaceable record aside under quarantineSuffix. The
// record is renamed, never removed: it is still the only account of what a
// client received, and an operator may yet recover what survives of it.
//
// The record is counted as set aside only once the rename and the directory
// flush behind it have both succeeded. Counting the intention instead reported
// records as set aside that were still sitting under their placeable name, so
// a volume that had stopped accepting renames looked exactly like one that was
// quietly doing its job — and the count an operator was given to act on was
// the one thing that could not be believed. A rename that fails is reported as
// the failure it is; the record stays where it is and the next sweep meets it
// again, which is why the failure has to be visible now.
func (s *Store) quarantine(path string, report *DrainReport) {
	if err := os.Rename(path, strings.TrimSuffix(path, recordSuffix)+quarantineSuffix); err != nil {
		report.QuarantineFailed++
		if report.FirstQuarantineFailure == nil {
			report.FirstQuarantineFailure = fmt.Errorf("stream cursor spool: set aside unreadable record: %w", err)
		}
		return
	}
	if err := syncDirectory(s.directory); err != nil {
		report.QuarantineFailed++
		if report.FirstQuarantineFailure == nil {
			report.FirstQuarantineFailure = err
		}
		return
	}
	report.Quarantined++
}

// heldNames lists the placeable records oldest first, so a backlog is drained
// in the order it accumulated and the oldest record's age is the one Stats
// reports.
func (s *Store) heldNames() ([]string, error) {
	entries, err := os.ReadDir(s.directory)
	if err != nil {
		return nil, fmt.Errorf("stream cursor spool: read held records: %w", err)
	}
	type aged struct {
		name    string
		written time.Time
	}
	values := make([]aged, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), recordSuffix) {
			continue
		}
		written := time.Time{}
		if info, err := entry.Info(); err == nil {
			written = info.ModTime()
		}
		values = append(values, aged{name: entry.Name(), written: written})
	}
	sort.Slice(values, func(left, right int) bool {
		if values[left].written.Equal(values[right].written) {
			return values[left].name < values[right].name
		}
		return values[left].written.Before(values[right].written)
	})
	names := make([]string, 0, len(values))
	for _, value := range values {
		names = append(names, value.name)
	}
	return names, nil
}

// Stats is what an operator needs to see about the spool without reading the
// volume: how much is held, how long the oldest record has waited, how close
// the instance is to refusing writes, and how much has been set aside as
// unreadable. A backlog that is merely large is an outage in progress; a
// backlog whose oldest record keeps ageing is one that is not draining.
type Stats struct {
	// Held is the number of records waiting to be placed.
	Held int
	// Quarantined is the number of records set aside as unreadable. They are
	// never placed and never released; they need an operator.
	Quarantined int
	// Capacity is the bound on the total number of record files the volume
	// carries — waiting and set aside together — past which writes are
	// refused.
	Capacity int
	// OldestAge is how long the oldest held record has waited. It is zero when
	// nothing is held.
	OldestAge time.Duration
}

// Stats reads the current state of the durable directory.
func (s *Store) Stats() (Stats, error) {
	entries, err := os.ReadDir(s.directory)
	if err != nil {
		return Stats{}, fmt.Errorf("stream cursor spool: read held records: %w", err)
	}
	stats := Stats{Capacity: s.capacity}
	oldest := time.Time{}
	now := time.Now()
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		switch {
		case strings.HasSuffix(entry.Name(), recordSuffix):
			stats.Held++
			info, err := entry.Info()
			if err != nil {
				continue
			}
			if oldest.IsZero() || info.ModTime().Before(oldest) {
				oldest = info.ModTime()
			}
		case strings.HasSuffix(entry.Name(), quarantineSuffix):
			stats.Quarantined++
		}
	}
	if !oldest.IsZero() && now.After(oldest) {
		stats.OldestAge = now.Sub(oldest)
	}
	return stats, nil
}

// Held reports how many records are still waiting to be placed.
func (s *Store) Held() (int, error) {
	stats, err := s.Stats()
	if err != nil {
		return 0, err
	}
	return stats.Held, nil
}

// SpoolObserver receives what each sweep learned. It is how the spool's
// backlog, its oldest waiting record, its remaining capacity, and its
// unreadable records reach operations: the spool holds records an outage
// created, and an outage nobody can see the size of is one nobody can end.
type SpoolObserver interface {
	ObserveCursorSpool(ctx context.Context, stats Stats, report DrainReport)
}

// Reconciler drains the spool into the authoritative cursor store: once at
// start, so records a previous process held are placed as soon as the store is
// reachable, and then on a bounded interval for as long as the service runs.
type Reconciler struct {
	store    *Store
	recorder events.CursorRecorder
	observer SpoolObserver
}

func NewReconciler(store *Store, recorder events.CursorRecorder) (*Reconciler, error) {
	return NewObservedReconciler(store, recorder, nil)
}

// NewObservedReconciler reports every sweep to the given observer.
func NewObservedReconciler(store *Store, recorder events.CursorRecorder, observer SpoolObserver) (*Reconciler, error) {
	if store == nil || recorder == nil {
		return nil, fmt.Errorf("stream cursor reconciler: a spool and a cursor recorder are required")
	}
	return &Reconciler{store: store, recorder: recorder, observer: observer}, nil
}

// ReconcileOnce places everything currently held and reports what the sweep
// found, whether or not every record could be placed.
func (r *Reconciler) ReconcileOnce(ctx context.Context) (DrainReport, error) {
	report, err := r.store.Drain(ctx, r.recorder)
	r.observe(ctx, report)
	return report, err
}

// observe publishes the post-sweep state. Observation is never allowed to
// decide the sweep's outcome: reporting the backlog is not the same act as
// draining it.
func (r *Reconciler) observe(ctx context.Context, report DrainReport) {
	if r.observer == nil {
		return
	}
	stats, err := r.store.Stats()
	if err != nil {
		return
	}
	r.observer.ObserveCursorSpool(ctx, stats, report)
}

// Run sweeps until the context ends. A sweep that cannot place a record
// reports it and leaves the record held for the next one; a sweep that sets a
// record aside as unreadable reports that too, because a quarantined record is
// never placed by any later sweep and needs an operator rather than time.
func (r *Reconciler) Run(ctx context.Context, interval time.Duration, observe func(error)) {
	if interval <= 0 || interval > time.Hour {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		report, err := r.ReconcileOnce(ctx)
		if observe != nil && ctx.Err() == nil {
			if err != nil {
				observe(err)
			} else if report.FirstDeferral != nil {
				observe(fmt.Errorf("stream cursor spool deferred %d record(s): %w", report.Deferred, report.FirstDeferral))
			}
			if report.Quarantined > 0 {
				observe(fmt.Errorf("stream cursor spool set aside %d unreadable record(s); they need operator recovery", report.Quarantined))
			}
			if report.FirstQuarantineFailure != nil {
				observe(fmt.Errorf("stream cursor spool could not set aside %d unreadable record(s): %w", report.QuarantineFailed, report.FirstQuarantineFailure))
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// persisted is the held record's on-disk shape. It is the connection record
// itself and nothing else: a held record must be placeable by a successor
// process that knows nothing about the one that wrote it.
type persisted struct {
	WorkspaceID  string `json:"workspaceId"`
	ProjectID    string `json:"projectId"`
	RunID        string `json:"runId"`
	ConnectionID string `json:"connectionId"`
	LastEventID  string `json:"lastEventId"`
	Reason       string `json:"reason"`
}

// recordName derives a held record's file name from the connection identity it
// belongs to, so the same connection recorded twice occupies one file rather
// than accumulating duplicates, and no tenant-supplied text reaches the path.
func recordName(record events.RecordedCursor) string {
	sum := sha256.Sum256([]byte(record.Scope.WorkspaceID + "\x00" + record.Scope.ProjectID + "\x00" + record.ConnectionID))
	return hex.EncodeToString(sum[:]) + recordSuffix
}

func writeDurably(file *os.File, raw []byte) error {
	if _, err := file.Write(raw); err != nil {
		_ = file.Close()
		return fmt.Errorf("stream cursor spool: write pending record: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("stream cursor spool: flush pending record: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("stream cursor spool: close pending record: %w", err)
	}
	return nil
}

func syncDirectory(directory string) error {
	handle, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("stream cursor spool: open durable directory: %w", err)
	}
	defer func() { _ = handle.Close() }()
	if err := handle.Sync(); err != nil {
		return fmt.Errorf("stream cursor spool: flush durable directory: %w", err)
	}
	return nil
}
