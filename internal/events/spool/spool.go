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
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/events"
)

// recordSuffix names a placed-pending record. The extension is deliberate:
// a partially written file never carries it, so a reader can never mistake a
// torn write for a record.
const recordSuffix = ".cursor.json"

// Store is the local durable holding area for disconnect records.
type Store struct {
	directory string
}

// NewStore prepares the durable directory and proves it is writable, so a
// deployment whose volume is missing or read-only fails at startup rather than
// at the first disconnect it would have had to record.
func NewStore(directory string) (*Store, error) {
	if strings.TrimSpace(directory) == "" {
		return nil, fmt.Errorf("stream cursor spool: a durable directory is required")
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
	return &Store{directory: directory}, nil
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

// Drain places every held record into the authoritative cursor store and
// forgets each one only after the store has accepted it. A record the store
// still refuses stays held for the next sweep, including a sweep in a
// successor process.
func (s *Store) Drain(ctx context.Context, recorder events.CursorRecorder) (int, error) {
	if recorder == nil {
		return 0, fmt.Errorf("stream cursor spool: a cursor recorder is required")
	}
	entries, err := os.ReadDir(s.directory)
	if err != nil {
		return 0, fmt.Errorf("stream cursor spool: read held records: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), recordSuffix) {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	placed := 0
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return placed, err
		}
		path := filepath.Join(s.directory, name)
		raw, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return placed, fmt.Errorf("stream cursor spool: read held record: %w", err)
		}
		var held persisted
		if err := json.Unmarshal(raw, &held); err != nil {
			// A record that cannot be read is not a record that can be placed,
			// and holding it forever would hide every one behind it. It is
			// reported as itself so the sweep's failure names the file.
			return placed, fmt.Errorf("stream cursor spool: held record %q is unreadable: %w", name, err)
		}
		scope := events.Scope{WorkspaceID: held.WorkspaceID, ProjectID: held.ProjectID}
		if err := recorder.RecordCursor(ctx, scope, held.RunID, held.ConnectionID, held.LastEventID, held.Reason); err != nil {
			return placed, fmt.Errorf("stream cursor spool: place held record: %w", err)
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return placed, fmt.Errorf("stream cursor spool: release placed record: %w", err)
		}
		placed++
	}
	return placed, nil
}

// Held reports how many records are still waiting to be placed.
func (s *Store) Held() (int, error) {
	entries, err := os.ReadDir(s.directory)
	if err != nil {
		return 0, fmt.Errorf("stream cursor spool: read held records: %w", err)
	}
	held := 0
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), recordSuffix) {
			held++
		}
	}
	return held, nil
}

// Reconciler drains the spool into the authoritative cursor store: once at
// start, so records a previous process held are placed as soon as the store is
// reachable, and then on a bounded interval for as long as the service runs.
type Reconciler struct {
	store    *Store
	recorder events.CursorRecorder
}

func NewReconciler(store *Store, recorder events.CursorRecorder) (*Reconciler, error) {
	if store == nil || recorder == nil {
		return nil, fmt.Errorf("stream cursor reconciler: a spool and a cursor recorder are required")
	}
	return &Reconciler{store: store, recorder: recorder}, nil
}

// ReconcileOnce places everything currently held.
func (r *Reconciler) ReconcileOnce(ctx context.Context) (int, error) {
	return r.store.Drain(ctx, r.recorder)
}

// Run sweeps until the context ends. A sweep that cannot place a record
// reports it and leaves the record held for the next one.
func (r *Reconciler) Run(ctx context.Context, interval time.Duration, observe func(error)) {
	if interval <= 0 || interval > time.Hour {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if _, err := r.ReconcileOnce(ctx); err != nil && observe != nil && ctx.Err() == nil {
			observe(err)
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
