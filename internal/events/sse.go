package events

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
)

type StreamAuthority interface{ Revalidate(context.Context) error }
type VisibilityObserver interface {
	ObserveEventVisibility(context.Context, string, string, string, time.Duration)
}

// CursorRecorder durably records the last successfully sent public cursor
// when a stream ends, so a disconnect — a slow consumer above all — leaves an
// operational record of exactly what the client had.
type CursorRecorder interface {
	RecordCursor(ctx context.Context, scope Scope, runID, connectionID, lastEventID, reason string) error
}

// CursorSpool is the durable retry path a disconnect record takes when the
// authoritative cursor store cannot accept it. Holding the record is not an
// optimisation: the record is written before the connection ends, so a store
// that is unreachable must not be allowed to turn the write into a report
// about a write. A spooled record outlives the process that spooled it and is
// placed in the authoritative store by the reconciler that drains the spool.
type CursorSpool interface {
	SpoolCursor(ctx context.Context, record RecordedCursor) error
}

// CursorRecordObserver receives a disconnect record only when neither the
// authoritative store nor the durable spool could take it — the one case where
// the record really is lost. It is a report of last resort, never the fallback
// itself: an operational counter is not a place a record is kept.
type CursorRecordObserver interface {
	ObserveCursorRecordFailure(ctx context.Context, scope Scope, runID, connectionID, lastEventID, reason string, err error)
}

// cursorRecordAttempts bounds how many times a stream tries to persist its
// disconnect record before reporting the failure. The stream is already
// ending, so the retries are short and finite.
const cursorRecordAttempts = 3

// cursorRecordBackoff is the pause between disconnect-record attempts.
const cursorRecordBackoff = 100 * time.Millisecond

// cursorSpoolTimeout bounds the durable spool write that keeps a disconnect
// record the authoritative store refused. It is separate from the store's
// deadline so a slow store cannot consume the budget the durable write needs.
const cursorSpoolTimeout = 2 * time.Second

type StreamConfig struct {
	Heartbeat, Revalidation time.Duration
	ReplayLimit             int
	Bounds                  Bounds
	Observer                VisibilityObserver
	// WriteTimeout bounds every event write: a consumer that cannot keep up
	// is disconnected instead of holding the stream goroutine hostage.
	// Zero disables the deadline (unit-test writers).
	WriteTimeout time.Duration
	// Cursors records the last sent durable cursor on disconnect. Nil skips
	// recording (unit-test streams); production composition always sets it.
	Cursors CursorRecorder
	// CursorSpool holds a disconnect record the authoritative store refused,
	// durably and across restarts, until a reconciler places it. It is
	// required whenever Cursors is set: without it a store outage turns the
	// governed record into a lost one.
	CursorSpool CursorSpool
	// CursorFailures receives disconnect records that neither the store nor
	// the spool could take. It is required whenever Cursors is set: a record
	// lost from both durable paths must still reach an operator.
	CursorFailures CursorRecordObserver
	// MaximumConnections caps concurrent streams per instance; zero means
	// uncapped (unit-test streams).
	MaximumConnections int
	// Deltas is the provisional stream-delta broker. Delta frames carry no
	// SSE id, so they can never advance the durable public cursor. Nil skips
	// the provisional channel entirely.
	Deltas *DeltaBroker
}
type Stream struct {
	reader    Reader
	authority StreamAuthority
	config    StreamConfig
	active    chan struct{}
}

func NewStream(reader Reader, authority StreamAuthority, config StreamConfig) (*Stream, error) {
	if reader == nil || authority == nil || config.Heartbeat <= 0 || config.Revalidation <= 0 || config.ReplayLimit < 1 || config.ReplayLimit > 1000 || config.Bounds.Validate() != nil {
		return nil, fmt.Errorf("SSE stream configuration is invalid")
	}
	if config.Cursors != nil && config.CursorSpool == nil {
		return nil, fmt.Errorf("SSE stream configuration is invalid: a durable cursor recorder requires a durable spool for records the store refuses")
	}
	if config.Cursors != nil && config.CursorFailures == nil {
		return nil, fmt.Errorf("SSE stream configuration is invalid: a durable cursor recorder requires a failure observer")
	}
	stream := &Stream{reader: reader, authority: authority, config: config}
	if config.MaximumConnections > 0 {
		stream.active = make(chan struct{}, config.MaximumConnections)
	}
	return stream, nil
}

func (s *Stream) Serve(ctx context.Context, response http.ResponseWriter, scope Scope, runID, cursor string) error {
	if s.active != nil {
		select {
		case s.active <- struct{}{}:
			defer func() { <-s.active }()
		default:
			overloaded := problem.New(problem.CodeAdmissionOverloaded, "")
			overloaded.Detail = "the instance's concurrent event-stream limit is reached"
			return overloaded
		}
	}
	if !flushable(response) {
		return fmt.Errorf("SSE response does not support flushing")
	}
	controller := http.NewResponseController(response)
	// The write deadline is the only thing standing between a stalled
	// consumer and a stream goroutine held open indefinitely, so a writer
	// that cannot carry one fails the stream instead of silently serving it
	// unprotected. Probing costs nothing on the wire: setting a deadline
	// writes no bytes, so a stream that has to answer 410 still can.
	if s.config.WriteTimeout > 0 {
		if err := controller.SetWriteDeadline(time.Now().Add(s.config.WriteTimeout)); err != nil {
			return fmt.Errorf("event stream write deadlines are unavailable on this response writer: %w", err)
		}
	}
	connectionID, err := streamConnectionID()
	if err != nil {
		return err
	}
	reason := "client-closed"
	// cursor is advanced only by a frame that was written and flushed, so the
	// recorded value is always what the client actually received.
	defer func() {
		if s.config.Cursors == nil {
			return
		}
		s.recordCursor(scope, runID, connectionID, cursor, reason)
	}()
	write := func(format string, arguments ...any) error {
		if s.config.WriteTimeout > 0 {
			if err := controller.SetWriteDeadline(time.Now().Add(s.config.WriteTimeout)); err != nil {
				return fmt.Errorf("event stream write deadline could not be set: %w", err)
			}
		}
		if _, err := fmt.Fprintf(response, format, arguments...); err != nil {
			reason = "slow-consumer"
			return fmt.Errorf("event stream write failed after the deadline: %w", err)
		}
		// A frame that is buffered is not a frame the client has. Flushing
		// through the controller is what turns a failed hand-off into an
		// error instead of a silently discarded write.
		if err := controller.Flush(); err != nil {
			reason = "slow-consumer"
			return fmt.Errorf("event stream flush failed: %w", err)
		}
		return nil
	}
	var deltaFrames <-chan []byte
	if s.config.Deltas != nil {
		frames, unsubscribe := s.config.Deltas.Subscribe(scope.WorkspaceID, runID)
		defer unsubscribe()
		deltaFrames = frames
	}
	response.Header().Set("Content-Type", "text/event-stream")
	response.Header().Set("Cache-Control", "no-store")
	heartbeat := time.NewTicker(s.config.Heartbeat)
	defer heartbeat.Stop()
	revalidation := time.NewTicker(s.config.Revalidation)
	defer revalidation.Stop()
	var afterSequence uint64
	// Every revalidation on this stream is one rule: authority that stops
	// being current ends the connection, and the disconnect is recorded as
	// what it was. The reason is set beside each call rather than derived
	// afterwards, because the durable record of why a client lost its stream
	// is the only account an operator or an audit has.
	revalidate := func() error {
		if err := s.authority.Revalidate(ctx); err != nil {
			reason = "authority-revoked"
			return err
		}
		return nil
	}
	for {
		// The admission check on entry, before any frame is replayed.
		if err := revalidate(); err != nil {
			return err
		}
		page, err := s.reader.Replay(ctx, ReplayRequest{Scope: scope, RunID: runID, AfterEventID: cursor, Limit: s.config.ReplayLimit})
		if err != nil {
			return err
		}
		afterSequence = page.CurrentSequence
		for _, event := range page.Events {
			// Per delivered event: a revoked actor must not receive the next
			// frame of a page that was already read.
			if err := revalidate(); err != nil {
				return err
			}
			if event.RunID != runID {
				return fmt.Errorf("event replay returned a different run identity")
			}
			if err := ValidateEnvelope(event.Bytes, s.config.Bounds, event.ID, event.RunID, event.Sequence); err != nil {
				return err
			}
			if err := write("id: %s\nevent: agent-event\ndata: %s\n\n", event.ID, event.Bytes); err != nil {
				return err
			}
			if s.config.Observer != nil && !event.CreatedAt.IsZero() {
				s.config.Observer.ObserveEventVisibility(ctx, scope.WorkspaceID, scope.ProjectID, runID, time.Since(event.CreatedAt))
			}
			cursor, afterSequence = event.ID, event.Sequence
		}
		if page.HasMore {
			continue
		}
		waitContext, cancel := context.WithCancel(ctx)
		waited := make(chan error, 1)
		waitAfter := afterSequence
		go func() {
			waited <- s.reader.Wait(waitContext, scope, runID, waitAfter, 2*s.config.Heartbeat)
			close(waited)
		}()
		select {
		case <-ctx.Done():
			cancel()
			return ctx.Err()
		case err := <-waited:
			cancel()
			if err != nil {
				return err
			}
		case frame := <-deltaFrames:
			cancel()
			// Provisional frames are anonymous on the SSE wire: no id line,
			// so Last-Event-ID and the durable cursor never move for them.
			if err := write("event: agent-stream-delta\ndata: %s\n\n", frame); err != nil {
				return err
			}
		case <-revalidation.C:
			cancel()
			// The periodic re-proof, on its own cadence.
			if err := revalidate(); err != nil {
				return err
			}
		case <-heartbeat.C:
			cancel()
			// The heartbeat re-proof: an idle stream is still a stream, so a
			// keep-alive frame is only written under current authority.
			if err := revalidate(); err != nil {
				return err
			}
			if err := write(": heartbeat\n\n"); err != nil {
				return err
			}
		}
	}
}

// recordCursor persists one ended connection's last delivered cursor before
// the connection ends. The request context is already finished when a stream
// ends, so the record runs on its own bounded deadline.
//
// The authoritative store is tried first, briefly, because a transient refusal
// is the common case and placing the record there directly is what an operator
// reads. A store that keeps refusing does not end the obligation: the record
// goes to the durable spool, which survives this process and is drained into
// the store by the reconciler. Only a record neither durable path would take
// is reported — and it is reported as a loss, not filed as one.
func (s *Stream) recordCursor(scope Scope, runID, connectionID, lastEventID, reason string) {
	recordCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var err error
	for attempt := 0; attempt < cursorRecordAttempts; attempt++ {
		if attempt > 0 {
			timer := time.NewTimer(cursorRecordBackoff)
			select {
			case <-recordCtx.Done():
				timer.Stop()
			case <-timer.C:
			}
		}
		if err = s.config.Cursors.RecordCursor(recordCtx, scope, runID, connectionID, lastEventID, reason); err == nil {
			return
		}
	}
	record := RecordedCursor{Scope: scope, RunID: runID, ConnectionID: connectionID, LastEventID: lastEventID, Reason: reason}
	if s.config.CursorSpool != nil {
		// The spool is given its own deadline: the attempts above may have
		// consumed the record deadline, and a durable write that is skipped
		// because an earlier store was slow is a record that was not kept.
		spoolCtx, spoolCancel := context.WithTimeout(context.Background(), cursorSpoolTimeout)
		spoolErr := s.config.CursorSpool.SpoolCursor(spoolCtx, record)
		spoolCancel()
		if spoolErr == nil {
			return
		}
		err = fmt.Errorf("%w; durable spool refused the record: %w", err, spoolErr)
	}
	if s.config.CursorFailures != nil {
		s.config.CursorFailures.ObserveCursorRecordFailure(recordCtx, scope, runID, connectionID, lastEventID, reason, err)
	}
}

// flushable reports whether a response can be flushed, resolving wrappers the
// same way http.ResponseController does. It exists because the support check
// has to happen before anything is written — a stream that must answer 410
// cannot afford a probe that commits a 200 — and a plain http.Flusher
// assertion would miss a wrapper that reports flush errors or that only
// unwraps to a flushable writer.
func flushable(response http.ResponseWriter) bool {
	for {
		switch value := response.(type) {
		case interface{ FlushError() error }:
			return true
		case http.Flusher:
			return true
		case interface{ Unwrap() http.ResponseWriter }:
			response = value.Unwrap()
		default:
			return false
		}
	}
}

func streamConnectionID() (string, error) {
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("allocate stream connection identity: %w", err)
	}
	return "stream." + hex.EncodeToString(raw), nil
}

// MemoryCursorRecorder records stream cursors in memory for tests. Concurrent
// connections to one run record through the same recorder, so it is safe for
// concurrent use exactly as the durable recorder is. It is also its own
// durable spool and its own failure observer, so a test exercises the complete
// pairing production requires rather than a looser one.
type MemoryCursorRecorder struct {
	lock     sync.Mutex
	records  []RecordedCursor
	spooled  []RecordedCursor
	failures []RecordedCursor
	// refuse makes every persistence attempt fail, so a test can prove a
	// refused disconnect record reaches the durable retry path.
	refuse error
	// refuseSpool makes the durable retry path fail too, so a test can prove
	// the one genuinely lost case is reported.
	refuseSpool error
}

// RefuseCursorRecords makes every subsequent record attempt fail with the
// given reason.
func (r *MemoryCursorRecorder) RefuseCursorRecords(reason error) {
	r.lock.Lock()
	defer r.lock.Unlock()
	r.refuse = reason
}

// RefuseCursorSpool makes every subsequent durable spool attempt fail with the
// given reason.
func (r *MemoryCursorRecorder) RefuseCursorSpool(reason error) {
	r.lock.Lock()
	defer r.lock.Unlock()
	r.refuseSpool = reason
}

// SpoolCursor holds a record the store refused, so a test can prove the
// disconnect record entered the durable retry path rather than being reported
// as lost.
func (r *MemoryCursorRecorder) SpoolCursor(_ context.Context, record RecordedCursor) error {
	r.lock.Lock()
	defer r.lock.Unlock()
	if r.refuseSpool != nil {
		return r.refuseSpool
	}
	r.spooled = append(r.spooled, record)
	return nil
}

// Spooled returns a copy of every record held by the durable retry path.
func (r *MemoryCursorRecorder) Spooled() []RecordedCursor {
	r.lock.Lock()
	defer r.lock.Unlock()
	return append([]RecordedCursor(nil), r.spooled...)
}

// ObserveCursorRecordFailure retains a disconnect record the recorder could
// not persist, so a test can assert the operational fact survived the failure.
func (r *MemoryCursorRecorder) ObserveCursorRecordFailure(_ context.Context, scope Scope, runID, connectionID, lastEventID, reason string, _ error) {
	r.lock.Lock()
	defer r.lock.Unlock()
	r.failures = append(r.failures, RecordedCursor{Scope: scope, RunID: runID, ConnectionID: connectionID, LastEventID: lastEventID, Reason: reason})
}

// Failures returns a copy of every disconnect record that could not be
// persisted.
func (r *MemoryCursorRecorder) Failures() []RecordedCursor {
	r.lock.Lock()
	defer r.lock.Unlock()
	return append([]RecordedCursor(nil), r.failures...)
}

type RecordedCursor struct {
	Scope        Scope
	RunID        string
	ConnectionID string
	LastEventID  string
	Reason       string
}

func (r *MemoryCursorRecorder) RecordCursor(_ context.Context, scope Scope, runID, connectionID, lastEventID, reason string) error {
	r.lock.Lock()
	defer r.lock.Unlock()
	if r.refuse != nil {
		return r.refuse
	}
	r.records = append(r.records, RecordedCursor{Scope: scope, RunID: runID, ConnectionID: connectionID, LastEventID: lastEventID, Reason: reason})
	return nil
}

// Recorded returns a copy of everything recorded so far.
func (r *MemoryCursorRecorder) Recorded() []RecordedCursor {
	r.lock.Lock()
	defer r.lock.Unlock()
	return append([]RecordedCursor(nil), r.records...)
}

func WriteProblem(response http.ResponseWriter, err error) {
	var details problem.Details
	if !errors.As(err, &details) {
		details = problem.Internal("")
	}
	response.Header().Set("Content-Type", "application/problem+json")
	response.WriteHeader(details.Status)
	_ = json.NewEncoder(response).Encode(details)
}
