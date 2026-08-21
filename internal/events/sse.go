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
	flusher, ok := response.(http.Flusher)
	if !ok {
		return fmt.Errorf("SSE response does not support flushing")
	}
	connectionID, err := streamConnectionID()
	if err != nil {
		return err
	}
	reason := "client-closed"
	defer func() {
		if s.config.Cursors == nil {
			return
		}
		recordCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.config.Cursors.RecordCursor(recordCtx, scope, runID, connectionID, cursor, reason)
	}()
	write := func(format string, arguments ...any) error {
		if s.config.WriteTimeout > 0 {
			controller := http.NewResponseController(response)
			if err := controller.SetWriteDeadline(time.Now().Add(s.config.WriteTimeout)); err != nil && !errors.Is(err, http.ErrNotSupported) {
				return err
			}
		}
		if _, err := fmt.Fprintf(response, format, arguments...); err != nil {
			reason = "slow-consumer"
			return fmt.Errorf("event stream write failed after the deadline: %w", err)
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
	revalidate := time.NewTicker(s.config.Revalidation)
	defer revalidate.Stop()
	var afterSequence uint64
	for {
		if err := s.authority.Revalidate(ctx); err != nil {
			return err
		}
		page, err := s.reader.Replay(ctx, ReplayRequest{Scope: scope, RunID: runID, AfterEventID: cursor, Limit: s.config.ReplayLimit})
		if err != nil {
			return err
		}
		afterSequence = page.CurrentSequence
		for _, event := range page.Events {
			if err := s.authority.Revalidate(ctx); err != nil {
				reason = "authority-revoked"
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
			flusher.Flush()
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
			flusher.Flush()
		case <-revalidate.C:
			cancel()
			if err := s.authority.Revalidate(ctx); err != nil {
				return err
			}
		case <-heartbeat.C:
			cancel()
			if err := s.authority.Revalidate(ctx); err != nil {
				return err
			}
			if err := write(": heartbeat\n\n"); err != nil {
				return err
			}
			flusher.Flush()
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
// concurrent use exactly as the durable recorder is.
type MemoryCursorRecorder struct {
	lock    sync.Mutex
	records []RecordedCursor
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
