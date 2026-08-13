package events

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
)

type StreamAuthority interface{ Revalidate(context.Context) error }
type VisibilityObserver interface {
	ObserveEventVisibility(context.Context, string, string, string, time.Duration)
}
type StreamConfig struct {
	Heartbeat, Revalidation time.Duration
	ReplayLimit             int
	Bounds                  Bounds
	Observer                VisibilityObserver
}
type Stream struct {
	reader    Reader
	authority StreamAuthority
	config    StreamConfig
}

func NewStream(reader Reader, authority StreamAuthority, config StreamConfig) (*Stream, error) {
	if reader == nil || authority == nil || config.Heartbeat <= 0 || config.Revalidation <= 0 || config.ReplayLimit < 1 || config.ReplayLimit > 1000 {
		return nil, fmt.Errorf("SSE stream configuration is invalid")
	}
	return &Stream{reader: reader, authority: authority, config: config}, nil
}

func (s *Stream) Serve(ctx context.Context, response http.ResponseWriter, scope Scope, runID, cursor string) error {
	flusher, ok := response.(http.Flusher)
	if !ok {
		return fmt.Errorf("SSE response does not support flushing")
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
				return err
			}
			if err := ValidateBytes(event.Bytes, s.config.Bounds); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(response, "id: %s\nevent: agent-event\ndata: %s\n\n", event.ID, event.Bytes); err != nil {
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
			if _, err := fmt.Fprint(response, ": heartbeat\n\n"); err != nil {
				return err
			}
			flusher.Flush()
		}
	}
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
