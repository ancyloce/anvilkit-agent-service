package events

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/auth"
)

type cursorReader struct{ waitedAfter uint64 }

func (r *cursorReader) Replay(context.Context, ReplayRequest) (ReplayPage, error) {
	return ReplayPage{CurrentCursor: "event-7", CurrentSequence: 7}, nil
}
func (*cursorReader) Snapshot(context.Context, Scope, string) (SnapshotProjection, error) {
	return SnapshotProjection{}, nil
}
func (r *cursorReader) Wait(_ context.Context, _ Scope, _ string, after uint64, _ time.Duration) error {
	r.waitedAfter = after
	return errors.New("stop")
}

func TestCursorResumeWaitsAfterResolvedSequence(t *testing.T) {
	reader := &cursorReader{}
	stream, err := NewStream(reader, &revokingAuthority{revokeAt: 100}, StreamConfig{Heartbeat: time.Second, Revalidation: time.Second, ReplayLimit: 100, Bounds: Bounds{MaximumBytes: 1024, MaximumFields: 4, MaximumFieldBytes: 32}})
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Serve(context.Background(), httptest.NewRecorder(), Scope{WorkspaceID: "w", ProjectID: "p"}, "run", "event-7"); err == nil {
		t.Fatal("reader stop was not returned")
	}
	if reader.waitedAfter != 7 {
		t.Fatalf("waited after %d, want resolved cursor sequence 7", reader.waitedAfter)
	}
}

func TestEventBoundsRejectProhibitedAndOversizedPayloads(t *testing.T) {
	bounds := Bounds{MaximumBytes: 1024, MaximumFields: 2, MaximumFieldBytes: 16}
	if err := ValidateBytes([]byte(validBoundedEvent), bounds); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		strings.Replace(validBoundedEvent, `"state":"created"`, `"prompt":"classified"`, 1),
		strings.Replace(validBoundedEvent, `"state":"created"`, `"a":"1","b":"2","c":"3"`, 1),
		strings.Replace(validBoundedEvent, `"payload":{"state":"created"}`, `"payload":{"state":"created"},"artifactReference":{"artifactId":"artifact.1","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`, 1),
		strings.Replace(validBoundedEvent, `"payload"`, `"unexpected"`, 1),
	} {
		if err := ValidateBytes([]byte(raw), bounds); err == nil {
			t.Fatalf("invalid event accepted: %s", raw)
		}
	}
}

func TestEventEnvelopeIdentityMustMatchBody(t *testing.T) {
	bounds := Bounds{MaximumBytes: 2048, MaximumFields: 4, MaximumFieldBytes: 32}
	if err := ValidateEnvelope([]byte(validBoundedEvent), bounds, "event.1", "run.1", 1); err != nil {
		t.Fatal(err)
	}
	for _, envelope := range []Event{{ID: "other", RunID: "run.1", Sequence: 1}, {ID: "event.1", RunID: "other", Sequence: 1}, {ID: "event.1", RunID: "run.1", Sequence: 2}} {
		if err := ValidateEnvelope([]byte(validBoundedEvent), bounds, envelope.ID, envelope.RunID, envelope.Sequence); err == nil {
			t.Fatalf("mismatched envelope accepted: %#v", envelope)
		}
	}
	duplicate := strings.Replace(validBoundedEvent, `"eventId":"event.1"`, `"eventId":"event.1","eventId":"other"`, 1)
	if err := ValidateBytes([]byte(duplicate), bounds); err == nil {
		t.Fatal("duplicate event identity accepted")
	}
}

func TestStreamConfigurationRejectsInvalidEventBounds(t *testing.T) {
	_, err := NewStream(onePageReader{}, &revokingAuthority{revokeAt: 100}, StreamConfig{Heartbeat: time.Second, Revalidation: time.Second, ReplayLimit: 100})
	if err == nil {
		t.Fatal("stream accepted zero event bounds")
	}
}

const validBoundedEvent = `{"kind":"AgentEvent","eventId":"event.1","runId":"run.1","workspaceId":"workspace.1","projectId":"project.1","sequence":1,"eventType":"run.created","occurredAt":"2026-08-13T00:00:00.000Z","subject":{"subjectType":"system","subjectId":"agent-service"},"traceContext":{"traceparent":"00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"},"contractBomReference":{"repository":"anvilkit/contracts","bomDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","ociManifestDigest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","evidenceManifestDigest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},"payload":{"state":"created"}}`

func TestGapDetection(t *testing.T) {
	if err := ValidateContiguous([]Event{{Sequence: 2}, {Sequence: 4}}, 1); err == nil {
		t.Fatal("gap accepted")
	}
	if err := ValidateContiguous([]Event{{Sequence: 2}, {Sequence: 3}}, 1); err != nil {
		t.Fatal(err)
	}
}

type onePageReader struct{ event Event }

func (r onePageReader) Replay(context.Context, ReplayRequest) (ReplayPage, error) {
	if r.event.ID == "" {
		return ReplayPage{}, nil
	}
	return ReplayPage{Events: []Event{r.event}, CurrentCursor: r.event.ID, CurrentSequence: r.event.Sequence}, nil
}
func (onePageReader) Snapshot(context.Context, Scope, string) (SnapshotProjection, error) {
	return SnapshotProjection{}, nil
}
func (onePageReader) Wait(ctx context.Context, _ Scope, _ string, _ uint64, _ time.Duration) error {
	<-ctx.Done()
	return ctx.Err()
}

type revokingAuthority struct {
	calls    atomic.Int64
	revokeAt int64
}

type visibilityObserver struct {
	duration time.Duration
	cancel   context.CancelFunc
}

func (o *visibilityObserver) ObserveEventVisibility(_ context.Context, _, _, _ string, duration time.Duration) {
	o.duration = duration
	o.cancel()
}

type advancingObserver struct{ advance func() }

func (o advancingObserver) ObserveEventVisibility(context.Context, string, string, string, time.Duration) {
	o.advance()
}

func TestAuthorizedVisibilityIsInstrumentedAfterFlush(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	observer := &visibilityObserver{cancel: cancel}
	reader := onePageReader{event: Event{ID: "event.1", RunID: "run.1", Sequence: 1, CreatedAt: time.Now().Add(-time.Second), Bytes: []byte(validBoundedEvent)}}
	stream, err := NewStream(reader, &revokingAuthority{revokeAt: 100}, StreamConfig{Heartbeat: time.Second, Revalidation: time.Second, ReplayLimit: 100, Bounds: Bounds{MaximumBytes: 1024, MaximumFields: 4, MaximumFieldBytes: 32}, Observer: observer})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	if err := stream.Serve(ctx, response, Scope{WorkspaceID: "w", ProjectID: "p"}, "run.1", ""); err == nil {
		t.Fatal("cancelled stream returned no error")
	}
	if observer.duration < time.Second || !strings.Contains(response.Body.String(), "event.1") {
		t.Fatalf("visibility was not measured after delivery: duration=%s body=%s", observer.duration, response.Body.String())
	}
}

func TestHeartbeatDoesNotAdvanceEventState(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	stream, err := NewStream(onePageReader{}, &revokingAuthority{revokeAt: 1000}, StreamConfig{Heartbeat: time.Millisecond, Revalidation: time.Second, ReplayLimit: 100, Bounds: Bounds{MaximumBytes: 256, MaximumFields: 4, MaximumFieldBytes: 32}})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	_ = stream.Serve(ctx, response, Scope{WorkspaceID: "w", ProjectID: "p"}, "run", "")
	if !strings.Contains(response.Body.String(), ": heartbeat") || strings.Contains(response.Body.String(), "id:") {
		t.Fatalf("heartbeat changed event state: %s", response.Body.String())
	}
}

func (a *revokingAuthority) Revalidate(context.Context) error {
	if a.calls.Add(1) >= a.revokeAt {
		return context.Canceled
	}
	return nil
}

func TestRevocationTerminatesBeforeAnotherProtectedEvent(t *testing.T) {
	second := strings.ReplaceAll(strings.ReplaceAll(validBoundedEvent, "event.1", "event.2"), `"sequence":1`, `"sequence":2`)
	reader := &fixedPageReader{events: []Event{
		{ID: "event.1", RunID: "run.1", Sequence: 1, Bytes: []byte(validBoundedEvent)},
		{ID: "event.2", RunID: "run.1", Sequence: 2, Bytes: []byte(second)},
	}}
	authority := &revokingAuthority{revokeAt: 3}
	stream, err := NewStream(reader, authority, StreamConfig{Heartbeat: time.Second, Revalidation: time.Second, ReplayLimit: 100, Bounds: Bounds{MaximumBytes: 2048, MaximumFields: 4, MaximumFieldBytes: 32}})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	err = stream.Serve(context.Background(), response, Scope{WorkspaceID: "w", ProjectID: "p"}, "run.1", "")
	if err == nil {
		t.Fatal("revocation did not terminate stream")
	}
	if !strings.Contains(response.Body.String(), "id: event.1") || strings.Contains(response.Body.String(), "id: event.2") {
		t.Fatalf("revocation boundary exposed the wrong events: %s", response.Body.String())
	}
}

func TestTokenExpiryMidStreamTerminatesBeforeNextEvent(t *testing.T) {
	now := time.Unix(1000, 0)
	clock := &atomicClock{}
	clock.now.Store(now.UnixNano())
	validator, err := auth.NewValidator(auth.Config{Issuers: []string{"issuer"}, Audience: "agent"}, eventTrust{}, clock)
	if err != nil {
		t.Fatal(err)
	}
	claims := auth.Claims{Verified: true, Source: auth.SourceWorkload, Issuer: "issuer", Audience: "agent", Subject: "actor", ActorID: "actor", WorkspaceID: "w", ProjectID: "p", Purpose: "agent", KeyID: "key", Scopes: []string{auth.ScopeRead}, ExpiresAt: now.Add(time.Minute)}
	second := strings.ReplaceAll(strings.ReplaceAll(validBoundedEvent, "event.1", "event.2"), `"sequence":1`, `"sequence":2`)
	reader := &fixedPageReader{events: []Event{{ID: "event.1", RunID: "run.1", Sequence: 1, CreatedAt: now, Bytes: []byte(validBoundedEvent)}, {ID: "event.2", RunID: "run.1", Sequence: 2, CreatedAt: now, Bytes: []byte(second)}}}
	stream, err := NewStream(reader, validatingAuthority{validator, claims}, StreamConfig{Heartbeat: time.Second, Revalidation: time.Second, ReplayLimit: 100, Bounds: Bounds{MaximumBytes: 2048, MaximumFields: 4, MaximumFieldBytes: 32}, Observer: advancingObserver{advance: func() { clock.now.Store(now.Add(2 * time.Minute).UnixNano()) }}})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	if err := stream.Serve(context.Background(), response, Scope{WorkspaceID: "w", ProjectID: "p"}, "run.1", ""); err == nil {
		t.Fatal("expired token did not terminate stream")
	}
	if !strings.Contains(response.Body.String(), "id: event.1") || strings.Contains(response.Body.String(), "id: event.2") {
		t.Fatalf("token expiry exposed the wrong events: %s", response.Body.String())
	}
}

type atomicClock struct{ now atomic.Int64 }

func (c *atomicClock) Now() time.Time { return time.Unix(0, c.now.Load()) }

type eventTrust struct{}

func (eventTrust) KeyActive(context.Context, string) (bool, error)     { return true, nil }
func (eventTrust) SubjectActive(context.Context, string) (bool, error) { return true, nil }
func (eventTrust) DelegationActive(context.Context, string, string) (bool, error) {
	return true, nil
}

type validatingAuthority struct {
	validator *auth.Validator
	claims    auth.Claims
}

func (a validatingAuthority) Revalidate(ctx context.Context) error {
	return a.validator.Revalidate(ctx, a.claims, auth.OpStreamEvents)
}

type fixedPageReader struct{ events []Event }

func (r *fixedPageReader) Replay(context.Context, ReplayRequest) (ReplayPage, error) {
	return ReplayPage{Events: append([]Event(nil), r.events...), CurrentCursor: "event.2", CurrentSequence: 2}, nil
}
func (*fixedPageReader) Snapshot(context.Context, Scope, string) (SnapshotProjection, error) {
	return SnapshotProjection{}, nil
}
func (*fixedPageReader) Wait(context.Context, Scope, string, uint64, time.Duration) error {
	return nil
}
