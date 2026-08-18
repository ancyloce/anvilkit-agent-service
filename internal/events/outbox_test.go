package events

import (
	"context"
	"errors"
	"testing"
	"time"
)

type outboxStoreStub struct {
	calls int
	err   error
}

func (s *outboxStoreStub) DispatchReady(_ context.Context, _ Publisher, batch int) (int, error) {
	s.calls++
	if batch != 17 {
		return 0, errors.New("unexpected batch size")
	}
	return 3, s.err
}

type publisherStub struct{}

func (publisherStub) Publish(context.Context, OutboxMessage) error { return nil }

func TestDispatcherDispatchesConfiguredBatch(t *testing.T) {
	store := &outboxStoreStub{}
	dispatcher, err := NewDispatcher(store, publisherStub{}, 17)
	if err != nil {
		t.Fatal(err)
	}
	count, err := dispatcher.DispatchOnce(context.Background())
	if err != nil || count != 3 || store.calls != 1 {
		t.Fatalf("DispatchOnce() = (%d, %v), calls = %d", count, err, store.calls)
	}
}

func TestDispatcherRunReportsFailureAndStops(t *testing.T) {
	want := errors.New("publish unavailable")
	store := &outboxStoreStub{err: want}
	dispatcher, err := NewDispatcher(store, publisherStub{}, 17)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	reported := make(chan error, 1)
	go dispatcher.Run(ctx, time.Millisecond, func(err error) {
		reported <- err
		cancel()
	})
	select {
	case got := <-reported:
		if !errors.Is(got, want) {
			t.Fatalf("reported error = %v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("dispatcher did not report failure")
	}
}
