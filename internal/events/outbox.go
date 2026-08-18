package events

import (
	"context"
	"fmt"
	"time"
)

type OutboxMessage struct {
	ID, WorkspaceID, ProjectID, RunID, Topic string
	Sequence                                 Sequence
	Payload                                  []byte
	Attempts                                 int
}

type Publisher interface {
	Publish(context.Context, OutboxMessage) error
}

type OutboxStore interface {
	DispatchReady(context.Context, Publisher, int) (int, error)
}

type Dispatcher struct {
	store     OutboxStore
	publisher Publisher
	batchSize int
}

func NewDispatcher(store OutboxStore, publisher Publisher, batchSize int) (*Dispatcher, error) {
	if store == nil || publisher == nil || batchSize < 1 || batchSize > 1000 {
		return nil, fmt.Errorf("outbox dispatcher requires a store, publisher, and bounded batch size")
	}
	return &Dispatcher{store: store, publisher: publisher, batchSize: batchSize}, nil
}

func (d *Dispatcher) DispatchOnce(ctx context.Context) (int, error) {
	return d.store.DispatchReady(ctx, d.publisher, d.batchSize)
}

func (d *Dispatcher) Run(ctx context.Context, interval time.Duration, observe func(error)) {
	if interval <= 0 || interval > time.Minute {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if _, err := d.DispatchOnce(ctx); err != nil && observe != nil && ctx.Err() == nil {
			observe(err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
