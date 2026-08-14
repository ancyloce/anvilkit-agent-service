package queue

import (
	"context"
	"errors"
	"testing"
)

func message() Message {
	return Message{ID: "message", WorkspaceID: "workspace", ProjectID: "project", RunID: "run", TaskID: "task", Topic: "tasks", Payload: []byte(`{"runId":"run","taskId":"task"}`), Attempts: 1}
}

func TestQueueRequiresExplicitLineageAndReplayIsIdempotent(t *testing.T) {
	memory := NewMemory()
	processor, _ := New(memory, memory, &failEffect{}, 1, nil)
	missing := message()
	missing.RunID = ""
	if err := processor.Handle(context.Background(), missing); err == nil {
		t.Fatal("message without run lineage accepted")
	}
	if err := processor.Handle(context.Background(), message()); err != nil {
		t.Fatal(err)
	}
	replay, _ := New(memory, memory, memory, 1, nil)
	if err := memory.Replay(context.Background(), 0, replay); err != nil {
		t.Fatal(err)
	}
	if err := memory.Replay(context.Background(), 0, replay); err != nil {
		t.Fatal(err)
	}
	effects, _, _ := memory.Stats()
	if effects != 1 {
		t.Fatalf("repeated replay effects=%d", effects)
	}
}
func TestWriteThenAckCrashRedeliversExactlyOnceSemantic(t *testing.T) {
	for _, point := range []FailurePoint{AfterEffect, AfterInboxCommit, BeforeAck} {
		t.Run(string(point), func(t *testing.T) {
			memory := NewMemory()
			fired := false
			processor, _ := New(memory, memory, memory, 3, func(candidate FailurePoint) error {
				if candidate == point && !fired {
					fired = true
					return errors.New("crash")
				}
				return nil
			})
			if err := processor.Handle(context.Background(), message()); err == nil {
				t.Fatal("crash not injected")
			}
			if err := processor.Handle(context.Background(), message()); err != nil {
				t.Fatal(err)
			}
			effects, acked, _ := memory.Stats()
			if effects != 1 || acked != 1 {
				t.Fatalf("effects=%d acked=%d", effects, acked)
			}
		})
	}
}
func TestDLQStableFieldsReplayDedup(t *testing.T) {
	memory := NewMemory()
	failing := &failEffect{}
	processor, _ := New(memory, memory, failing, 1, nil)
	m := message()
	if err := processor.Handle(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	_, _, dead := memory.Stats()
	if dead != 1 {
		t.Fatal("message not dead-lettered")
	}
	replay, _ := New(memory, memory, memory, 1, nil)
	if err := memory.Replay(context.Background(), 0, replay); err != nil {
		t.Fatal(err)
	}
	effects, acked, _ := memory.Stats()
	if effects != 1 || acked != 1 {
		t.Fatalf("replay effects=%d ack=%d", effects, acked)
	}
}

func TestInboxIdentityIsTenantScoped(t *testing.T) {
	memory := NewMemory()
	processor, _ := New(memory, memory, memory, 1, nil)
	first := message()
	second := first
	second.WorkspaceID = "other-workspace"
	second.Payload = []byte(`{"runId":"other","taskId":"task"}`)
	if err := processor.Handle(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if err := processor.Handle(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	effects, acknowledged, _ := memory.Stats()
	if effects != 2 || acknowledged != 2 {
		t.Fatalf("effects=%d acknowledged=%d", effects, acknowledged)
	}
}

type failEffect struct{}

func (*failEffect) Write(context.Context, Message) error { return errors.New("worker failed") }
