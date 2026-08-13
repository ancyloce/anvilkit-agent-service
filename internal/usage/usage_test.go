package usage

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

type flakySink struct {
	MemorySink
	failed bool
}

func (s *flakySink) Observe(ctx context.Context, value Observation) error {
	if !s.failed {
		s.failed = true
		return errors.New("sink unavailable")
	}
	return s.MemorySink.Observe(ctx, value)
}

var observed = time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)

func value(kind string, recovery, generation, sequence uint64, attempt string) Observation {
	return Observation{WorkspaceID: "workspace", ProjectID: "project", ObservationID: fmt.Sprintf("observation-%s-%d-%d-%d", kind, recovery, generation, sequence), RootRunID: "root", RunID: "run", TaskID: "task", RecoveryEpoch: recovery, ExecutionGeneration: generation, PhysicalAttemptID: attempt, ReservationID: "reservation", Meter: "provider-cost", Quantity: "1", Unit: "usd-micro", Currency: "USD", CostMicros: 10, MeterSequence: sequence, Final: true, ObservedAt: observed, Provider: "provider", BuildIdentity: "build", Traceparent: "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"}
}
func TestEveryAttemptClassAcceptedIndependentOfResult(t *testing.T) {
	store := NewMemoryStore()
	sink := &MemorySink{}
	pipeline, _ := New(store, sink)
	classes := []string{"winning", "losing", "stale", "superseded", "expired", "delayed", "pre-restore"}
	for index, class := range classes {
		v := value(class, uint64(index%2), uint64(index+1), 1, class)
		if accepted, err := pipeline.Accept(context.Background(), v); err != nil || !accepted {
			t.Fatalf("%s accepted=%v err=%v", class, accepted, err)
		}
	}
	if store.Count() != len(classes) || len(sink.Values) != len(classes) {
		t.Fatalf("undercount store=%d sink=%d", store.Count(), len(sink.Values))
	}
}
func TestDedupProviderIdentityAndAttemptIdentity(t *testing.T) {
	store := NewMemoryStore()
	sink := &MemorySink{}
	pipeline, _ := New(store, sink)
	provider := value("provider", 1, 1, 1, "attempt")
	provider.ProviderEventID = "billing-1"
	accepted, _ := pipeline.Accept(context.Background(), provider)
	if !accepted {
		t.Fatal("first rejected")
	}
	duplicate := provider
	duplicate.ObservationID = "different-observation"
	if _, err := pipeline.Accept(context.Background(), duplicate); err == nil {
		t.Fatal("different bytes reused provider event")
	}
	distinct := value("distinct", 2, 2, 1, "attempt")
	if accepted, err := pipeline.Accept(context.Background(), distinct); err != nil || !accepted {
		t.Fatal("distinct recovery/execution collapsed")
	}
	sameAttempt := distinct
	sameAttempt.ObservationID = "other"
	sameAttempt.MeterSequence = 2
	if accepted, err := pipeline.Accept(context.Background(), sameAttempt); err != nil || !accepted {
		t.Fatal("monotonic sequence collapsed")
	}
}
func TestMissingFinalRepairAndSeparation(t *testing.T) {
	store := NewMemoryStore()
	sink := &MemorySink{}
	pipeline, _ := New(store, sink)
	partial := value("partial", 1, 1, 1, "attempt")
	partial.Final = false
	if _, err := pipeline.Accept(context.Background(), partial); err != nil {
		t.Fatal(err)
	}
	final, err := pipeline.FinalKnown(context.Background(), partial)
	if err != nil || final {
		t.Fatal("missing final reported final")
	}
	repair := partial
	repair.ObservationID = "repair"
	repair.ProviderEventID = "billing-final"
	repair.MeterSequence = 2
	repair.CostMicros = 20
	if accepted, err := pipeline.RepairFinal(context.Background(), repair); err != nil || !accepted {
		t.Fatalf("repair=%v %v", accepted, err)
	}
	final, _ = pipeline.FinalKnown(context.Background(), repair)
	if !final {
		t.Fatal("billing repair did not close attempt")
	}
	if store.Count() != 2 {
		t.Fatal("usage mutated another state surface")
	}
}

func TestDurableObservationRetriesAuthoritativeForward(t *testing.T) {
	store := NewMemoryStore()
	sink := &flakySink{}
	pipeline, _ := New(store, sink)
	observation := value("forward-retry", 1, 1, 1, "attempt")
	if accepted, err := pipeline.Accept(context.Background(), observation); err == nil || accepted {
		t.Fatalf("first forward accepted=%v err=%v", accepted, err)
	}
	if accepted, err := pipeline.Accept(context.Background(), observation); err != nil || accepted {
		t.Fatalf("durable retry accepted=%v err=%v", accepted, err)
	}
	if store.Count() != 1 || len(sink.Values) != 1 {
		t.Fatalf("store=%d sink=%d", store.Count(), len(sink.Values))
	}
}
