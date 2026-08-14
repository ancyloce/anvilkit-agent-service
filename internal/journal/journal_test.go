package journal

import (
	"context"
	"fmt"
	"sync"
	"testing"
)

type restoredDatabase struct {
	facts     map[string]Fact
	conflicts map[string]bool
}

func (d *restoredDatabase) Apply(_ context.Context, fact Fact) (ApplyResult, error) {
	if d.conflicts[fact.ID] {
		return Conflict, nil
	}
	d.facts[fact.ID] = fact
	return Reconstructed, nil
}

func TestLostAcknowledgementMatrixReconstructsEveryFactClass(t *testing.T) {
	store := NewMemoryStore()
	coordinator := NewCoordinator(store)
	for index, class := range Classes() {
		fact, err := NewFact(fmt.Sprintf("fact-%d", index), "w", "p", class, []byte(class), nil)
		if err != nil {
			t.Fatal(err)
		}
		got, err := coordinator.Acknowledge(context.Background(), fact, func(context.Context) ([]byte, error) { return []byte("projection-" + string(class)), nil })
		if err != nil || string(got) != "projection-"+string(class) {
			t.Fatalf("class %s was not acknowledged: %q %v", class, got, err)
		}
	}
	restored := &restoredDatabase{facts: make(map[string]Fact), conflicts: map[string]bool{"fact-3": true}}
	results, err := Reconstruct(context.Background(), store, restored)
	if err != nil {
		t.Fatal(err)
	}
	for index := range Classes() {
		id := fmt.Sprintf("fact-%d", index)
		if results[id] != Reconstructed && results[id] != Conflict {
			t.Fatalf("fact %s silently lost", id)
		}
	}
}

func TestAcknowledgementWaitsForJournalAndFailsClosed(t *testing.T) {
	store := NewMemoryStore()
	store.SetAvailable(false)
	coordinator := NewCoordinator(store)
	fact, _ := NewFact("fact", "w", "p", FactAuthorization, []byte("authorization"), nil)
	committed := false
	if _, err := coordinator.Acknowledge(context.Background(), fact, func(context.Context) ([]byte, error) { committed = true; return []byte("result"), nil }); err == nil {
		t.Fatal("unavailable journal acknowledged write")
	}
	if !committed {
		t.Fatal("database commit simulation did not run")
	}
}

func TestDuplicateFactsRequireIdenticalDigestAndProjection(t *testing.T) {
	store := NewMemoryStore()
	first, _ := NewFact("fact", "w", "p", FactCreate, []byte("one"), []byte("result"))
	retained, err := store.Append(context.Background(), first)
	if err != nil || retained.OperationOrder != 1 {
		t.Fatal(err)
	}
	replayed, err := store.Append(context.Background(), first)
	if err != nil || replayed.OperationOrder != retained.OperationOrder {
		t.Fatal(err)
	}
	second, _ := NewFact("fact", "w", "p", FactCreate, []byte("two"), []byte("result"))
	if _, err := store.Append(context.Background(), second); err == nil {
		t.Fatal("different fact bytes accepted")
	}
}

func TestStoreAssignsOneGlobalMonotonicOrderUnderConcurrency(t *testing.T) {
	store := NewMemoryStore()
	const writers = 64
	var wait sync.WaitGroup
	errors := make(chan error, writers)
	for index := range writers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			fact, err := NewFact(fmt.Sprintf("concurrent-%d", index), "w", "p", FactCreate, []byte(fmt.Sprintf("value-%d", index)), nil)
			if err == nil {
				_, err = store.Append(context.Background(), fact)
			}
			errors <- err
		}()
	}
	wait.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	facts, err := store.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[uint64]bool, writers)
	for _, fact := range facts {
		if fact.OperationOrder < 1 || fact.OperationOrder > writers || seen[fact.OperationOrder] {
			t.Fatalf("invalid assigned order %d", fact.OperationOrder)
		}
		seen[fact.OperationOrder] = true
	}
}
