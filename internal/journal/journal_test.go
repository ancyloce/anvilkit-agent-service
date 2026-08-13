package journal

import (
	"context"
	"fmt"
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
		fact, err := NewFact(fmt.Sprintf("fact-%d", index), "w", "p", class, uint64(index+1), []byte(class), nil)
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
	fact, _ := NewFact("fact", "w", "p", FactAuthorization, 1, []byte("authorization"), nil)
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
	first, _ := NewFact("fact", "w", "p", FactCreate, 1, []byte("one"), []byte("result"))
	if err := store.Append(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	if err := store.Append(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	second, _ := NewFact("fact", "w", "p", FactCreate, 1, []byte("two"), []byte("result"))
	if err := store.Append(context.Background(), second); err == nil {
		t.Fatal("different fact bytes accepted")
	}
}
