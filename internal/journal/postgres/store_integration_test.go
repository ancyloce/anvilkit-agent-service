package postgres

import (
	"context"
	"fmt"
	"os"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ancyloce/anvilkit-agent-service/internal/journal"
)

func TestPostgresJournalAssignsGlobalOrderAndRejectsConflicts(t *testing.T) {
	databaseURL := os.Getenv("POSTGRES_TEST_URL")
	if databaseURL == "" {
		if os.Getenv("ANVILKIT_REQUIRE_POSTGRES_PROOFS") != "" {
			t.Fatal("POSTGRES_TEST_URL is not set but ANVILKIT_REQUIRE_POSTGRES_PROOFS requires these proofs; point POSTGRES_TEST_URL at a disposable PostgreSQL database")
		}
		t.Skip("POSTGRES_TEST_URL is not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	store := New(pool)
	if err := store.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	prefix := fmt.Sprintf("workflow-%d", time.Now().UnixNano())
	const writers = 32
	var wait sync.WaitGroup
	retained := make(chan journal.Fact, writers)
	errors := make(chan error, writers)
	for index := range writers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			fact, err := journal.NewFact(fmt.Sprintf("%s-%d", prefix, index), "workspace", "project", journal.FactCreate, []byte(fmt.Sprintf("request-%d", index)), []byte(fmt.Sprintf("response-%d", index)))
			if err == nil {
				var value journal.Fact
				value, err = store.Append(ctx, fact)
				retained <- value
			}
			errors <- err
		}()
	}
	wait.Wait()
	close(retained)
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	orders := make([]uint64, 0, writers)
	for fact := range retained {
		orders = append(orders, fact.OperationOrder)
	}
	sort.Slice(orders, func(i, j int) bool { return orders[i] < orders[j] })
	for index := 1; index < len(orders); index++ {
		if orders[index] <= orders[index-1] {
			t.Fatalf("journal order is not strictly monotonic: %v", orders)
		}
	}
	first, _ := journal.NewFact(prefix+"-0", "workspace", "project", journal.FactCreate, []byte("request-0"), []byte("response-0"))
	replay, err := store.Append(ctx, first)
	if err != nil || replay.OperationOrder == 0 || !containsOrder(orders, replay.OperationOrder) {
		t.Fatalf("identical replay order=%d err=%v", replay.OperationOrder, err)
	}
	conflict, _ := journal.NewFact(prefix+"-0", "workspace", "project", journal.FactCreate, []byte("different"), []byte("response-0"))
	if _, err := store.Append(ctx, conflict); err == nil {
		t.Fatal("different journal bytes reused one fact identity")
	}
	if _, err := pool.Exec(ctx, `DELETE FROM agent_receipts.facts WHERE fact_id LIKE $1`, prefix+"-%"); err != nil {
		t.Fatal(err)
	}
}

func containsOrder(values []uint64, candidate uint64) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}
