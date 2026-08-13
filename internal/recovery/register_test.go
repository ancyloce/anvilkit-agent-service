package recovery

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPlatformMigrationsExcludeAuthoritativeRegister(t *testing.T) {
	entries, err := os.ReadDir("../persistence/migrations")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		body, err := os.ReadFile("../persistence/migrations/" + entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		lower := strings.ToLower(string(body))
		if strings.Contains(lower, "create table") && strings.Contains(lower, "recovery_register") {
			t.Fatalf("authoritative register stored in Platform migration %s", entry.Name())
		}
	}
}

func TestConditionalIncrementLinearizableConformance(t *testing.T) {
	register, _ := NewMemoryRegister(7)
	const writers = 64
	var wait sync.WaitGroup
	errorsByWriter := make(chan error, writers)
	for writer := 0; writer < writers; writer++ {
		wait.Add(1)
		go func(writer int) {
			defer wait.Done()
			for {
				current, err := register.Current(context.Background())
				if err != nil {
					errorsByWriter <- err
					return
				}
				_, err = register.Increment(context.Background(), current, IncrementEvidence{Actor: "operator", Workload: "restore", Reason: "PITR", Ticket: fmt.Sprintf("INC-%d", writer), Traceparent: "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01", At: time.Unix(700, 0)})
				if err == nil {
					return
				}
			}
		}(writer)
	}
	wait.Wait()
	close(errorsByWriter)
	for err := range errorsByWriter {
		t.Error(err)
	}
	current, err := register.Current(context.Background())
	if err != nil || current != 7+writers || register.IncrementCount() != writers {
		t.Fatalf("epoch=%d increments=%d err=%v", current, register.IncrementCount(), err)
	}
}

func TestRegisterUnavailableFailsClosed(t *testing.T) {
	register, _ := NewMemoryRegister(1)
	register.SetUnavailable(true)
	if _, err := register.Current(context.Background()); err == nil {
		t.Fatal("unavailable register returned an epoch")
	}
	if _, err := register.Increment(context.Background(), 1, IncrementEvidence{}); err == nil {
		t.Fatal("unavailable register incremented")
	}
}
