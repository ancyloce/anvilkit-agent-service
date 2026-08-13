package idempotency

import (
	"testing"
	"time"
)

func TestRetentionMustCoverGovernedLifetime(t *testing.T) {
	if _, err := New(nil, Config{Retention: time.Hour, MinimumLifetime: 24 * time.Hour}); err == nil {
		t.Fatal("short retention accepted")
	}
	if _, err := New(nil, Config{Retention: 24 * time.Hour, MinimumLifetime: 24 * time.Hour}); err != nil {
		t.Fatal(err)
	}
}
