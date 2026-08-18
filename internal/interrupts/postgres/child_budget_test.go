package postgres

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/interrupts"
	"github.com/ancyloce/anvilkit-agent-service/internal/runs"
)

func TestCurrencyMicrosIsExactAndOverflowSafe(t *testing.T) {
	tests := map[string]int64{
		"0":         0,
		"1":         1_000_000,
		"12.34":     12_340_000,
		"0.000001":  1,
		"1.0000000": 1_000_000,
	}
	for input, want := range tests {
		got, err := currencyMicros(input)
		if err != nil || got != want {
			t.Errorf("currencyMicros(%q) = %d, %v; want %d", input, got, err, want)
		}
	}
	for _, input := range []string{"", "-1", "+1", "1.", ".1", "0.0000001", "9223372036854775807"} {
		if _, err := currencyMicros(input); err == nil {
			t.Errorf("currencyMicros(%q) accepted invalid or inexact cost", input)
		}
	}
}

func TestDecodeRootBudgetRejectsPartialOrUnknownAuthority(t *testing.T) {
	valid := json.RawMessage(`{"apiVersion":"anvilkit.io/contracts/v1","kind":"AgentBudget","modelLimits":{},"tokenLimits":{},"workerLimits":{},"gpuLimits":{},"currencyLimits":{"maximumCost":{"amount":"1","currency":"USD"},"reservedCost":{"amount":"0","currency":"USD"}},"reservationId":"root-reservation","exceedBehavior":"refuse","policy":{"policyId":"policy","version":"v1","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}`)
	if _, err := decodeRootBudget(valid); err != nil {
		t.Fatal(err)
	}
	unknown := append(append([]byte(nil), valid[:len(valid)-1]...), []byte(`,"forged":true}`)...)
	if _, err := decodeRootBudget(unknown); err == nil {
		t.Fatal("unknown root budget authority was accepted")
	}
	if _, err := decodeRootBudget(json.RawMessage(`{"apiVersion":"anvilkit.io/contracts/v1","kind":"AgentBudget"}`)); err == nil {
		t.Fatal("partial root budget authority was accepted")
	}
}

func TestChildReservationIdentityIsStableAcrossGeneratedChildIDs(t *testing.T) {
	base := interrupts.ChildBudgetRequest{Write: interrupts.Write{Scope: runs.Scope{TenantID: "tenant", WorkspaceID: "workspace", ProjectID: "project", ActorID: "actor"}, RunID: "parent", IdempotencyKey: "spawn"}, ChildRunID: "child-1", Mode: interrupts.ChildRequired, Digest: "sha256:" + strings.Repeat("a", 64), RequestedAt: time.Now()}
	first := childReservationID(base)
	base.ChildRunID = "child-2"
	base.Digest = "sha256:" + strings.Repeat("b", 64)
	if second := childReservationID(base); first != second {
		t.Fatalf("idempotent retry changed reservation identity: %s != %s", first, second)
	}
	base.Write.IdempotencyKey = "other-spawn"
	if other := childReservationID(base); first == other {
		t.Fatal("different child operation reused reservation identity")
	}
}
