package main

import (
	"os"
	"path/filepath"
	"testing"

	contractguard "github.com/ancyloce/anvilkit-agent-service/internal/contracts"
)

func TestRunAuthorityFileIsStrictAndContractValid(t *testing.T) {
	guard, err := contractguard.NewGuard("../..")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "authority.json")
	policy := `{"policyId":"policy.synthetic","version":"v1","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`
	raw := `{"contractBomReference":{"repository":"anvilkit/contracts","bomDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","ociManifestDigest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","evidenceManifestDigest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},"policy":` + policy + `,"budget":{"apiVersion":"anvilkit.io/contracts/v1","kind":"AgentBudget","modelLimits":{"maximumCalls":10,"maximumConcurrentCalls":2},"tokenLimits":{"inputTokens":4096,"outputTokens":2048,"totalTokens":6144},"workerLimits":{"maximumAttempts":4,"maximumDurationMilliseconds":60000},"gpuLimits":{"maximumGpuMilliseconds":0},"currencyLimits":{"maximumCost":{"amount":"1000","currency":"USD"},"reservedCost":{"amount":"500","currency":"USD"}},"reservationId":"reservation.synthetic.001","exceedBehavior":"refuse","policy":` + policy + `}}`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadRunAuthority(path, guard); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(raw[:len(raw)-1]+`,"actorId":"attacker"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadRunAuthority(path, guard); err == nil {
		t.Fatal("unknown server-authority field was accepted")
	}
}
