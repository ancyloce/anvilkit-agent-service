package contracts

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTrustBoundaryCoverageCannotBeSatisfiedByRegistrationAlone(t *testing.T) {
	guard, err := NewGuard("../..")
	if err != nil {
		t.Fatal(err)
	}
	if err := guard.AssertCoverage(); err == nil {
		t.Fatal("empty coverage accepted")
	}
	validEvent := []byte(`{"apiVersion":"anvilkit.io/contracts/v1","kind":"AgentEvent","eventId":"event.synthetic.001","runId":"run.synthetic.001","sequence":1,"eventType":"run.created","occurredAt":"2026-08-09T12:00:00.000Z","traceContext":{"traceparent":"00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"},"payload":{"status":"created"},"contractBomReference":{"repository":"anvilkit/contracts","bomDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","ociManifestDigest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","evidenceManifestDigest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}}`)
	if err := guard.Require(context.Background(), EventIn, "anvilkit://schema/agent-event.v1@1.0.0?digest=sha256:f19775b8dfdd34cac0318fce8067460988671840987a2b9aaeaa3c85710591ab", validEvent); err != nil {
		t.Fatal(err)
	}
	if err := guard.AssertCoverage(); err == nil {
		t.Fatal("one real boundary incorrectly satisfied all-boundary coverage")
	}
}

func TestRequireRejectsBeforeSideEffect(t *testing.T) {
	guard, err := NewGuard("../..")
	if err != nil {
		t.Fatal(err)
	}
	effected := false
	invalid := []byte(`{"apiVersion":"wrong"}`)
	if err := guard.Require(context.Background(), EventIn, "anvilkit://schema/agent-event.v1@1.0.0?digest=sha256:f19775b8dfdd34cac0318fce8067460988671840987a2b9aaeaa3c85710591ab", invalid); err == nil {
		effected = true
	}
	if effected {
		t.Fatal("invalid boundary payload reached side effect")
	}
}

func TestUnknownTrustBoundaryFailsClosed(t *testing.T) {
	guard, err := NewGuard("../..")
	if err != nil {
		t.Fatal(err)
	}
	findings := guard.Validate(context.Background(), Boundary("invented"), "missing", []byte(`{}`))
	if len(findings) != 1 || findings[0].Code != "VALIDATION_BOUNDARY_UNKNOWN" {
		t.Fatalf("unexpected findings %#v", findings)
	}
}

func TestPinnedMaterialIntegrity(t *testing.T) {
	if err := VerifyPinnedMaterial("../..", false); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPinnedMaterial("../..", true); err == nil || !strings.Contains(err.Error(), "published") {
		t.Fatalf("unpublished material was accepted for production: %v", err)
	}
}

func TestPinnedMaterialRejectsSchemaTampering(t *testing.T) {
	repositoryRoot := copyContractMaterial(t)
	path := filepath.Join(repositoryRoot, "contracts", "schemas", "v1", "agent-run.schema.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(raw, ' '), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPinnedMaterial(repositoryRoot, false); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("tampered schema was accepted: %v", err)
	}
}

func TestPinnedMaterialRejectsBOMTampering(t *testing.T) {
	repositoryRoot := copyContractMaterial(t)
	path := filepath.Join(repositoryRoot, "contracts", "bom", "release-bom.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(raw), `"version": "1.0.0"`, `"version": "1.0.1"`, 1)
	if err := os.WriteFile(path, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPinnedMaterial(repositoryRoot, false); err == nil || !strings.Contains(err.Error(), "identity") {
		t.Fatalf("tampered BOM was accepted: %v", err)
	}
}

func copyContractMaterial(t *testing.T) string {
	t.Helper()
	repositoryRoot := t.TempDir()
	if err := os.CopyFS(filepath.Join(repositoryRoot, "contracts"), os.DirFS(filepath.Join("..", "..", "contracts"))); err != nil {
		t.Fatal(err)
	}
	return repositoryRoot
}
