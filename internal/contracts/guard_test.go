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
	validEvent := []byte(`{"kind":"AgentEvent","eventId":"event.synthetic.001","runId":"run.synthetic.001","workspaceId":"workspace.synthetic.001","projectId":"project.synthetic.001","sequence":1,"eventType":"run.created","occurredAt":"2026-08-09T12:00:00.000Z","subject":{"subjectType":"system","subjectId":"agent-service"},"traceContext":{"traceparent":"00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"},"payload":{"status":"created"},"contractBomReference":{"repository":"anvilkit/contracts","bomDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","ociManifestDigest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","evidenceManifestDigest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}}`)
	if err := guard.Require(context.Background(), EventIn, "anvilkit://schema/agent-event?digest=sha256:2fdd8937381427507e721675ebbd66144595a193b53ba460534e9712df9b774a", validEvent); err != nil {
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
	if err := guard.Require(context.Background(), EventIn, "anvilkit://schema/agent-event?digest=sha256:2fdd8937381427507e721675ebbd66144595a193b53ba460534e9712df9b774a", invalid); err == nil {
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
	if err := VerifyPinnedMaterial("../.."); err != nil {
		t.Fatal(err)
	}
}

func TestPinnedMaterialRejectsSchemaTampering(t *testing.T) {
	repositoryRoot := copyContractMaterial(t)
	path := filepath.Join(repositoryRoot, "contracts", "agent", "schemas", "agent-run.schema.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(raw, ' '), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPinnedMaterial(repositoryRoot); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("tampered schema was accepted: %v", err)
	}
}

func TestPinnedMaterialRejectsLockTampering(t *testing.T) {
	repositoryRoot := copyContractMaterial(t)
	path := filepath.Join(repositoryRoot, "contracts", "agent", "lock", "contracts.lock.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(raw), `"lockVersion": 1`, `"lockVersion": 2`, 1)
	if err := os.WriteFile(path, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPinnedMaterial(repositoryRoot); err == nil || !strings.Contains(err.Error(), "match") {
		t.Fatalf("tampered lock was accepted: %v", err)
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
