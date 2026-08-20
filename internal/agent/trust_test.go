package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeTrustMaterial lays the operator-distributed documents on disk the way a
// deployment does, so the gate reads exactly what it would read in service.
func writeTrustMaterial(t *testing.T, root, statement []byte) (string, string) {
	t.Helper()
	directory := t.TempDir()
	rootPath := filepath.Join(directory, "trust-root.json")
	statementPath := filepath.Join(directory, "catalog-statement.json")
	if err := os.WriteFile(rootPath, root, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statementPath, statement, 0o600); err != nil {
		t.Fatal(err)
	}
	return rootPath, statementPath
}

// Verifying once at startup proves only that the material was valid then. The
// gate re-reads and re-verifies on every check, so material that expires or is
// revoked while the process runs stops work from that moment on.
func TestCatalogTrustFailsClosedWhenMaterialExpiresOrIsRevokedAfterStartup(t *testing.T) {
	key, public := syntheticSigner(t)
	digest := DocumentDigest([]byte("approved-catalog"))
	startup := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	expiry := startup.Add(time.Hour)
	root := trustRootDocument(t, public, "key-1", "active", expiry)
	statement := statementEnvelope(t, key, "key-1", digest, CatalogMediaType, expiry)
	rootPath, statementPath := writeTrustMaterial(t, root, statement)

	gate, err := NewCatalogTrust(rootPath, statementPath, digest)
	if err != nil {
		t.Fatal(err)
	}
	if err := gate.Verify(startup); err != nil {
		t.Fatalf("valid trust material was refused at startup: %v", err)
	}

	t.Run("the trust root passes its freshness bound while the process runs", func(t *testing.T) {
		if err := gate.Verify(expiry.Add(2 * time.Hour)); err == nil {
			t.Fatal("stale trust material was accepted after startup")
		}
		if gate.LastError() == nil {
			t.Fatal("the gate reported no reason for refusing")
		}
		if err := gate.Verify(startup); err != nil {
			t.Fatalf("the gate did not recover once time was inside the bound again: %v", err)
		}
	})

	t.Run("the signing key is revoked while the process runs", func(t *testing.T) {
		revoked := trustRootDocument(t, public, "key-1", "revoked", expiry)
		if err := os.WriteFile(rootPath, revoked, 0o600); err != nil {
			t.Fatal(err)
		}
		err := gate.Verify(startup)
		if err == nil {
			t.Fatal("a revoked signing key was accepted after startup")
		}
		if !strings.Contains(err.Error(), "not usable") {
			t.Fatalf("error = %v, want the revoked key named", err)
		}
		if err := os.WriteFile(rootPath, root, 0o600); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("the statement leaves its validity interval", func(t *testing.T) {
		// Past the statement's validity end by more than the trust root's
		// declared clock skew, so the expiry is unambiguous.
		expired := statementEnvelope(t, key, "key-1", digest, CatalogMediaType, startup.Add(-10*time.Minute))
		if err := os.WriteFile(statementPath, expired, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := gate.Verify(startup); err == nil {
			t.Fatal("an expired statement was accepted after startup")
		}
		if err := os.WriteFile(statementPath, statement, 0o600); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("the statement stops binding the loaded catalog", func(t *testing.T) {
		other := statementEnvelope(t, key, "key-1", DocumentDigest([]byte("another-catalog")), CatalogMediaType, expiry)
		if err := os.WriteFile(statementPath, other, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := gate.Verify(startup); err == nil {
			t.Fatal("a statement binding another catalog was accepted")
		}
		if err := os.WriteFile(statementPath, statement, 0o600); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("the trust material becomes unreadable", func(t *testing.T) {
		if err := os.Remove(rootPath); err != nil {
			t.Fatal(err)
		}
		if err := gate.Verify(startup); err == nil {
			t.Fatal("missing trust material was accepted")
		}
		if err := os.WriteFile(rootPath, root, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := gate.Verify(startup); err != nil {
			t.Fatalf("restored trust material was refused: %v", err)
		}
	})
}

// A gate cannot be built from half the material or against a malformed
// catalog identity: an unattested catalog is never treated as attested.
func TestCatalogTrustRequiresCompleteMaterial(t *testing.T) {
	if _, err := NewCatalogTrust("", "statement.json", DocumentDigest([]byte("catalog"))); err == nil {
		t.Fatal("a gate was built without a trust root")
	}
	if _, err := NewCatalogTrust("root.json", "", DocumentDigest([]byte("catalog"))); err == nil {
		t.Fatal("a gate was built without a signature statement")
	}
	if _, err := NewCatalogTrust("root.json", "statement.json", "not-a-digest"); err == nil {
		t.Fatal("a gate was built against a malformed catalog identity")
	}
}
