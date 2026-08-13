package auth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestFileRegistryReloadsRevocationState(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "trust.json")
	write := func(status string) {
		t.Helper()
		raw := []byte(fmt.Sprintf(`{"keys":{"key-1":{"publicKey":%q,"status":%q}},"subjects":{"workload":"active"},"delegations":{}}`, base64.RawURLEncoding.EncodeToString(public), status))
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("active")
	registry, err := NewFileRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	active, err := registry.KeyActive(context.Background(), "key-1")
	if err != nil || !active {
		t.Fatalf("active key rejected: active=%v err=%v", active, err)
	}
	write("revoked")
	active, err = registry.KeyActive(context.Background(), "key-1")
	if err != nil || active {
		t.Fatalf("revocation was not reloaded: active=%v err=%v", active, err)
	}
}
