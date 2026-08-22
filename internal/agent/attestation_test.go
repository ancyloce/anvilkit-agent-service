package agent

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"github.com/ancyloce/anvilkit-agent-service/internal/trust"
	"strings"
	"testing"
	"time"
)

// syntheticSigner is a test-only key. The repository ships no signing key:
// the trust root a deployment verifies against is distributed to it, never
// committed beside the material it authenticates.
func syntheticSigner(t *testing.T) (ed25519.PrivateKey, string) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index + 1)
	}
	key := ed25519.NewKeyFromSeed(seed)
	public := key.Public().(ed25519.PublicKey)
	return key, base64.RawURLEncoding.EncodeToString(public)
}

func trustRootDocument(t *testing.T, publicKey, keyID, status string, notAfter time.Time) []byte {
	t.Helper()
	root := TrustRoot{
		Kind:                    "ContractTrustRoot",
		SnapshotID:              "trust-snapshot-verification",
		IssuedAt:                "2026-08-01T00:00:00.000Z",
		NextUpdate:              notAfter.UTC().Format(timestampLayout),
		MaximumClockSkewSeconds: 60,
	}
	key := TrustRootKey{
		KeyID:      keyID,
		Issuer:     "urn:anvilkit:issuer:agent-definitions",
		Audiences:  []string{CatalogAudience},
		Algorithms: []string{catalogAlgorithm},
		Status:     status,
		NotBefore:  "2026-08-01T00:00:00.000Z",
		NotAfter:   notAfter.UTC().Format(timestampLayout),
	}
	key.PublicKeyJwk.KeyType, key.PublicKeyJwk.Curve, key.PublicKeyJwk.X = "OKP", "Ed25519", publicKey
	root.Keys = []TrustRootKey{key}
	raw, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func statementEnvelope(t *testing.T, key ed25519.PrivateKey, keyID, digest, mediaType string, expires time.Time) []byte {
	t.Helper()
	statement := CatalogStatement{
		Kind:      "AgentDefinitionCatalogStatement",
		Algorithm: catalogAlgorithm,
		Issuer:    "urn:anvilkit:issuer:agent-definitions",
		Audience:  CatalogAudience,
		KeyID:     keyID,
		IssuedAt:  "2026-08-01T00:00:00.000Z",
		NotBefore: "2026-08-01T00:00:00.000Z",
		ExpiresAt: expires.UTC().Format(timestampLayout),
	}
	statement.Subject.Digest, statement.Subject.MediaType = digest, mediaType
	payload, err := json.Marshal(statement)
	if err != nil {
		t.Fatal(err)
	}
	envelope := Envelope{
		PayloadType: CatalogStatementType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures:  []trust.Signature{{KeyID: keyID, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, trust.EncodePAE(CatalogStatementType, payload)))}},
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestCatalogAttestationVerifiesAndFailsClosed(t *testing.T) {
	signer, publicKey := syntheticSigner(t)
	const keyID = "urn:anvilkit:key:agent-definitions:verification"
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	fresh := now.Add(24 * time.Hour)
	digest := "sha256:" + strings.Repeat("a", 64)

	root := trustRootDocument(t, publicKey, keyID, "active", fresh)
	statement := statementEnvelope(t, signer, keyID, digest, CatalogMediaType, fresh)
	if err := VerifyCatalogAttestation(root, statement, digest, now); err != nil {
		t.Fatalf("a valid attestation was rejected: %v", err)
	}

	t.Run("wrong catalog digest", func(t *testing.T) {
		other := "sha256:" + strings.Repeat("b", 64)
		if err := VerifyCatalogAttestation(root, statement, other, now); err == nil {
			t.Fatal("a statement binding a different catalog was accepted")
		}
	})
	t.Run("tampered payload", func(t *testing.T) {
		forged := statementEnvelope(t, signer, keyID, digest, CatalogMediaType, fresh)
		var envelope Envelope
		if err := json.Unmarshal(forged, &envelope); err != nil {
			t.Fatal(err)
		}
		payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
		if err != nil {
			t.Fatal(err)
		}
		envelope.Payload = base64.StdEncoding.EncodeToString([]byte(strings.Replace(string(payload), strings.Repeat("a", 64), strings.Repeat("c", 64), 1)))
		raw, err := json.Marshal(envelope)
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyCatalogAttestation(root, raw, digest, now); err == nil {
			t.Fatal("a tampered statement was accepted")
		}
	})
	t.Run("unknown key", func(t *testing.T) {
		if err := VerifyCatalogAttestation(trustRootDocument(t, publicKey, "urn:anvilkit:key:agent-definitions:other", "active", fresh), statement, digest, now); err == nil {
			t.Fatal("a statement signed by a key outside the trust root was accepted")
		}
	})
	t.Run("revoked key", func(t *testing.T) {
		if err := VerifyCatalogAttestation(trustRootDocument(t, publicKey, keyID, "revoked", fresh), statement, digest, now); err == nil {
			t.Fatal("a revoked key was accepted")
		}
	})
	t.Run("foreign signature", func(t *testing.T) {
		otherSeed := make([]byte, ed25519.SeedSize)
		for index := range otherSeed {
			otherSeed[index] = byte(200 - index)
		}
		other := ed25519.NewKeyFromSeed(otherSeed)
		if err := VerifyCatalogAttestation(root, statementEnvelope(t, other, keyID, digest, CatalogMediaType, fresh), digest, now); err == nil {
			t.Fatal("a signature from an unrelated key was accepted")
		}
	})
	t.Run("expired statement", func(t *testing.T) {
		expired := statementEnvelope(t, signer, keyID, digest, CatalogMediaType, now.Add(-time.Hour))
		if err := VerifyCatalogAttestation(root, expired, digest, now); err == nil {
			t.Fatal("an expired statement was accepted")
		}
	})
	t.Run("stale trust root", func(t *testing.T) {
		stale := trustRootDocument(t, publicKey, keyID, "active", now.Add(-time.Hour))
		if err := VerifyCatalogAttestation(stale, statement, digest, now); err == nil {
			t.Fatal("a trust root past its freshness bound was accepted")
		}
	})
	t.Run("wrong subject media type", func(t *testing.T) {
		wrong := statementEnvelope(t, signer, keyID, digest, "application/json", fresh)
		if err := VerifyCatalogAttestation(root, wrong, digest, now); err == nil {
			t.Fatal("a statement about a different kind of subject was accepted")
		}
	})
}

// The embedded catalog is the identity an attestation signs, so its digest
// must be exactly the digest of the bytes the registry loaded.
func TestRegistryExposesTheDigestOfTheCatalogItLoaded(t *testing.T) {
	registry := newTestRegistry(t)
	raw, err := EmbeddedCatalog{}.Catalog(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if registry.CatalogDigest() != DocumentDigest(raw) {
		t.Fatalf("catalog digest = %s, want %s", registry.CatalogDigest(), DocumentDigest(raw))
	}
}
