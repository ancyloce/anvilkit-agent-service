package applyauth

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// Domain-separation prefixes keep the published key identity underivable from
// the signing seed and vice versa: both are hashes of the operator material,
// but under different domains.
const (
	seedDomain  = "anvilkit:apply-authorization:signing-seed:"
	keyIDDomain = "anvilkit:apply-authorization:key-id:"
)

// SeededKeyID derives the stable key identity for operator-supplied signing
// material. The identity follows the material: rotated material is a new key.
func SeededKeyID(material []byte) string {
	digest := sha256.Sum256(append([]byte(keyIDDomain), material...))
	return "urn:anvilkit:key:" + hex.EncodeToString(digest[:16])
}

// NewSeededKeyRing derives a deterministic Ed25519 signing key from
// operator-supplied secret material, so issuance survives process restarts
// with a stable key identity and verifiable signatures. The material itself is
// never stored; only the derived private key lives in process memory, and the
// SigningPort never exposes it. Production key custody (KMS/HSM) remains a
// separate ADR-016 decision; this keyring is the kernel's operator-secret
// signing implementation.
func NewSeededKeyRing(material []byte) (*MemoryKeyRing, error) {
	if len(material) < 16 {
		return nil, fmt.Errorf("signing material must be at least 16 bytes")
	}
	keyID := SeededKeyID(material)
	if !validKeyID(keyID) {
		return nil, fmt.Errorf("derived key ID is invalid")
	}
	seed := sha256.Sum256(append([]byte(seedDomain), material...))
	private := ed25519.NewKeyFromSeed(seed[:])
	return &MemoryKeyRing{active: keyID, private: map[string]ed25519.PrivateKey{keyID: private}, revoked: map[string]bool{}}, nil
}
