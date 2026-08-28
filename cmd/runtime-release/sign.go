package main

// sign.go holds the signing side of a release cut: the authorities that seal
// catalog statements and image signatures, and the trust root that lets a
// verifier resolve them. The service side only ever verifies; sealing lives
// here, in the release tool, which is the one place allowed to hold a signing
// seed.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/agent"
	"github.com/ancyloce/anvilkit-agent-service/internal/trust"
)

const (
	// catalogAlgorithm is the algorithm label both catalog attestations use.
	catalogAlgorithm = "dsse-ed25519-v1"
	// definitionStatementKind mirrors the kind internal/agent verifies.
	definitionStatementKind = "AgentDefinitionCatalogStatement"
	// The definition catalog statement identifiers are the ones internal/agent
	// accepts; sealing with anything else would produce an attestation the
	// service refuses.
	definitionCatalogStatementType = agent.CatalogStatementType
	definitionCatalogMediaType     = agent.CatalogMediaType

	// imageSignaturePayloadType and imageSignatureStatementKind identify the
	// statement a release seals over one built image digest. The digest of the
	// sealed envelope is what a runtime manifest records as its image
	// signature reference.
	imageSignaturePayloadType   = "application/vnd.anvilkit.agent-runtime-image-signature-statement+json"
	imageSignatureStatementKind = "AgentRuntimeImageSignatureStatement"
	// ociImageManifestMediaType is the media type an image digest names.
	ociImageManifestMediaType = "application/vnd.oci.image.manifest.v1+json"

	releaseIssuer    = "urn:anvilkit:issuer:agent-runtime-releases"
	definitionIssuer = "urn:anvilkit:issuer:agent-definitions"

	releaseKeyID    = "urn:anvilkit:key:agent-runtime-release-signing"
	definitionKeyID = "urn:anvilkit:key:agent-definition-catalog-signing"

	trustClockSkewSeconds = 60
)

// signingAuthority is one seed-backed Ed25519 signer with its governed
// identity. The abstraction the service trusts is (keyId, issuer, audience);
// a KMS-backed implementation replaces only how seal is computed.
type signingAuthority struct {
	key    ed25519.PrivateKey
	keyID  string
	issuer string
}

// authorityFromSeedFile reads a base64url Ed25519 seed, the same encoding the
// runtime units use for their result-signing seeds.
func authorityFromSeedFile(path, keyID, issuer string) (signingAuthority, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return signingAuthority{}, fmt.Errorf("read signing seed: %w", err)
	}
	seed, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return signingAuthority{}, fmt.Errorf("signing seed must be a base64url Ed25519 seed")
	}
	return signingAuthority{key: ed25519.NewKeyFromSeed(seed), keyID: keyID, issuer: issuer}, nil
}

// ephemeralAuthority generates a fresh keypair. It exists for pipeline
// verification: a build proves the cut-sign-verify path end to end without
// ever holding a production key.
func ephemeralAuthority(keyID, issuer string) (signingAuthority, []byte, error) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return signingAuthority{}, nil, fmt.Errorf("generate ephemeral seed: %w", err)
	}
	encoded := []byte(base64.RawURLEncoding.EncodeToString(seed))
	return signingAuthority{key: ed25519.NewKeyFromSeed(seed), keyID: keyID, issuer: issuer}, encoded, nil
}

// sealStatement builds and seals one signed statement binding a subject
// digest, returning the envelope bytes a verifier reads.
func (a signingAuthority) sealStatement(kind, payloadType, mediaType, audience, subjectDigest string, now time.Time, validity time.Duration) ([]byte, error) {
	statement := trust.Statement{
		Kind:      kind,
		Algorithm: catalogAlgorithm,
		Issuer:    a.issuer,
		Audience:  audience,
		KeyID:     a.keyID,
		IssuedAt:  now.UTC().Format(trust.Timestamp),
		NotBefore: now.UTC().Format(trust.Timestamp),
		ExpiresAt: now.UTC().Add(validity).Format(trust.Timestamp),
	}
	statement.Subject.Digest = subjectDigest
	statement.Subject.MediaType = mediaType
	payload, err := json.Marshal(statement)
	if err != nil {
		return nil, fmt.Errorf("encode statement: %w", err)
	}
	envelope, err := trust.Seal(a.key, a.keyID, payloadType, payload)
	if err != nil {
		return nil, fmt.Errorf("seal statement: %w", err)
	}
	encoded, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode envelope: %w", err)
	}
	return append(encoded, '\n'), nil
}

// trustRootDocument publishes the verification keys for the given authorities
// in the shared operator trust-root format.
func trustRootDocument(authorities []signingAuthority, audience string, now time.Time, validity time.Duration) ([]byte, error) {
	root := trust.Root{
		Kind:                    trust.RootKind,
		SnapshotID:              "runtime-release-" + now.UTC().Format("20060102T150405Z"),
		IssuedAt:                now.UTC().Format(trust.Timestamp),
		NextUpdate:              now.UTC().Add(validity).Format(trust.Timestamp),
		MaximumClockSkewSeconds: trustClockSkewSeconds,
	}
	for _, authority := range authorities {
		key := trust.Key{
			KeyID:      authority.keyID,
			Issuer:     authority.issuer,
			Audiences:  []string{audience},
			Algorithms: []string{catalogAlgorithm},
			Status:     "active",
			NotBefore:  now.UTC().Format(trust.Timestamp),
			NotAfter:   now.UTC().Add(validity).Format(trust.Timestamp),
		}
		key.PublicKeyJwk.KeyType = "OKP"
		key.PublicKeyJwk.Curve = "Ed25519"
		key.PublicKeyJwk.X = base64.RawURLEncoding.EncodeToString(authority.key.Public().(ed25519.PublicKey))
		root.Keys = append(root.Keys, key)
	}
	encoded, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode trust root: %w", err)
	}
	return append(encoded, '\n'), nil
}
