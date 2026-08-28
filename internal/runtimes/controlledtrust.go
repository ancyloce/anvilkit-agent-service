package runtimes

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/eligibility"
	"github.com/ancyloce/anvilkit-agent-service/internal/trust"
)

// controlledTrustWindow is how long a synthesized trust document declares
// itself fresh for. It is short and rolling: the document is regenerated on
// every read, so the window only has to outlive one verification.
const controlledTrustWindow = time.Hour

// ControlledSigningTrust is the result-signing trust store for a deployment
// whose runtime runs inside this process.
//
// It exists because the verifier is not optional. A controlled composition
// still has to prove a result was signed by the thing that produced it, and the
// thing that produced it is the in-process stand-in — so the material naming
// its key is synthesized from the same key the stand-in signs with, rather than
// the verification being skipped where there is no operator document.
//
// It declares itself controlled, which is how production refuses it whatever it
// is configured as: a deployment that synthesized its own runtime trust would be
// certifying its own results.
type ControlledSigningTrust struct {
	document []byte
	now      func() time.Time
}

// NewControlledSigningTrust synthesizes the trust store for one in-process
// signer over the approved releases it stands in for.
func NewControlledSigningTrust(public ed25519.PublicKey, keyID string, releases []Release, now func() time.Time) (*ControlledSigningTrust, error) {
	if len(public) != ed25519.PublicKeySize || keyID == "" || now == nil {
		return nil, fmt.Errorf("controlled signing trust: a public key, its identity, and a clock are all required")
	}
	if len(releases) == 0 {
		return nil, fmt.Errorf("controlled signing trust: there are no approved releases to stand in for")
	}
	units := make([]string, 0, len(releases))
	audiences := make([]string, 0, len(releases))
	manifests := make([]string, 0, len(releases))
	for _, release := range releases {
		units = append(units, release.RuntimeUnitID)
		audiences = append(audiences, release.Binding.RuntimeAudience)
		manifests = append(manifests, release.ManifestDigest)
	}
	key := SigningKey{
		KeyID:          keyID,
		RuntimeUnitIDs: deduplicate(units),
		Audiences:      deduplicate(audiences),
		Algorithm:      ResultSignatureAlgorithm,
		Status:         "active",
		// The stand-in's provenance is the released manifest it is standing in
		// for — there is no image, so there is no image attestation to name.
		// The scope is therefore the same set on both axes, which is honest
		// about what an in-process runtime can attest to.
		RuntimeManifestDigests: deduplicate(manifests),
		ProvenanceDigests:      deduplicate(manifests),
	}
	key.PublicKeyJwk.KeyType = "OKP"
	key.PublicKeyJwk.Curve = "Ed25519"
	key.PublicKeyJwk.X = base64.RawURLEncoding.EncodeToString(public)
	document, err := json.Marshal(SigningTrustStore{
		Kind:                    SigningTrustKind,
		SnapshotID:              "controlled-runtime-signing-trust",
		MaximumClockSkewSeconds: 0,
		Keys:                    []SigningKey{key},
	})
	if err != nil {
		return nil, fmt.Errorf("controlled signing trust: encode trust store: %w", err)
	}
	return &ControlledSigningTrust{document: document, now: now}, nil
}

// Eligibility declares this source controlled. See the type's documentation for
// why a synthesized trust store must never reach production.
func (*ControlledSigningTrust) Eligibility() eligibility.Eligibility {
	return eligibility.ControlledOnly
}

// SigningTrust stamps the validity window onto the synthesized document. The
// timestamps are filled in per read so the store is always fresh for the
// verification it is being read for and never fresh for longer.
func (c *ControlledSigningTrust) SigningTrust() ([]byte, error) {
	return stampValidity(c.document, c.now().UTC())
}

// ControlledCredentialTrust is the task-credential trust root for a deployment
// that issues and admits credentials in the same process.
//
// A released unit is handed the operator's trust root; the in-process stand-in
// is handed this, built from the issuer's own public key. The point is that the
// stand-in still verifies rather than reading claims it was handed directly: an
// admission path that trusted the caller in the controlled composition would be
// a different admission path from the one production runs.
type ControlledCredentialTrust struct {
	document []byte
	now      func() time.Time
}

// NewControlledCredentialTrust synthesizes the credential trust root for one
// in-process issuer over the audiences it may mint for.
func NewControlledCredentialTrust(public ed25519.PublicKey, keyID string, audiences []string, now func() time.Time) (*ControlledCredentialTrust, error) {
	if len(public) != ed25519.PublicKeySize || keyID == "" || now == nil {
		return nil, fmt.Errorf("controlled credential trust: a public key, its identity, and a clock are all required")
	}
	if len(audiences) == 0 {
		return nil, fmt.Errorf("controlled credential trust: there are no audiences to mint credentials for")
	}
	key := trust.Key{
		KeyID:      keyID,
		Issuer:     CredentialIssuer,
		Audiences:  deduplicate(audiences),
		Algorithms: []string{CredentialAlgorithm},
		Status:     "active",
	}
	key.PublicKeyJwk.KeyType = "OKP"
	key.PublicKeyJwk.Curve = "Ed25519"
	key.PublicKeyJwk.X = base64.RawURLEncoding.EncodeToString(public)
	document, err := json.Marshal(trust.Root{
		Kind:                    trust.RootKind,
		SnapshotID:              "controlled-task-credential-trust",
		MaximumClockSkewSeconds: 0,
		Keys:                    []trust.Key{key},
	})
	if err != nil {
		return nil, fmt.Errorf("controlled credential trust: encode trust root: %w", err)
	}
	return &ControlledCredentialTrust{document: document, now: now}, nil
}

// Eligibility declares this source controlled.
func (*ControlledCredentialTrust) Eligibility() eligibility.Eligibility {
	return eligibility.ControlledOnly
}

// Root stamps the validity window onto the synthesized trust root.
func (c *ControlledCredentialTrust) Root() ([]byte, error) {
	return stampValidity(c.document, c.now().UTC())
}

// stampValidity fills in the issue, freshness, and key validity timestamps of a
// synthesized trust document at the instant it is read. Doing it here rather
// than at construction is what keeps a long-running controlled process from
// holding a document that has silently gone stale.
func stampValidity(document []byte, now time.Time) ([]byte, error) {
	var stamped map[string]any
	if err := json.Unmarshal(document, &stamped); err != nil {
		return nil, fmt.Errorf("controlled trust: decode synthesized document: %w", err)
	}
	issued := now.Add(-controlledTrustWindow).Format(trust.Timestamp)
	expires := now.Add(controlledTrustWindow).Format(trust.Timestamp)
	stamped["issuedAt"] = issued
	stamped["nextUpdate"] = expires
	keys, _ := stamped["keys"].([]any)
	for _, entry := range keys {
		key, ok := entry.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("controlled trust: the synthesized document is malformed")
		}
		key["notBefore"] = issued
		key["notAfter"] = expires
	}
	raw, err := json.Marshal(stamped)
	if err != nil {
		return nil, fmt.Errorf("controlled trust: encode synthesized document: %w", err)
	}
	return raw, nil
}

func deduplicate(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	unique := make([]string, 0, len(values))
	for _, value := range values {
		if _, duplicate := seen[value]; duplicate {
			continue
		}
		seen[value] = struct{}{}
		unique = append(unique, value)
	}
	sort.Strings(unique)
	return unique
}
