package runtimes

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/contracts/generated/schema"
	"github.com/ancyloce/anvilkit-agent-service/internal/agent"
	"github.com/ancyloce/anvilkit-agent-service/internal/eligibility"
	"github.com/ancyloce/anvilkit-agent-service/internal/trust"
)

// SigningTrustKind is the only document kind accepted as a runtime
// result-signing trust store. It is distinct from every other trust document
// this service reads, so operator material distributed to authenticate
// something else can never be read as an approval of runtime signing keys.
const SigningTrustKind = "AgentRuntimeSigningTrust"

// ResultSignatureAlgorithm is the only algorithm a runtime result signature may
// declare: Ed25519 over the DSSE pre-authentication encoding of the canonical
// statement.
const ResultSignatureAlgorithm = "dsse-ed25519-v1"

// maximumSigningTrustBytes bounds the operator document.
const maximumSigningTrustBytes = 262144

// SigningKey is one runtime result-signing key as the operator approved it.
//
// A key is not merely a public key: it is a public key approved to sign for a
// named set of runtime units and audiences, over a bounded set of released
// manifests and image provenances. That scope is the difference between "this
// signature verifies" and "this signature is authority for the release this run
// pinned".
//
// The identity and audience are sets rather than single values because one
// signer can legitimately stand for several releases — an in-process stand-in
// serving every approved unit is the case that exists today. A real operator
// issues one key per unit and writes a one-element set; nothing here depends on
// which of the two a deployment does, because a result from a unit outside the
// set is refused either way.
type SigningKey struct {
	KeyID          string   `json:"keyId"`
	RuntimeUnitIDs []string `json:"runtimeUnitIds"`
	Audiences      []string `json:"audiences"`
	Algorithm      string   `json:"algorithm"`
	PublicKeyJwk   struct {
		KeyType string `json:"kty"`
		Curve   string `json:"crv"`
		X       string `json:"x"`
	} `json:"publicKeyJwk"`
	// Status is the rotation state: active, overlap during a rotation, or
	// revoked. A revoked key stops verifying immediately, which is the control
	// that makes a leaked runtime key recoverable without a redeploy.
	Status    string `json:"status"`
	NotBefore string `json:"notBefore"`
	NotAfter  string `json:"notAfter"`
	// RuntimeManifestDigests and ProvenanceDigests are the release scope. A key
	// approved for one release may not sign results attributed to another, so a
	// runtime that kept its key across an unapproved rebuild signs results the
	// control plane refuses.
	RuntimeManifestDigests []string `json:"runtimeManifestDigests"`
	ProvenanceDigests      []string `json:"provenanceDigests"`
}

// SigningTrustStore is the operator-distributed map from key identity to the
// runtime identity and release scope that key may sign for.
type SigningTrustStore struct {
	Kind                    string       `json:"kind"`
	SnapshotID              string       `json:"snapshotId"`
	IssuedAt                string       `json:"issuedAt"`
	NextUpdate              string       `json:"nextUpdate"`
	MaximumClockSkewSeconds int          `json:"maximumClockSkewSeconds"`
	Keys                    []SigningKey `json:"keys"`
}

// ParseSigningTrust decodes and freshness-checks one signing trust store.
//
// The freshness bound is the operator's own statement of how long this snapshot
// may be believed. A store past it is refused rather than used with a warning: a
// trust store that outlives its declared life is how a revoked runtime key keeps
// verifying.
func ParseSigningTrust(raw []byte, now time.Time) (SigningTrustStore, time.Duration, error) {
	if len(raw) == 0 || len(raw) > maximumSigningTrustBytes {
		return SigningTrustStore{}, 0, fmt.Errorf("runtime signing trust: the trust store is empty or unbounded")
	}
	var store SigningTrustStore
	if err := trust.DecodeJSON(raw, &store); err != nil {
		return SigningTrustStore{}, 0, fmt.Errorf("runtime signing trust: decode trust store: %w", err)
	}
	if store.Kind != SigningTrustKind || store.SnapshotID == "" || len(store.Keys) == 0 || len(store.Keys) > 32 {
		return SigningTrustStore{}, 0, fmt.Errorf("runtime signing trust: the trust store is incomplete")
	}
	if store.MaximumClockSkewSeconds < 0 || store.MaximumClockSkewSeconds > 300 {
		return SigningTrustStore{}, 0, fmt.Errorf("runtime signing trust: the declared clock skew is outside the accepted bound")
	}
	nextUpdate, err := time.Parse(trust.Timestamp, store.NextUpdate)
	if err != nil {
		return SigningTrustStore{}, 0, fmt.Errorf("runtime signing trust: the freshness bound is malformed")
	}
	skew := time.Duration(store.MaximumClockSkewSeconds) * time.Second
	if now.After(nextUpdate.Add(skew)) {
		return SigningTrustStore{}, 0, fmt.Errorf("runtime signing trust: the trust store is past its declared freshness bound")
	}
	seen := make(map[string]struct{}, len(store.Keys))
	for _, key := range store.Keys {
		if _, duplicate := seen[key.KeyID]; duplicate {
			return SigningTrustStore{}, 0, fmt.Errorf("runtime signing trust: key %s is approved twice", key.KeyID)
		}
		seen[key.KeyID] = struct{}{}
	}
	return store, skew, nil
}

// Resolve answers the approved key for one identity, or refuses.
//
// Every refusal below is a distinct way a signature can verify and still not be
// authority: an unknown key, a revoked one, one outside its validity interval,
// one approved for another algorithm, and one whose material is not an Ed25519
// public key at all.
func (s SigningTrustStore) Resolve(keyID string, now time.Time, skew time.Duration) (SigningKey, ed25519.PublicKey, error) {
	for _, candidate := range s.Keys {
		if candidate.KeyID != keyID {
			continue
		}
		if candidate.Status != "active" && candidate.Status != "overlap" {
			return SigningKey{}, nil, fmt.Errorf("runtime signing trust: the result-signing key is not usable")
		}
		if candidate.Algorithm != ResultSignatureAlgorithm {
			return SigningKey{}, nil, fmt.Errorf("runtime signing trust: the result-signing key is not approved for %s", ResultSignatureAlgorithm)
		}
		notBefore, err := time.Parse(trust.Timestamp, candidate.NotBefore)
		if err != nil {
			return SigningKey{}, nil, fmt.Errorf("runtime signing trust: the key validity start is malformed")
		}
		notAfter, err := time.Parse(trust.Timestamp, candidate.NotAfter)
		if err != nil {
			return SigningKey{}, nil, fmt.Errorf("runtime signing trust: the key validity end is malformed")
		}
		if now.Add(skew).Before(notBefore) || now.After(notAfter.Add(skew)) {
			return SigningKey{}, nil, fmt.Errorf("runtime signing trust: the result-signing key is outside its validity interval")
		}
		if candidate.PublicKeyJwk.KeyType != "OKP" || candidate.PublicKeyJwk.Curve != "Ed25519" {
			return SigningKey{}, nil, fmt.Errorf("runtime signing trust: the result-signing key is not an Ed25519 key")
		}
		material, err := base64.RawURLEncoding.DecodeString(candidate.PublicKeyJwk.X)
		if err != nil || len(material) != ed25519.PublicKeySize {
			return SigningKey{}, nil, fmt.Errorf("runtime signing trust: the result-signing key material is malformed")
		}
		if len(candidate.RuntimeUnitIDs) == 0 || len(candidate.Audiences) == 0 {
			return SigningKey{}, nil, fmt.Errorf("runtime signing trust: the result-signing key names no runtime identity")
		}
		for _, unit := range candidate.RuntimeUnitIDs {
			if !validComponentID(unit) {
				return SigningKey{}, nil, fmt.Errorf("runtime signing trust: the result-signing key names no bounded runtime identity")
			}
		}
		for _, audience := range candidate.Audiences {
			if !validAudience(audience) {
				return SigningKey{}, nil, fmt.Errorf("runtime signing trust: the result-signing key names no governed audience")
			}
		}
		if len(candidate.RuntimeManifestDigests) == 0 || len(candidate.ProvenanceDigests) == 0 {
			return SigningKey{}, nil, fmt.Errorf("runtime signing trust: the result-signing key names no release scope")
		}
		return candidate, ed25519.PublicKey(material), nil
	}
	return SigningKey{}, nil, fmt.Errorf("runtime signing trust: the result-signing key is not in the trust store")
}

// SigningTrustSource supplies the operator's trust store bytes.
type SigningTrustSource interface {
	SigningTrust() ([]byte, error)
	eligibility.ProductionEligibility
}

// FileSigningTrust reads the operator-distributed trust store from disk on
// every verification. Reading once at start would only prove the material was
// good when the process began; a key revoked an hour later must stop verifying
// an hour later.
type FileSigningTrust struct{ path string }

// NewFileSigningTrust binds the verifier to the operator's document.
func NewFileSigningTrust(path string) (*FileSigningTrust, error) {
	if path == "" {
		return nil, fmt.Errorf("runtime signing trust: a trust store path is required")
	}
	return &FileSigningTrust{path: path}, nil
}

// Eligibility declares this source fit for production: it reads real operator
// material distributed independently of the runtimes it authenticates.
func (*FileSigningTrust) Eligibility() eligibility.Eligibility { return eligibility.ProductionEligible }

func (f *FileSigningTrust) SigningTrust() ([]byte, error) { return os.ReadFile(f.path) }

// ResultVerifier proves a runtime result was signed by a key the operator
// approved for the release the run pinned.
//
// It is the trust half of the commit predicate. The binding and fencing checks
// answer "is this result for the execution we are holding"; this answers "was
// this result produced by the release we dispatched to". Neither implies the
// other: a correctly bound result with no valid signature is an unattributable
// proposal, and a perfectly signed result for another attempt is a replay.
type ResultVerifier struct {
	source SigningTrustSource

	lock sync.Mutex
}

// NewResultVerifier binds the verifier to its trust material.
func NewResultVerifier(source SigningTrustSource) (*ResultVerifier, error) {
	if source == nil {
		return nil, fmt.Errorf("runtime result verification: a signing trust store is required")
	}
	return &ResultVerifier{source: source}, nil
}

// Eligibility is the trust source's own declaration. A verifier is exactly as
// production-fit as the material it reads, so it reports that rather than
// asserting anything of its own.
func (v *ResultVerifier) Eligibility() eligibility.Eligibility {
	return eligibility.EligibilityOf(v.source)
}

// Verify proves the signature envelope of one result against the release the
// run pinned. A non-nil error means no state may change.
func (v *ResultVerifier) Verify(result schema.AgentRuntimeResult, binding agent.RuntimeBinding, now time.Time) error {
	envelope := result.Signature
	if string(envelope.Algorithm) != ResultSignatureAlgorithm {
		return fmt.Errorf("runtime result verification: the result declares signature algorithm %q, which this service does not accept", envelope.Algorithm)
	}
	if envelope.KeyId == "" || envelope.Signature == "" || envelope.StatementDigest == "" || envelope.ProvenanceReference == "" {
		return fmt.Errorf("runtime result verification: the signature envelope is incomplete")
	}
	signature, err := base64.RawURLEncoding.DecodeString(envelope.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("runtime result verification: the signature is not verifiable bytes")
	}
	// The statement is recomputed rather than reconstructed from the digest the
	// result asserts. A verifier that signed off on the sender's own digest
	// would be proving a signature over a document nobody checked.
	statement, err := StatementBytes(result)
	if err != nil {
		return fmt.Errorf("runtime result verification: %w", err)
	}
	if digest, err := StatementDigest(result); err != nil || digest != string(envelope.StatementDigest) {
		return fmt.Errorf("runtime result verification: the statement digest does not describe the result")
	}

	v.lock.Lock()
	raw, err := v.source.SigningTrust()
	v.lock.Unlock()
	if err != nil {
		return fmt.Errorf("runtime result verification: read the signing trust store: %w", err)
	}
	store, skew, err := ParseSigningTrust(raw, now)
	if err != nil {
		return err
	}
	key, public, err := store.Resolve(envelope.KeyId, now, skew)
	if err != nil {
		return err
	}
	// The key's approved runtime identity must be the release this run pinned
	// and the one the result claims to be. Checking only one of the two would
	// leave the other free to vary.
	if !contains(key.RuntimeUnitIDs, binding.RuntimeUnitID) || binding.RuntimeUnitID != string(result.Selected.RuntimeUnitId) {
		return fmt.Errorf("runtime result verification: the signing key is not approved for the runtime unit this run pinned")
	}
	if !contains(key.Audiences, binding.RuntimeAudience) {
		return fmt.Errorf("runtime result verification: the signing key is not approved for the audience this run pinned")
	}
	if !contains(key.RuntimeManifestDigests, binding.RuntimeManifestDigest) {
		return fmt.Errorf("runtime result verification: the signing key is not approved for the released manifest this run pinned")
	}
	if !contains(key.ProvenanceDigests, string(envelope.ProvenanceReference)) {
		return fmt.Errorf("runtime result verification: the result names a provenance the signing key is not approved for")
	}
	if !trust.Verify(public, StatementPayloadType, statement, signature) {
		return fmt.Errorf("runtime result verification: the result signature does not verify")
	}
	return nil
}
