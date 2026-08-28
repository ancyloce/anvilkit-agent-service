package runtimes

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/contracts/generated/schema"
	"github.com/ancyloce/anvilkit-agent-service/internal/agent"
	"github.com/ancyloce/anvilkit-agent-service/internal/eligibility"
)

// Result verification is the trust half of the commit predicate: it answers
// whether the thing that produced a result was the release the run dispatched
// to. The fence answers a different question — whether the result is still for
// the execution being held — and these tests are written so that neither can
// stand in for the other.

const (
	verifyingUnit      = "runtime.platform.page-change-manager"
	verifyingAudience  = "urn:anvilkit:audience:runtime-page-change-manager"
	verifyingManifest  = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	verifyingImage     = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	verifyingProtocol  = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	verifyingProvenanc = "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	verifyingKeyID     = "urn:anvilkit:key:page-change-manager-result"
)

var verifyingNow = time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)

func verifiedBinding() agent.RuntimeBinding {
	return agent.RuntimeBinding{
		RuntimeUnitID:            verifyingUnit,
		RuntimeManifestDigest:    verifyingManifest,
		RuntimeImageDigest:       verifyingImage,
		InvocationProtocolDigest: verifyingProtocol,
		RuntimeAudience:          verifyingAudience,
	}
}

// releaseSigner is the runtime's own key. It signs exactly as a released unit
// does: Ed25519 over the DSSE pre-authentication encoding of the canonical
// statement.
type releaseSigner struct {
	key   ed25519.PrivateKey
	keyID string
}

func newReleaseSigner(t *testing.T, filler byte, keyID string) *releaseSigner {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = filler
	}
	return &releaseSigner{key: ed25519.NewKeyFromSeed(seed), keyID: keyID}
}

// sign stamps a complete, verifiable envelope onto a result.
func (s *releaseSigner) sign(t *testing.T, result *schema.AgentRuntimeResult, provenance string) {
	t.Helper()
	statement, err := StatementBytes(*result)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := StatementDigest(*result)
	if err != nil {
		t.Fatal(err)
	}
	prefix := "DSSEv1 " + itoa(len(StatementPayloadType)) + " " + StatementPayloadType + " " + itoa(len(statement)) + " "
	signature := ed25519.Sign(s.key, append([]byte(prefix), statement...))
	result.Signature = schema.AgentRuntimeResultSignature{
		Algorithm:           ResultSignatureAlgorithm,
		KeyId:               s.keyID,
		Signature:           base64.RawURLEncoding.EncodeToString(signature),
		StatementDigest:     schema.SharedPrimitivesDigest(digest),
		ProvenanceReference: schema.SharedPrimitivesDigest(provenance),
	}
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	digits := []byte{}
	for value > 0 {
		digits = append([]byte{byte('0' + value%10)}, digits...)
		value /= 10
	}
	return string(digits)
}

// signedResult is a complete, well-formed result from the release under test.
func signedResult(t *testing.T, signer *releaseSigner, mutate func(*schema.AgentRuntimeResult)) schema.AgentRuntimeResult {
	t.Helper()
	result := schema.AgentRuntimeResult{
		Kind:                "AgentRuntimeResult",
		TaskId:              "task.synthetic.001",
		RunId:               "run.synthetic.001",
		RootRunId:           "run.synthetic.001",
		PhysicalAttemptId:   "attempt.synthetic.001",
		AttemptNumber:       1,
		ExecutionGeneration: 1,
		LeaseEpoch:          1,
		FenceToken:          "fence.synthetic.0001",
		Selected: schema.AgentRuntimeResultSelected{
			RuntimeUnitId:            verifyingUnit,
			DefinitionDigest:         schema.SharedPrimitivesDigest("sha256:" + repeated('a')),
			RuntimeManifestDigest:    verifyingManifest,
			InvocationProtocolDigest: verifyingProtocol,
			ImageDigest:              verifyingImage,
		},
		Status: schema.AgentRuntimeResultStatus{Status: "completed", ReasonCode: "RUNTIME_COMPLETED"},
		TurnDecision: schema.AgentRuntimeResultTurnDecision{
			Decision:        schema.AgentRuntimeResultTurnDecisionDecisionContinue,
			Payload:         schema.SharedPrimitivesBoundedStringMap{"note": "thinking"},
			ArtifactOutputs: []schema.SharedPrimitivesArtifactReference{},
		},
		Usage: schema.AgentRuntimeResultUsage{
			Cost: schema.SharedPrimitivesCost{Amount: "0", Currency: "USD"},
		},
		Diagnostics:  []schema.AgentRuntimeResultDiagnosticsElem{},
		TraceContext: schema.SharedPrimitivesTraceContext{Traceparent: "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"},
	}
	if mutate != nil {
		mutate(&result)
	}
	signer.sign(t, &result, verifyingProvenanc)
	return result
}

// signingTrustSource serves a synthesized operator document, so a test can put
// a key into any state the operator could put it in.
type signingTrustSource struct{ document []byte }

func (signingTrustSource) Eligibility() eligibility.Eligibility {
	return eligibility.ProductionEligible
}
func (s signingTrustSource) SigningTrust() ([]byte, error) { return s.document, nil }

type signingKeyOptions struct {
	keyID      string
	units      []string
	audiences  []string
	manifests  []string
	provenance []string
	status     string
	algorithm  string
	notAfter   time.Time
	nextUpdate time.Time
}

func approvedKey(signer *releaseSigner) signingKeyOptions {
	return signingKeyOptions{
		keyID:      signer.keyID,
		units:      []string{verifyingUnit},
		audiences:  []string{verifyingAudience},
		manifests:  []string{verifyingManifest},
		provenance: []string{verifyingProvenanc},
		status:     "active",
		algorithm:  ResultSignatureAlgorithm,
		notAfter:   verifyingNow.Add(24 * time.Hour),
		nextUpdate: verifyingNow.Add(24 * time.Hour),
	}
}

func verifierFor(t *testing.T, signer *releaseSigner, options signingKeyOptions) *ResultVerifier {
	t.Helper()
	key := SigningKey{
		KeyID:                  options.keyID,
		RuntimeUnitIDs:         options.units,
		Audiences:              options.audiences,
		Algorithm:              options.algorithm,
		Status:                 options.status,
		NotBefore:              verifyingNow.Add(-24 * time.Hour).Format("2006-01-02T15:04:05.000Z"),
		NotAfter:               options.notAfter.Format("2006-01-02T15:04:05.000Z"),
		RuntimeManifestDigests: options.manifests,
		ProvenanceDigests:      options.provenance,
	}
	key.PublicKeyJwk.KeyType = "OKP"
	key.PublicKeyJwk.Curve = "Ed25519"
	key.PublicKeyJwk.X = base64.RawURLEncoding.EncodeToString(signer.key.Public().(ed25519.PublicKey))
	document, err := json.Marshal(SigningTrustStore{
		Kind:                    SigningTrustKind,
		SnapshotID:              "runtime-signing-trust-test",
		IssuedAt:                verifyingNow.Add(-24 * time.Hour).Format("2006-01-02T15:04:05.000Z"),
		NextUpdate:              options.nextUpdate.Format("2006-01-02T15:04:05.000Z"),
		MaximumClockSkewSeconds: 0,
		Keys:                    []SigningKey{key},
	})
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewResultVerifier(signingTrustSource{document: document})
	if err != nil {
		t.Fatal(err)
	}
	return verifier
}

// A result signed by the key the operator approved for this release verifies.
// Every refusal below is only meaningful against this.
func TestAResultFromTheApprovedReleaseVerifies(t *testing.T) {
	signer := newReleaseSigner(t, 1, verifyingKeyID)
	verifier := verifierFor(t, signer, approvedKey(signer))
	if err := verifier.Verify(signedResult(t, signer, nil), verifiedBinding(), verifyingNow); err != nil {
		t.Fatalf("a result from the approved release did not verify: %v", err)
	}
}

// A statement altered after signing is not attributable to anything. This is
// the property that makes every field of the result trustworthy at all: change
// one and the signature stops covering the document.
func TestATamperedStatementIsNotAttributable(t *testing.T) {
	signer := newReleaseSigner(t, 1, verifyingKeyID)
	verifier := verifierFor(t, signer, approvedKey(signer))
	for name, tamper := range map[string]func(*schema.AgentRuntimeResult){
		"the decision": func(r *schema.AgentRuntimeResult) { r.TurnDecision.Payload["note"] = "something else" },
		"the usage":    func(r *schema.AgentRuntimeResult) { r.Usage.ModelCalls = 99 },
		"the status":   func(r *schema.AgentRuntimeResult) { r.Status.ReasonCode = "RUNTIME_REFUSED_BY_POLICY" },
		"the fence":    func(r *schema.AgentRuntimeResult) { r.FenceToken = "fence.somewhere-else" },
		"the attempt":  func(r *schema.AgentRuntimeResult) { r.PhysicalAttemptId = "attempt.somewhere-else" },
		"the selection": func(r *schema.AgentRuntimeResult) {
			r.Selected.ImageDigest = schema.SharedPrimitivesDigest("sha256:" + repeated('9'))
		},
	} {
		t.Run(name, func(t *testing.T) {
			result := signedResult(t, signer, nil)
			tamper(&result)
			// The digest is restated so the tampering is not caught by the
			// cheaper check before it: what is under test is the signature.
			digest, err := StatementDigest(result)
			if err != nil {
				t.Fatal(err)
			}
			result.Signature.StatementDigest = schema.SharedPrimitivesDigest(digest)
			if err := verifier.Verify(result, verifiedBinding(), verifyingNow); err == nil {
				t.Fatal("a result altered after signing was attributed to a release")
			}
		})
	}
}

// A signature from a key nobody approved proves nothing, however well-formed
// the envelope around it is.
func TestASignatureFromAnUnapprovedKeyIsRefused(t *testing.T) {
	approved := newReleaseSigner(t, 1, verifyingKeyID)
	imposter := newReleaseSigner(t, 2, verifyingKeyID)
	verifier := verifierFor(t, approved, approvedKey(approved))
	if err := verifier.Verify(signedResult(t, imposter, nil), verifiedBinding(), verifyingNow); err == nil {
		t.Fatal("a result signed by an unapproved key was attributed to the release")
	}
	unknown := newReleaseSigner(t, 3, "urn:anvilkit:key:some-key-nobody-approved")
	if err := verifier.Verify(signedResult(t, unknown, nil), verifiedBinding(), verifyingNow); err == nil {
		t.Fatal("a result naming a key outside the trust store was attributed to the release")
	}
}

// The key's approved scope is what makes a signature authority rather than
// merely valid: a key approved for one runtime, audience, manifest, or image
// provenance may not sign for another.
func TestAKeyMaySignOnlyWithinItsApprovedScope(t *testing.T) {
	signer := newReleaseSigner(t, 1, verifyingKeyID)
	other := "sha256:" + repeated('9')
	for name, narrow := range map[string]func(*signingKeyOptions){
		"another runtime unit": func(o *signingKeyOptions) {
			o.units = []string{"runtime.platform.page-candidate-specialist"}
		},
		"another audience": func(o *signingKeyOptions) {
			o.audiences = []string{"urn:anvilkit:audience:runtime-page-candidate-specialist"}
		},
		"another manifest":   func(o *signingKeyOptions) { o.manifests = []string{other} },
		"another provenance": func(o *signingKeyOptions) { o.provenance = []string{other} },
	} {
		t.Run(name, func(t *testing.T) {
			options := approvedKey(signer)
			narrow(&options)
			if err := verifierFor(t, signer, options).Verify(signedResult(t, signer, nil), verifiedBinding(), verifyingNow); err == nil {
				t.Fatal("a key signed outside the scope the operator approved it for")
			}
		})
	}
}

// A revoked key stops attributing results immediately, and an overlapping one
// keeps working through a rotation. These are the two halves of being able to
// replace a runtime signing key without dropping work.
func TestKeyRotationAndRevocation(t *testing.T) {
	signer := newReleaseSigner(t, 1, verifyingKeyID)
	for status, attributable := range map[string]bool{"active": true, "overlap": true, "revoked": false, "disabled": false} {
		t.Run(status, func(t *testing.T) {
			options := approvedKey(signer)
			options.status = status
			err := verifierFor(t, signer, options).Verify(signedResult(t, signer, nil), verifiedBinding(), verifyingNow)
			if attributable && err != nil {
				t.Fatalf("a usable key did not attribute a result: %v", err)
			}
			if !attributable && err == nil {
				t.Fatalf("a %s key still attributed a result", status)
			}
		})
	}
	t.Run("outside its validity interval", func(t *testing.T) {
		options := approvedKey(signer)
		options.notAfter = verifyingNow.Add(-time.Second)
		if err := verifierFor(t, signer, options).Verify(signedResult(t, signer, nil), verifiedBinding(), verifyingNow); err == nil {
			t.Fatal("a key past its validity interval still attributed a result")
		}
	})
}

// A trust store past its declared freshness bound attributes nothing. A store
// that outlives its own life is how a revoked key keeps verifying.
func TestAStaleTrustStoreAttributesNothing(t *testing.T) {
	signer := newReleaseSigner(t, 1, verifyingKeyID)
	options := approvedKey(signer)
	options.nextUpdate = verifyingNow.Add(-time.Second)
	if err := verifierFor(t, signer, options).Verify(signedResult(t, signer, nil), verifiedBinding(), verifyingNow); err == nil {
		t.Fatal("a trust store past its freshness bound still attributed a result")
	}
}

// An envelope missing any of its parts is not a signature. A digest alone
// proves nothing to a verifier that does not already hold the bytes.
func TestAnIncompleteEnvelopeIsRefused(t *testing.T) {
	signer := newReleaseSigner(t, 1, verifyingKeyID)
	verifier := verifierFor(t, signer, approvedKey(signer))
	for name, strip := range map[string]func(*schema.AgentRuntimeResult){
		"no signature bytes": func(r *schema.AgentRuntimeResult) { r.Signature.Signature = "" },
		"no key identity":    func(r *schema.AgentRuntimeResult) { r.Signature.KeyId = "" },
		"no statement digest": func(r *schema.AgentRuntimeResult) {
			r.Signature.StatementDigest = ""
		},
		"no provenance": func(r *schema.AgentRuntimeResult) { r.Signature.ProvenanceReference = "" },
		"another algorithm": func(r *schema.AgentRuntimeResult) {
			r.Signature.Algorithm = schema.AgentRuntimeResultSignatureAlgorithm("hmac-sha256")
		},
		"signature that is not bytes": func(r *schema.AgentRuntimeResult) { r.Signature.Signature = "not base64url!!" },
		"a digest that describes something else": func(r *schema.AgentRuntimeResult) {
			r.Signature.StatementDigest = schema.SharedPrimitivesDigest("sha256:" + repeated('9'))
		},
	} {
		t.Run(name, func(t *testing.T) {
			result := signedResult(t, signer, nil)
			strip(&result)
			if err := verifier.Verify(result, verifiedBinding(), verifyingNow); err == nil {
				t.Fatal("an incomplete signature envelope was accepted as a signature")
			}
		})
	}
}

// A perfectly valid signature over a result for another release is still not
// authority for this run. Verification and binding are separate checks, and
// this is the one that proves neither substitutes for the other.
func TestAValidSignatureDoesNotSubstituteForTheReleaseBinding(t *testing.T) {
	signer := newReleaseSigner(t, 1, verifyingKeyID)
	verifier := verifierFor(t, signer, approvedKey(signer))

	// The result is genuinely signed, and genuinely for a different release.
	elsewhere := signedResult(t, signer, func(r *schema.AgentRuntimeResult) {
		r.Selected.RuntimeUnitId = "runtime.platform.page-candidate-specialist"
	})
	if err := verifier.Verify(elsewhere, verifiedBinding(), verifyingNow); err == nil {
		t.Fatal("a validly signed result for another release was attributed to this run's pin")
	}

	// And the same result, verified against a run pinned to a release this key
	// is not approved for, is refused for the pin rather than for the
	// signature.
	binding := verifiedBinding()
	binding.RuntimeManifestDigest = "sha256:" + repeated('9')
	if err := verifier.Verify(signedResult(t, signer, nil), binding, verifyingNow); err == nil {
		t.Fatal("a result was attributed to a manifest the signing key is not approved for")
	}
}

// The trust store is operator material and is read strictly: a document with a
// member this process does not understand is one it cannot claim to have
// verified.
func TestTheTrustStoreIsReadStrictly(t *testing.T) {
	for name, document := range map[string]string{
		"empty":                ``,
		"another kind":         `{"kind":"ContractTrustRoot","snapshotId":"s","issuedAt":"2026-08-27T00:00:00.000Z","nextUpdate":"2026-08-28T00:00:00.000Z","maximumClockSkewSeconds":0,"keys":[]}`,
		"no keys":              `{"kind":"AgentRuntimeSigningTrust","snapshotId":"s","issuedAt":"2026-08-27T00:00:00.000Z","nextUpdate":"2026-08-28T00:00:00.000Z","maximumClockSkewSeconds":0,"keys":[]}`,
		"unknown member":       `{"kind":"AgentRuntimeSigningTrust","snapshotId":"s","issuedAt":"2026-08-27T00:00:00.000Z","nextUpdate":"2026-08-28T00:00:00.000Z","maximumClockSkewSeconds":0,"keys":[],"extra":1}`,
		"trailing content":     `{"kind":"AgentRuntimeSigningTrust","snapshotId":"s","issuedAt":"2026-08-27T00:00:00.000Z","nextUpdate":"2026-08-28T00:00:00.000Z","maximumClockSkewSeconds":0,"keys":[]}{}`,
		"malformed freshness":  `{"kind":"AgentRuntimeSigningTrust","snapshotId":"s","issuedAt":"2026-08-27T00:00:00.000Z","nextUpdate":"tomorrow","maximumClockSkewSeconds":0,"keys":[]}`,
		"unbounded clock skew": `{"kind":"AgentRuntimeSigningTrust","snapshotId":"s","issuedAt":"2026-08-27T00:00:00.000Z","nextUpdate":"2026-08-28T00:00:00.000Z","maximumClockSkewSeconds":9999,"keys":[]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := ParseSigningTrust([]byte(document), verifyingNow); err == nil {
				t.Fatal("a trust store this process cannot fully read was accepted")
			}
		})
	}
}

// A synthesized trust store declares itself controlled, and the verifier that
// reads one reports the same. That declaration is what stops a deployment from
// certifying its own results in production.
func TestASynthesizedTrustStoreDeclaresItselfControlled(t *testing.T) {
	signer := newReleaseSigner(t, 1, verifyingKeyID)
	source, err := NewControlledSigningTrust(signer.key.Public().(ed25519.PublicKey), verifyingKeyID,
		[]Release{{RuntimeUnitID: verifyingUnit, ManifestDigest: verifyingManifest, Binding: verifiedBinding()}},
		func() time.Time { return verifyingNow })
	if err != nil {
		t.Fatal(err)
	}
	if source.Eligibility() != eligibility.ControlledOnly {
		t.Fatal("a synthesized runtime trust store did not declare itself controlled")
	}
	verifier, err := NewResultVerifier(source)
	if err != nil {
		t.Fatal(err)
	}
	if verifier.Eligibility() != eligibility.ControlledOnly {
		t.Fatal("a verifier reading synthesized material claimed to be production-eligible")
	}
	// It still verifies: a controlled composition proves the same property
	// production does, against material it is not allowed to use there.
	result := signedResult(t, signer, nil)
	result.Signature.ProvenanceReference = schema.SharedPrimitivesDigest(verifyingManifest)
	signer.sign(t, &result, verifyingManifest)
	if err := verifier.Verify(result, verifiedBinding(), verifyingNow); err != nil {
		t.Fatalf("the synthesized store did not attribute the stand-in's own result: %v", err)
	}
}
