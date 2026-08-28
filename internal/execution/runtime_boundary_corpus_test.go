package execution_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/contracts/generated/schema"
	"github.com/ancyloce/anvilkit-agent-service/internal/agent"
	"github.com/ancyloce/anvilkit-agent-service/internal/dispatch"
	"github.com/ancyloce/anvilkit-agent-service/internal/runtimes"
	"github.com/ancyloce/anvilkit-agent-service/internal/security"
)

// The execution boundary's own adversarial categories.
//
// Each is bound to the decision that actually owns it in production: the
// credential verifier a runtime admits against, the result verifier the fenced
// commit runs before any mutation, and the dispatch coordinator that holds the
// fence. A guard written against a comparison in the test instead would prove
// the corpus agrees with itself, which is the failure the corpus was rebuilt to
// stop being.

// boundaryGuards binds the runtime-boundary categories to those decisions.
func boundaryGuards(t *testing.T) security.Guards {
	t.Helper()
	return security.Guards{
		"credential-replay": security.GuardFunc(func(_ context.Context, _ security.AttackCase) (bool, error) {
			return aCredentialIsNotAuthorityForAnotherAttempt(t), nil
		}),
		"credential-forgery": security.GuardFunc(func(_ context.Context, _ security.AttackCase) (bool, error) {
			return aRewrittenCredentialDoesNotVerify(t), nil
		}),
		"expired-credential": security.GuardFunc(func(_ context.Context, _ security.AttackCase) (bool, error) {
			return anExpiredCredentialDoesNotVerify(t), nil
		}),
		"wrong-audience": security.GuardFunc(func(_ context.Context, attack security.AttackCase) (bool, error) {
			return aCredentialForAnotherAudienceIsRefused(t, attack), nil
		}),
		"wrong-runtime": security.GuardFunc(func(_ context.Context, attack security.AttackCase) (bool, error) {
			return aResultFromAnotherReleaseIsNotAttributed(t, attack), nil
		}),
		"result-tampering": security.GuardFunc(func(_ context.Context, _ security.AttackCase) (bool, error) {
			return aTamperedResultIsNotAttributed(t), nil
		}),
		"unsigned-result": security.GuardFunc(func(_ context.Context, _ security.AttackCase) (bool, error) {
			return anUnsignedResultIsNotAttributed(t), nil
		}),
		"stale-attempt": security.GuardFunc(func(ctx context.Context, _ security.AttackCase) (bool, error) {
			return aSupersededAttemptCannotCommit(ctx, t)
		}),
	}
}

const (
	boundaryUnit       = "runtime.platform.page-change-manager"
	boundaryAudience   = "urn:anvilkit:audience:runtime-page-change-manager"
	boundaryManifest   = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	boundaryImage      = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	boundaryProtocol   = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	boundaryProvenance = "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	boundaryKeyID      = "urn:anvilkit:key:boundary-corpus-runtime-result"
	boundaryCredKeyID  = "urn:anvilkit:key:boundary-corpus-task-credential"
)

var boundaryNow = time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)

func boundaryBinding() agent.RuntimeBinding {
	return agent.RuntimeBinding{
		RuntimeUnitID:            boundaryUnit,
		RuntimeManifestDigest:    boundaryManifest,
		RuntimeImageDigest:       boundaryImage,
		InvocationProtocolDigest: boundaryProtocol,
		RuntimeAudience:          boundaryAudience,
	}
}

// boundaryTask is the canonical task these attacks are aimed at.
func boundaryTask() schema.AgentTask {
	return schema.AgentTask{
		Kind:                  "AgentTask",
		TaskId:                "task.corpus.001",
		RunId:                 "run.corpus.001",
		RootRunId:             "run.corpus.001",
		PhysicalAttemptId:     "attempt.corpus.001",
		AttemptNumber:         1,
		ExecutionGeneration:   1,
		LeaseEpoch:            1,
		FenceToken:            "fence.corpus.0001",
		ExpiresAt:             schema.SharedPrimitivesTimestamp(boundaryNow.Add(time.Hour)),
		AuthorizationAudience: boundaryAudience,
		RuntimeBinding: schema.AgentTaskRuntimeBinding{
			RuntimeUnitId:            schema.SharedPrimitivesOpaqueId(boundaryUnit),
			RuntimeManifestDigest:    boundaryManifest,
			RuntimeImageDigest:       boundaryImage,
			InvocationProtocolDigest: boundaryProtocol,
			RuntimeAudience:          boundaryAudience,
		},
	}
}

// boundaryCredentials builds the real issuer and the real trust it is admitted
// against — the same two objects a deployment composes.
func boundaryCredentials(t *testing.T) (*runtimes.TaskCredentials, *runtimes.CredentialTrust) {
	t.Helper()
	issuer, err := runtimes.NewSeededTaskCredentials("boundary-corpus-credential-material", boundaryCredKeyID, 5*time.Minute,
		func() time.Time { return boundaryNow })
	if err != nil {
		t.Fatal(err)
	}
	source, err := runtimes.NewControlledCredentialTrust(issuer.PublicKey(), issuer.KeyID(),
		[]string{boundaryAudience}, func() time.Time { return boundaryNow })
	if err != nil {
		t.Fatal(err)
	}
	trust, err := runtimes.NewCredentialTrust(source)
	if err != nil {
		t.Fatal(err)
	}
	return issuer, trust
}

// A credential is authority for one attempt. Presented beside any other, it
// verifies as what it is — a credential for a different attempt — and binds
// nothing here.
func aCredentialIsNotAuthorityForAnotherAttempt(t *testing.T) bool {
	t.Helper()
	issuer, trust := boundaryCredentials(t)
	credential, err := issuer.Issue(context.Background(), boundaryTask(),
		runtimes.Subject{WorkspaceID: "workspace-a", ProjectID: "project-a"})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := trust.Verify(credential.Value, boundaryAudience, boundaryNow)
	if err != nil {
		t.Fatal(err)
	}
	replayed := boundaryTask()
	replayed.PhysicalAttemptId = "attempt.corpus.002"
	replayed.LeaseEpoch = 2
	return runtimes.BindsTask(verified, replayed, runtimes.OperationExecute) != ""
}

// A credential whose claims were rewritten after signing does not verify. This
// is what makes every other claim on it worth reading.
func aRewrittenCredentialDoesNotVerify(t *testing.T) bool {
	t.Helper()
	issuer, trust := boundaryCredentials(t)
	credential, err := issuer.Issue(context.Background(), boundaryTask(),
		runtimes.Subject{WorkspaceID: "workspace-a", ProjectID: "project-a"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = trust.Verify(rewriteTenant(t, credential.Value), boundaryAudience, boundaryNow)
	return err != nil
}

// A captured credential stops being authority when its window closes.
func anExpiredCredentialDoesNotVerify(t *testing.T) bool {
	t.Helper()
	issuer, trust := boundaryCredentials(t)
	credential, err := issuer.Issue(context.Background(), boundaryTask(),
		runtimes.Subject{WorkspaceID: "workspace-a", ProjectID: "project-a"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = trust.Verify(credential.Value, boundaryAudience, credential.ExpiresAt.Add(time.Second))
	return err != nil
}

// A credential minted for one release is refused at another, even though it is
// perfectly valid where it was issued.
func aCredentialForAnotherAudienceIsRefused(t *testing.T, attack security.AttackCase) bool {
	t.Helper()
	issuer, trust := boundaryCredentials(t)
	credential, err := issuer.Issue(context.Background(), boundaryTask(),
		runtimes.Subject{WorkspaceID: "workspace-a", ProjectID: "project-a"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = trust.Verify(credential.Value, attack.Input, boundaryNow)
	return err != nil
}

// A result attributed to another release is not attributed to this run's pin,
// however genuinely it was signed.
func aResultFromAnotherReleaseIsNotAttributed(t *testing.T, attack security.AttackCase) bool {
	t.Helper()
	signer, verifier := boundaryResultTrust(t)
	result := boundaryResult(t, signer, func(r *schema.AgentRuntimeResult) {
		r.Selected.RuntimeUnitId = schema.SharedPrimitivesOpaqueId(attack.Input)
	})
	return verifier.Verify(result, boundaryBinding(), boundaryNow) != nil
}

// A result altered after signing is not attributable to anything, even with its
// own statement digest restated to match.
func aTamperedResultIsNotAttributed(t *testing.T) bool {
	t.Helper()
	signer, verifier := boundaryResultTrust(t)
	result := boundaryResult(t, signer, nil)
	result.Usage.ModelCalls = 99
	digest, err := runtimes.StatementDigest(result)
	if err != nil {
		t.Fatal(err)
	}
	result.Signature.StatementDigest = schema.SharedPrimitivesDigest(digest)
	return verifier.Verify(result, boundaryBinding(), boundaryNow) != nil
}

// A result carrying a digest and no verifiable signature is a claim, not an
// attestation. Signing only a digest label is exactly the failure the complete
// envelope exists to prevent.
func anUnsignedResultIsNotAttributed(t *testing.T) bool {
	t.Helper()
	signer, verifier := boundaryResultTrust(t)
	result := boundaryResult(t, signer, nil)
	result.Signature.Signature = ""
	return verifier.Verify(result, boundaryBinding(), boundaryNow) != nil
}

// A superseded attempt is refused twice over: its credential is not authority
// for the replacement's lease, so the work is never admitted, and its result
// could not commit even if it were.
//
// Both halves are asserted because only one of them is new. The fence has been
// held by the durable record since the attempt lifecycle existed; what was open
// until now is the front door, where a runtime executed — and charged a model
// call for — work under a lease nobody could commit against.
func aSupersededAttemptCannotCommit(ctx context.Context, t *testing.T) (bool, error) {
	t.Helper()
	if !aCredentialIsNotAuthorityForALaterLease(t) {
		return false, nil
	}
	repository := dispatch.NewMemoryRepository()
	coordinator, err := dispatch.New(dispatch.Config{
		Repository: repository,
		Tokens:     dispatch.RandomTokens{},
		Clock:      systemClock{},
		Lease:      time.Minute,
	})
	if err != nil {
		return false, err
	}
	scope := dispatch.Scope{WorkspaceID: "workspace-a", ProjectID: "project-a"}
	request := dispatch.Request{
		Scope:               scope,
		RunID:               "run.corpus.001",
		RootRunID:           "run.corpus.001",
		TaskID:              "task.corpus.001",
		ExecutionGeneration: 1,
		DefinitionDigest:    "sha256:" + boundaryFill('a'),
		Runtime:             boundaryBinding(),
		Capability:          runtimes.TurnCapability,
		RequestDigest:       "sha256:" + boundaryFill('b'),
	}
	first, err := coordinator.Open(ctx, request)
	if err != nil {
		return false, err
	}
	// A replacement is opened, which is what supersedes the first attempt.
	replacement := request
	replacement.Replacing = dispatch.ReasonDispatchFailed
	if _, err := coordinator.Open(ctx, replacement); err != nil {
		return false, err
	}
	settled, err := coordinator.Settle(ctx, dispatch.Settle{
		Scope:     scope,
		RunID:     request.RunID,
		Predicate: boundaryPredicate(first),
		Outcome: dispatch.Outcome{
			Status:                "completed",
			ReasonCode:            "RUNTIME_COMPLETED",
			ResultStatementDigest: "sha256:" + boundaryFill('c'),
			SignatureKeyID:        boundaryKeyID,
			Statement:             []byte(`{"kind":"AgentRuntimeResult"}`),
			ObservedAt:            systemClock{}.Now(),
		},
	})
	if err != nil {
		return false, err
	}
	return !settled.Disposition.Committed(), nil
}

// aCredentialIsNotAuthorityForALaterLease is the admission half: the credential
// a superseded attempt was dispatched with names that attempt's lease epoch, and
// binds nothing once a replacement holds the lease.
func aCredentialIsNotAuthorityForALaterLease(t *testing.T) bool {
	t.Helper()
	issuer, trust := boundaryCredentials(t)
	superseded := boundaryTask()
	credential, err := issuer.Issue(context.Background(), superseded,
		runtimes.Subject{WorkspaceID: "workspace-a", ProjectID: "project-a"})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := trust.Verify(credential.Value, boundaryAudience, boundaryNow)
	if err != nil {
		t.Fatal(err)
	}
	replacement := boundaryTask()
	replacement.PhysicalAttemptId = "attempt.corpus.002"
	replacement.AttemptNumber = 2
	replacement.LeaseEpoch = 2
	return runtimes.BindsTask(verified, replacement, runtimes.OperationExecute) != ""
}

func boundaryPredicate(execution dispatch.Execution) dispatch.Predicate {
	return dispatch.Predicate{
		RunID:                    execution.Task.RunID,
		TaskID:                   execution.Task.TaskID,
		ExecutionGeneration:      execution.Task.ExecutionGeneration,
		PhysicalAttemptID:        execution.Attempt.PhysicalAttemptID,
		AttemptNumber:            execution.Attempt.AttemptNumber,
		LeaseEpoch:               execution.Attempt.LeaseEpoch,
		FenceToken:               execution.FenceToken,
		RuntimeUnitID:            execution.Task.Runtime.RuntimeUnitID,
		RuntimeManifestDigest:    execution.Task.Runtime.RuntimeManifestDigest,
		RuntimeImageDigest:       execution.Task.Runtime.RuntimeImageDigest,
		InvocationProtocolDigest: execution.Task.Runtime.InvocationProtocolDigest,
	}
}

// boundaryResultTrust builds a runtime signing key and the trust store that
// approves it for this release — the real verifier, over real material.
func boundaryResultTrust(t *testing.T) (ed25519.PrivateKey, *runtimes.ResultVerifier) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = 7
	}
	key := ed25519.NewKeyFromSeed(seed)
	source, err := runtimes.NewControlledSigningTrust(key.Public().(ed25519.PublicKey), boundaryKeyID,
		[]runtimes.Release{{RuntimeUnitID: boundaryUnit, ManifestDigest: boundaryManifest, Binding: boundaryBinding()}},
		func() time.Time { return boundaryNow })
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := runtimes.NewResultVerifier(source)
	if err != nil {
		t.Fatal(err)
	}
	return key, verifier
}

// boundaryResult is a complete, genuinely signed result from that release.
func boundaryResult(t *testing.T, key ed25519.PrivateKey, mutate func(*schema.AgentRuntimeResult)) schema.AgentRuntimeResult {
	t.Helper()
	result := schema.AgentRuntimeResult{
		Kind:                "AgentRuntimeResult",
		TaskId:              "task.corpus.001",
		RunId:               "run.corpus.001",
		RootRunId:           "run.corpus.001",
		PhysicalAttemptId:   "attempt.corpus.001",
		AttemptNumber:       1,
		ExecutionGeneration: 1,
		LeaseEpoch:          1,
		FenceToken:          "fence.corpus.0001",
		Selected: schema.AgentRuntimeResultSelected{
			RuntimeUnitId:            schema.SharedPrimitivesOpaqueId(boundaryUnit),
			DefinitionDigest:         schema.SharedPrimitivesDigest("sha256:" + boundaryFill('a')),
			RuntimeManifestDigest:    boundaryManifest,
			InvocationProtocolDigest: boundaryProtocol,
			ImageDigest:              boundaryImage,
		},
		Status: schema.AgentRuntimeResultStatus{Status: "completed", ReasonCode: "RUNTIME_COMPLETED"},
		TurnDecision: schema.AgentRuntimeResultTurnDecision{
			Decision:        schema.AgentRuntimeResultTurnDecisionDecisionContinue,
			Payload:         schema.SharedPrimitivesBoundedStringMap{"note": "thinking"},
			ArtifactOutputs: []schema.SharedPrimitivesArtifactReference{},
		},
		Usage:        schema.AgentRuntimeResultUsage{Cost: schema.SharedPrimitivesCost{Amount: "0", Currency: "USD"}},
		Diagnostics:  []schema.AgentRuntimeResultDiagnosticsElem{},
		TraceContext: schema.SharedPrimitivesTraceContext{Traceparent: "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"},
	}
	if mutate != nil {
		mutate(&result)
	}
	statement, err := runtimes.StatementBytes(result)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := runtimes.StatementDigest(result)
	if err != nil {
		t.Fatal(err)
	}
	// The provenance a stand-in reports is the released manifest it stands in
	// for, which is what the synthesized trust store approves it for.
	prefix := []byte("DSSEv1 " + itoa(len(runtimes.StatementPayloadType)) + " " + runtimes.StatementPayloadType + " " + itoa(len(statement)) + " ")
	result.Signature = schema.AgentRuntimeResultSignature{
		Algorithm:           runtimes.ResultSignatureAlgorithm,
		KeyId:               boundaryKeyID,
		Signature:           base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, append(prefix, statement...))),
		StatementDigest:     schema.SharedPrimitivesDigest(digest),
		ProvenanceReference: schema.SharedPrimitivesDigest(boundaryManifest),
	}
	return result
}

// rewriteTenant rewrites one claim of a signed credential and leaves the
// signature as it was, which is what an interception looks like.
func rewriteTenant(t *testing.T, credential string) string {
	t.Helper()
	parts := splitThree(t, credential)
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatal(err)
	}
	binding, ok := claims["urn:anvilkit:claim:task-binding"].(map[string]any)
	if !ok {
		t.Fatal("the credential carries no task binding")
	}
	binding["workspaceId"] = "workspace-b"
	encoded, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	parts[1] = base64.RawURLEncoding.EncodeToString(encoded)
	return parts[0] + "." + parts[1] + "." + parts[2]
}

func splitThree(t *testing.T, value string) [3]string {
	t.Helper()
	var parts [3]string
	index, start := 0, 0
	for position := 0; position < len(value); position++ {
		if value[position] != '.' {
			continue
		}
		if index > 1 {
			t.Fatal("the credential is not a compact JWS")
		}
		parts[index] = value[start:position]
		index, start = index+1, position+1
	}
	if index != 2 {
		t.Fatal("the credential is not a compact JWS")
	}
	parts[2] = value[start:]
	return parts
}

func boundaryFill(character byte) string {
	value := make([]byte, 64)
	for index := range value {
		value[index] = character
	}
	return string(value)
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
