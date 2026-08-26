package runapp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/artifacts"
	"github.com/ancyloce/anvilkit-agent-service/internal/auth"
	"github.com/ancyloce/anvilkit-agent-service/internal/events"
	"github.com/ancyloce/anvilkit-agent-service/internal/execution"
	"github.com/ancyloce/anvilkit-agent-service/internal/journal"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/runs"
)

const (
	authorizationRunID    = "run"
	authorizationArtifact = "artifact.apply.0001"
	authorizationApproval = "request.approve.0001"
	authorizationTrace    = "00-00000000000000000000000000000001-0000000000000001-01"
)

func authorizationDigest(character string) string {
	return "sha256:" + strings.Repeat(character, 64)
}

// recordingIssuer stands in for the execution pipeline. It records the intent
// it was handed, so a test can prove that nothing the caller supplied about
// identity, expiry, or issuer reached it — only what the caller is allowed to
// state.
type recordingIssuer struct {
	intents []execution.ApplyAuthorizationIntent
	issued  execution.IssuedAuthorization
	err     error
}

func (i *recordingIssuer) IssueApplyAuthorization(_ context.Context, _ runs.Scope, intent execution.ApplyAuthorizationIntent) (execution.IssuedAuthorization, error) {
	i.intents = append(i.intents, intent)
	if i.err != nil {
		return execution.IssuedAuthorization{}, i.err
	}
	return i.issued, nil
}

// signedCapability renders a compact JWS whose payload is a canonical
// ApplyAuthorization document, which is what the issuer really produces.
func signedCapability(t *testing.T) execution.IssuedAuthorization {
	t.Helper()
	payload := map[string]any{
		"kind":              "ApplyAuthorization",
		"authorizationId":   "authorization.0001",
		"keyId":             "urn:anvilkit:key:agent-service:synthetic",
		"issuer":            "urn:anvilkit:issuer:agent-service",
		"audience":          "urn:anvilkit:audience:pagix",
		"issuedAt":          "2026-08-21T12:00:00.000Z",
		"notBefore":         "2026-08-21T12:00:00.000Z",
		"expiresAt":         "2026-08-21T12:05:00.000Z",
		"runId":             authorizationRunID,
		"actionDigest":      authorizationDigest("a"),
		"artifactDigest":    authorizationDigest("a"),
		"target":            map[string]any{"targetType": "page", "targetId": "page.0001", "workspaceId": "workspace", "projectId": "project"},
		"baseRevision":      "revision.synthetic.001",
		"actorId":           "actor",
		"workspaceId":       "workspace",
		"approvalVersion":   1,
		"contractBomDigest": authorizationDigest("b"),
		"policyDigest":      authorizationDigest("c"),
		"definitionDigest":  authorizationDigest("d"),
		"catalogDigest":     authorizationDigest("e"),
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","kid":"urn:anvilkit:key:agent-service:synthetic","typ":"anvilkit-apply-authorization+jws"}`))
	body := base64.RawURLEncoding.EncodeToString(raw)
	signature := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("s", 64)))
	return execution.IssuedAuthorization{
		AuthorizationID: "authorization.0001",
		CompactJWS:      header + "." + body + "." + signature,
		ExpiresAt:       time.Date(2026, 8, 21, 12, 5, 0, 0, time.UTC),
	}
}

func authorizationApp(t *testing.T, issuer ApplyAuthorizationIssuer) (*App, *MemoryCommandReceipts) {
	t.Helper()
	now := time.Now()
	validator, err := auth.NewValidator(auth.Config{Issuers: []string{"issuer"}, Audience: "agent", MaximumClockSkew: time.Second}, trust{}, clock{now})
	if err != nil {
		t.Fatal(err)
	}
	runStore := &store{snapshot: runs.Snapshot{RunID: authorizationRunID, WorkspaceID: "workspace", Version: 3}}
	app := New(validator, runs.NewService(runStore, starter{}, ids{}, clock{now}, journal.NewMemoryStore(), runs.AdmitFunc(func(context.Context, runs.Scope) error { return nil })), eventReader{}, events.StreamConfig{}, appAuthoritySource{}, testGuard(t), testDefinitions{})
	receipts := NewMemoryCommandReceipts(func() time.Time { return now }, time.Minute)
	app.WithApplyAuthorization(issuer, receipts)
	return app, receipts
}

func issuerClaims() auth.Claims {
	return auth.Claims{
		Verified: true, Source: auth.SourceWorkload, Issuer: "issuer", Audience: "agent",
		Subject: "issuer-actor", ActorID: "issuer-actor", WorkspaceID: "workspace", ProjectID: "project",
		Purpose: "agent", KeyID: "key", Scopes: []string{auth.ScopeIssuer},
		ExpiresAt: time.Now().Add(time.Hour),
	}
}

func authorizationBody() []byte {
	return []byte(`{"kind":"IssueApplyAuthorizationRequest","runId":"` + authorizationRunID +
		`","actionDigest":"` + authorizationDigest("a") +
		`","artifact":{"artifactId":"` + authorizationArtifact + `","digest":"` + authorizationDigest("a") + `","mediaType":"application/json","sizeBytes":128}` +
		`,"target":{"targetType":"page","targetId":"page.0001","workspaceId":"workspace","projectId":"project"}` +
		`,"baseRevision":"rev:` + authorizationApproval + `"` +
		`,"approvalReference":{"requestId":"` + authorizationApproval + `","decisionVersion":1}` +
		`,"expectedRunRevision":3}`)
}

func authorizationInput(t *testing.T, raw []byte, key string) ControlInput {
	t.Helper()
	return ControlInput{
		WorkspaceID: "workspace",
		RunID:       authorizationRunID,
		ETag:        `"` + authorizationRunID + `:v3"`,
		Key:         key,
		Digest:      custodyDigest(t, raw),
		Traceparent: authorizationTrace,
	}
}

// The governed issuance path answers the canonical representation, and the
// document it carries is the token's own payload rather than a second
// rendering beside it.
func TestIssuingAnApplyAuthorizationAnswersTheCanonicalRepresentation(t *testing.T) {
	issuer := &recordingIssuer{issued: signedCapability(t)}
	app, _ := authorizationApp(t, issuer)
	raw := authorizationBody()
	result, err := app.IssueApplyAuthorization(context.Background(), issuerClaims(), authorizationInput(t, raw, "issue-key"), raw)
	if err != nil {
		t.Fatalf("a governed issuance was refused: %v", err)
	}
	var representation struct {
		Kind          string          `json:"kind"`
		Authorization json.RawMessage `json:"authorization"`
		CompactJWS    string          `json:"compactJws"`
	}
	if err := json.Unmarshal(result.Body, &representation); err != nil {
		t.Fatal(err)
	}
	if representation.Kind != IssuedApplyAuthorizationKind || representation.CompactJWS != issuer.issued.CompactJWS {
		t.Fatalf("the representation does not carry the issued capability: %s", result.Body)
	}
	// The document and the token must be the same bytes after
	// canonicalization; taking the document from the token is what makes that
	// true rather than hoped for.
	segments := strings.Split(issuer.issued.CompactJWS, ".")
	payload, err := base64.RawURLEncoding.DecodeString(segments[1])
	if err != nil {
		t.Fatal(err)
	}
	var fromToken, fromRepresentation map[string]any
	if err := json.Unmarshal(payload, &fromToken); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(representation.Authorization, &fromRepresentation); err != nil {
		t.Fatal(err)
	}
	if len(fromToken) != len(fromRepresentation) || fromToken["authorizationId"] != fromRepresentation["authorizationId"] {
		t.Fatalf("the document is not the token's payload: %s", representation.Authorization)
	}
	// The intent carries only what the caller is allowed to state. Nothing
	// about issuer, key, audience, or expiry reaches it, because the canonical
	// contract has no place to put them.
	if len(issuer.intents) != 1 {
		t.Fatalf("the issuance ran %d times", len(issuer.intents))
	}
	intent := issuer.intents[0]
	if intent.RunID != authorizationRunID || intent.ExpectedRunRevision != 3 || intent.ApprovalRequestID != authorizationApproval || intent.ApprovalDecisionVersion != 1 {
		t.Fatalf("the intent did not carry the command: %+v", intent)
	}
}

// A signed capability is the last thing that should be mintable twice because
// a client retried, so the recorded outcome is replayed and the issuance runs
// once.
func TestARepeatedIssuanceKeyReplaysTheRecordedCapability(t *testing.T) {
	issuer := &recordingIssuer{issued: signedCapability(t)}
	app, _ := authorizationApp(t, issuer)
	raw := authorizationBody()
	first, err := app.IssueApplyAuthorization(context.Background(), issuerClaims(), authorizationInput(t, raw, "issue-key"), raw)
	if err != nil {
		t.Fatal(err)
	}
	second, err := app.IssueApplyAuthorization(context.Background(), issuerClaims(), authorizationInput(t, raw, "issue-key"), raw)
	if err != nil {
		t.Fatal(err)
	}
	if !second.Replayed || string(second.Body) != string(first.Body) || second.ETag != first.ETag {
		t.Fatalf("a replayed key did not answer the recorded capability: %+v", second)
	}
	if len(issuer.intents) != 1 {
		t.Fatalf("a replayed key minted %d capabilities", len(issuer.intents))
	}
}

// Every way the request can be wrong fails closed, and none of them mints a
// capability.
func TestIssuanceFailsClosedOnEveryMalformedOrUnauthorizedRequest(t *testing.T) {
	raw := authorizationBody()
	for name, attempt := range map[string]struct {
		claims auth.Claims
		input  func(t *testing.T) ControlInput
		body   []byte
		expect problem.Code
	}{
		"another tenant's workspace is absent rather than denied": {
			claims: issuerClaims(),
			input: func(t *testing.T) ControlInput {
				input := authorizationInput(t, raw, "issue-key")
				input.WorkspaceID = "other-workspace"
				return input
			},
			body:   raw,
			expect: problem.CodeResourceNotFound,
		},
		"a caller without the issuance scope is denied": {
			claims: func() auth.Claims {
				claims := issuerClaims()
				claims.Scopes = []string{auth.ScopeRead}
				return claims
			}(),
			input:  func(t *testing.T) ControlInput { return authorizationInput(t, raw, "issue-key") },
			body:   raw,
			expect: problem.CodeAuthorizationDenied,
		},
		"a missing concurrency precondition is required": {
			claims: issuerClaims(),
			input: func(t *testing.T) ControlInput {
				input := authorizationInput(t, raw, "issue-key")
				input.ETag = ""
				return input
			},
			body:   raw,
			expect: problem.CodePreconditionRequired,
		},
		"a stale concurrency precondition conflicts": {
			claims: issuerClaims(),
			input: func(t *testing.T) ControlInput {
				input := authorizationInput(t, raw, "issue-key")
				input.ETag = `"` + authorizationRunID + `:v2"`
				return input
			},
			body:   raw,
			expect: problem.CodeRequestInvalid,
		},
		"a command naming another run is refused": {
			claims: issuerClaims(),
			input:  func(t *testing.T) ControlInput { return authorizationInput(t, mismatchedRunBody(), "issue-key") },
			body:   mismatchedRunBody(),
			expect: problem.CodeRequestInvalid,
		},
		"a command carrying a caller-owned server field is structurally refused": {
			claims: issuerClaims(),
			input:  func(t *testing.T) ControlInput { return authorizationInput(t, forgedIssuerBody(), "issue-key") },
			body:   forgedIssuerBody(),
			expect: problem.CodeRequestInvalid,
		},
		"a digest that does not cover the command is refused": {
			claims: issuerClaims(),
			input: func(t *testing.T) ControlInput {
				input := authorizationInput(t, raw, "issue-key")
				input.Digest = authorizationDigest("f")
				return input
			},
			body:   raw,
			expect: problem.CodeRequestInvalid,
		},
		"an issuance with no idempotency key is refused": {
			claims: issuerClaims(),
			input: func(t *testing.T) ControlInput {
				input := authorizationInput(t, raw, "issue-key")
				input.Key = ""
				return input
			},
			body:   raw,
			expect: problem.CodeRequestInvalid,
		},
	} {
		t.Run(name, func(t *testing.T) {
			issuer := &recordingIssuer{issued: signedCapability(t)}
			app, _ := authorizationApp(t, issuer)
			_, err := app.IssueApplyAuthorization(context.Background(), attempt.claims, attempt.input(t), attempt.body)
			if !isProblem(err, attempt.expect) {
				t.Fatalf("error = %v, want %s", err, attempt.expect)
			}
			if len(issuer.intents) != 0 {
				t.Fatalf("a refused request reached the issuance path %d times", len(issuer.intents))
			}
		})
	}
}

func mismatchedRunBody() []byte {
	return []byte(strings.Replace(string(authorizationBody()), `"runId":"`+authorizationRunID+`"`, `"runId":"another-run"`, 1))
}

func forgedIssuerBody() []byte {
	return []byte(strings.Replace(string(authorizationBody()), `"kind":"IssueApplyAuthorizationRequest"`, `"kind":"IssueApplyAuthorizationRequest","issuer":"urn:anvilkit:issuer:attacker"`, 1))
}

// A refused issuance releases the key, so the caller can correct the request
// and try again rather than being left with a key that can never be used.
func TestARefusedIssuanceLeavesItsKeyUsable(t *testing.T) {
	issuer := &recordingIssuer{err: problem.New(problem.CodeApplyAuthorizationDenied, "")}
	app, _ := authorizationApp(t, issuer)
	raw := authorizationBody()
	if _, err := app.IssueApplyAuthorization(context.Background(), issuerClaims(), authorizationInput(t, raw, "issue-key"), raw); !isProblem(err, problem.CodeApplyAuthorizationDenied) {
		t.Fatalf("error = %v", err)
	}
	issuer.err = nil
	issuer.issued = signedCapability(t)
	if _, err := app.IssueApplyAuthorization(context.Background(), issuerClaims(), authorizationInput(t, raw, "issue-key"), raw); err != nil {
		t.Fatalf("the retry could not reuse its key: %v", err)
	}
}

// An unbound issuance path answers as unavailable rather than as absent: a
// caller must not learn from a 404 that a deployment simply has not composed
// this capability.
func TestAnUnboundIssuancePathAnswersAsUnavailable(t *testing.T) {
	app, _ := authorizationApp(t, &recordingIssuer{})
	app.WithApplyAuthorization(nil, nil)
	raw := authorizationBody()
	_, err := app.IssueApplyAuthorization(context.Background(), issuerClaims(), authorizationInput(t, raw, "issue-key"), raw)
	if !isProblem(err, problem.CodeInfrastructureUnavailable) {
		t.Fatalf("error = %v, want the unavailable answer", err)
	}
}

// recordingMetadata stands in for the execution pipeline's governed metadata
// surface.
type recordingMetadata struct {
	record      artifacts.Record
	err         error
	scopes      []runs.Scope
	ids         []artifacts.ID
	disclosures []execution.ArtifactDisclosure
}

func (m *recordingMetadata) ArtifactMetadata(_ context.Context, scope runs.Scope, id artifacts.ID, disclosure execution.ArtifactDisclosure) (execution.GovernedArtifact, error) {
	m.scopes, m.ids, m.disclosures = append(m.scopes, scope), append(m.ids, id), append(m.disclosures, disclosure)
	if m.err != nil {
		return execution.GovernedArtifact{}, m.err
	}
	return execution.GovernedArtifact{Record: m.record}, nil
}

func governedArtifactRecord() artifacts.Record {
	moment := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	return artifacts.Record{
		WorkspaceID: "workspace", ProjectID: "project", RunID: authorizationRunID,
		ID:     artifacts.ID(authorizationArtifact),
		Kind:   artifacts.WorkerResult,
		Digest: authorizationDigest("a"),
		Reference: artifacts.Reference{
			Bucket: "anvilkit-agent-artifacts", ObjectKey: "workspace/project/run/artifact.json",
			SizeBytes: 128, MediaType: "application/json",
		},
		Schema: artifacts.SchemaIdentity{Component: "anvilkit.contract.schema.agent-artifact", Version: "canonical", Digest: authorizationDigest("b")},
		Lineage: artifacts.Lineage{
			RunID: authorizationRunID, TaskID: "task.0001", PhysicalAttemptID: "attempt.0001",
			Producer: artifacts.Producer{TaskID: "task.0001", PhysicalAttemptID: "attempt.0001", RecoveryEpoch: 1, ExecutionGeneration: 1, LeaseEpoch: 1},
		},
		Validation: artifacts.Validation{
			ValidatedAt: moment,
			Checks:      []artifacts.Check{{Name: "schema", Result: "passed", EvidenceDigest: authorizationDigest("b")}},
		},
		State: artifacts.Finalized, Version: 3, SecurityGeneration: 1,
		CreatedAt: moment, UpdatedAt: moment,
	}
}

func metadataApp(t *testing.T, reader ArtifactMetadataReader) *App {
	t.Helper()
	now := time.Now()
	validator, err := auth.NewValidator(auth.Config{Issuers: []string{"issuer"}, Audience: "agent", MaximumClockSkew: time.Second}, trust{}, clock{now})
	if err != nil {
		t.Fatal(err)
	}
	runStore := &store{snapshot: runs.Snapshot{RunID: authorizationRunID, WorkspaceID: "workspace", Version: 3}}
	app := New(validator, runs.NewService(runStore, starter{}, ids{}, clock{now}, journal.NewMemoryStore(), runs.AdmitFunc(func(context.Context, runs.Scope) error { return nil })), eventReader{}, events.StreamConfig{}, appAuthoritySource{}, testGuard(t), testDefinitions{})
	return app.WithArtifactMetadata(reader)
}

func readerClaims() auth.Claims {
	return auth.Claims{
		Verified: true, Source: auth.SourceWorkload, Issuer: "issuer", Audience: "agent",
		Subject: "reader-actor", ActorID: "reader-actor", WorkspaceID: "workspace", ProjectID: "project",
		Purpose: "agent", KeyID: "key", Scopes: []string{auth.ScopeRead},
		ExpiresAt: time.Now().Add(time.Hour),
	}
}

// The governed metadata read answers the canonical representation, proved
// against its pinned contract before it leaves, and confines the lookup to the
// caller's own tenant.
func TestReadingAnArtifactAnswersTheCanonicalRepresentation(t *testing.T) {
	reader := &recordingMetadata{record: governedArtifactRecord()}
	app := metadataApp(t, reader)
	result, err := app.GetArtifact(context.Background(), readerClaims(), ArtifactInput{WorkspaceID: "workspace", ArtifactID: authorizationArtifact, Purpose: string(artifacts.ReadAccess), Traceparent: authorizationTrace})
	if err != nil {
		t.Fatalf("a governed metadata read was refused: %v", err)
	}
	var representation map[string]any
	if err := json.Unmarshal(result.Body, &representation); err != nil {
		t.Fatal(err)
	}
	if representation["contractType"] != AgentArtifactKind || representation["artifactId"] != authorizationArtifact {
		t.Fatalf("the representation is not the canonical artifact: %s", result.Body)
	}
	if representation["kind"] != string(artifacts.WorkerResult) || representation["lifecycle"] != string(artifacts.Finalized) {
		t.Fatalf("the representation does not carry what the artifact is: %s", result.Body)
	}
	if result.ETag != governedArtifactRecord().ETag() {
		t.Fatalf("the representation does not name the revision it stands at: %q", result.ETag)
	}
	// The purpose the caller declared reaches the pipeline verbatim, because
	// that is what gets recorded: a purpose transport rewrote is not the one
	// anybody stated.
	if len(reader.disclosures) != 1 || reader.disclosures[0].Purpose != string(artifacts.ReadAccess) || reader.disclosures[0].Traceparent != authorizationTrace {
		t.Fatalf("the declared disclosure did not reach the pipeline: %+v", reader.disclosures)
	}
	// The project the lookup ran in came from the verified authority, never
	// from the path — which is what confines it to the caller's tenant.
	if len(reader.scopes) != 1 || reader.scopes[0].WorkspaceID != "workspace" || reader.scopes[0].ProjectID != "project" || reader.scopes[0].ActorID != "reader-actor" {
		t.Fatalf("the read was not confined to the caller's own scope: %+v", reader.scopes)
	}
}

// Reading an artifact fails closed on every way the request can be wrong, and
// a workspace the caller does not hold is absent rather than denied.
func TestReadingAnArtifactFailsClosed(t *testing.T) {
	for name, attempt := range map[string]struct {
		claims auth.Claims
		input  ArtifactInput
		reader *recordingMetadata
		expect problem.Code
	}{
		"another tenant's workspace is absent rather than denied": {
			claims: readerClaims(),
			input:  ArtifactInput{WorkspaceID: "other-workspace", ArtifactID: authorizationArtifact, Purpose: string(artifacts.ReadAccess), Traceparent: authorizationTrace},
			reader: &recordingMetadata{record: governedArtifactRecord()},
			expect: problem.CodeResourceNotFound,
		},
		"an unauthenticated caller is refused": {
			claims: auth.Claims{},
			input:  ArtifactInput{WorkspaceID: "workspace", ArtifactID: authorizationArtifact, Purpose: string(artifacts.ReadAccess), Traceparent: authorizationTrace},
			reader: &recordingMetadata{record: governedArtifactRecord()},
			expect: problem.CodeAuthenticationInvalid,
		},
		"an unbounded artifact identity is refused": {
			claims: readerClaims(),
			input:  ArtifactInput{WorkspaceID: "workspace", ArtifactID: strings.Repeat("x", 129), Purpose: string(artifacts.ReadAccess), Traceparent: authorizationTrace},
			reader: &recordingMetadata{record: governedArtifactRecord()},
			expect: problem.CodeRequestInvalid,
		},
		"a caller whose authority no longer stands is denied": {
			claims: readerClaims(),
			input:  ArtifactInput{WorkspaceID: "workspace", ArtifactID: authorizationArtifact, Purpose: string(artifacts.ReadAccess), Traceparent: authorizationTrace},
			reader: &recordingMetadata{err: problem.New(problem.CodeArtifactAccessDenied, "")},
			expect: problem.CodeArtifactAccessDenied,
		},
		"a read declaring no purpose is refused": {
			claims: readerClaims(),
			input:  ArtifactInput{WorkspaceID: "workspace", ArtifactID: authorizationArtifact, Traceparent: authorizationTrace},
			reader: &recordingMetadata{record: governedArtifactRecord()},
			expect: problem.CodeRequestInvalid,
		},
		"a purpose outside the governed vocabulary is refused": {
			claims: readerClaims(),
			input:  ArtifactInput{WorkspaceID: "workspace", ArtifactID: authorizationArtifact, Purpose: "exfiltration", Traceparent: authorizationTrace},
			reader: &recordingMetadata{record: governedArtifactRecord()},
			expect: problem.CodeRequestInvalid,
		},
		"a read with no trace to record the disclosure under is refused": {
			claims: readerClaims(),
			input:  ArtifactInput{WorkspaceID: "workspace", ArtifactID: authorizationArtifact, Purpose: string(artifacts.ReadAccess)},
			reader: &recordingMetadata{record: governedArtifactRecord()},
			expect: problem.CodeRequestInvalid,
		},
		"a destroyed artifact is absent": {
			claims: readerClaims(),
			input:  ArtifactInput{WorkspaceID: "workspace", ArtifactID: authorizationArtifact, Purpose: string(artifacts.ReadAccess), Traceparent: authorizationTrace},
			reader: &recordingMetadata{err: problem.New(problem.CodeResourceNotFound, "")},
			expect: problem.CodeResourceNotFound,
		},
	} {
		t.Run(name, func(t *testing.T) {
			app := metadataApp(t, attempt.reader)
			if _, err := app.GetArtifact(context.Background(), attempt.claims, attempt.input); !isProblem(err, attempt.expect) {
				t.Fatalf("error = %v, want %s", err, attempt.expect)
			}
		})
	}
}

// An unbound metadata surface answers as unavailable rather than as absent.
func TestAnUnboundArtifactMetadataSurfaceAnswersAsUnavailable(t *testing.T) {
	app := metadataApp(t, &recordingMetadata{record: governedArtifactRecord()})
	app.WithArtifactMetadata(nil)
	_, err := app.GetArtifact(context.Background(), readerClaims(), ArtifactInput{WorkspaceID: "workspace", ArtifactID: authorizationArtifact, Purpose: string(artifacts.ReadAccess), Traceparent: authorizationTrace})
	if !isProblem(err, problem.CodeInfrastructureUnavailable) {
		t.Fatalf("error = %v, want the unavailable answer", err)
	}
}
