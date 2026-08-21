package runapp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/agent"
	"github.com/ancyloce/anvilkit-agent-service/internal/auth"
	"github.com/ancyloce/anvilkit-agent-service/internal/authority"
	"github.com/ancyloce/anvilkit-agent-service/internal/canonical"
	contractguard "github.com/ancyloce/anvilkit-agent-service/internal/contracts"
	"github.com/ancyloce/anvilkit-agent-service/internal/events"
	"github.com/ancyloce/anvilkit-agent-service/internal/execution"
	"github.com/ancyloce/anvilkit-agent-service/internal/journal"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/runs"
)

func testGuard(t *testing.T) *contractguard.Guard {
	t.Helper()
	guard, err := contractguard.NewGuard("../..")
	if err != nil {
		t.Fatal(err)
	}
	return guard
}

// testDefinitions resolves exactly the definition the test authority pins.
type testDefinitions struct{}

func (testDefinitions) Resolve(reference agent.DefinitionReference) (agent.Definition, error) {
	if reference.DefinitionID != "definition.test" || reference.DefinitionDigest != "sha256:"+strings.Repeat("a", 64) {
		return agent.Definition{}, fmt.Errorf("unknown definition")
	}
	return agent.Definition{DefinitionID: reference.DefinitionID, DefinitionDigest: reference.DefinitionDigest}, nil
}

type clock struct{ now time.Time }

func (c clock) Now() time.Time { return c.now }

type trust struct{}

func (trust) KeyActive(context.Context, string) (bool, error)                { return true, nil }
func (trust) SubjectActive(context.Context, string) (bool, error)            { return true, nil }
func (trust) DelegationActive(context.Context, string, string) (bool, error) { return true, nil }

type store struct {
	snapshot        runs.Snapshot
	transitionCalls int
}

func (s *store) Create(_ context.Context, record runs.CreateRecord) (runs.CreateOutcome, error) {
	body, err := json.Marshal(record.Snapshot)
	if err != nil {
		return runs.CreateOutcome{}, err
	}
	return runs.CreateOutcome{Snapshot: record.Snapshot, Bytes: body}, nil
}
func (s *store) Get(_ context.Context, scope runs.Scope, _ runs.ID) (runs.Snapshot, error) {
	if scope.WorkspaceID != "workspace" {
		return runs.Snapshot{}, problem.New(problem.CodeResourceNotFound, "")
	}
	return s.snapshot, nil
}
func (s *store) List(context.Context, runs.Scope, runs.ListOptions) (runs.Page, error) {
	return runs.Page{Items: []runs.Snapshot{s.snapshot}}, nil
}
func (s *store) Transition(_ context.Context, _ runs.Scope, _ runs.ID, version uint64, _ runs.Command) (runs.Snapshot, error) {
	if version != s.snapshot.Version {
		return runs.Snapshot{}, problem.New(problem.CodeVersionConflict, "")
	}
	s.transitionCalls++
	s.snapshot.Version++
	return s.snapshot, nil
}

type starter struct{}

func (starter) Ensure(context.Context, runs.Start) error { return nil }

type ids struct{}

func (ids) NewID() (runs.ID, error) { return "run", nil }

type eventReader struct{}

func (eventReader) Replay(context.Context, events.ReplayRequest) (events.ReplayPage, error) {
	return events.ReplayPage{}, nil
}
func (eventReader) Snapshot(context.Context, events.Scope, string) (events.SnapshotProjection, error) {
	return events.SnapshotProjection{Cursor: "cursor"}, nil
}
func (eventReader) Wait(context.Context, events.Scope, string, uint64, time.Duration) error {
	return nil
}

type appAuthoritySource struct{}

func (appAuthoritySource) Current(context.Context, authority.Scope) (authority.Current, error) {
	return testAuthority(), nil
}

// testAuthority is a complete, active current-authority observation.
func testAuthority() authority.Current {
	return authority.Current{
		Definition:       []byte(`{"definitionId":"definition.test","definitionDigest":"sha256:` + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" + `"}`),
		ContractBOM:      []byte(`{"bom":"test"}`),
		Policy:           []byte(`{"policyId":"policy.test","version":"v1"}`),
		Budget:           []byte(`{"budget":"test"}`),
		WorkspaceActive:  true,
		ActorActive:      true,
		PermissionActive: true,
		PolicyActive:     true,
	}
}

func TestServerScopeComesOnlyFromVerifiedClaimsAndCrossWorkspaceIs404(t *testing.T) {
	now := time.Now()
	validator, _ := auth.NewValidator(auth.Config{Issuers: []string{"issuer"}, Audience: "agent", MaximumClockSkew: time.Second}, trust{}, clock{now})
	runStore := &store{snapshot: runs.Snapshot{RunID: "run", WorkspaceID: "workspace", Version: 3}}
	app := New(validator, runs.NewService(runStore, starter{}, ids{}, clock{now}, journal.NewMemoryStore(), runs.AdmitFunc(func(context.Context, runs.Scope) error { return nil })), eventReader{}, events.StreamConfig{Heartbeat: time.Second, Revalidation: time.Second, ReplayLimit: 10, Bounds: events.Bounds{MaximumBytes: 1000, MaximumFields: 10, MaximumFieldBytes: 100}}, appAuthoritySource{}, testGuard(t), testDefinitions{})
	claims := auth.Claims{Verified: true, Source: auth.SourceWorkload, Issuer: "issuer", Audience: "agent", Subject: "actor", ActorID: "actor", WorkspaceID: "workspace", ProjectID: "project", Purpose: "agent", KeyID: "key", Scopes: []string{auth.ScopeRead, auth.ScopeWrite}, ExpiresAt: now.Add(time.Hour)}
	result, err := app.Get(context.Background(), claims, "workspace", "run")
	if err != nil || result.ETag != `"run:v3"` {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	_, err = app.Get(context.Background(), claims, "other", "run")
	assertProblem(t, err, problem.CodeResourceNotFound)
	browser := claims
	browser.Source = auth.SourceBrowser
	_, err = app.Get(context.Background(), browser, "workspace", "run")
	assertProblem(t, err, problem.CodeAuthenticationInvalid)
}

func TestStrongETagPreconditionAllowsOneMutation(t *testing.T) {
	now := time.Now()
	validator, _ := auth.NewValidator(auth.Config{Issuers: []string{"issuer"}, Audience: "agent"}, trust{}, clock{now})
	runStore := &store{snapshot: runs.Snapshot{RunID: "run", WorkspaceID: "workspace", Version: 3}}
	app := New(validator, runs.NewService(runStore, starter{}, ids{}, clock{now}, journal.NewMemoryStore(), runs.AdmitFunc(func(context.Context, runs.Scope) error { return nil })), eventReader{}, events.StreamConfig{}, appAuthoritySource{}, testGuard(t), testDefinitions{})
	claims := auth.Claims{Verified: true, Source: auth.SourceWorkload, Issuer: "issuer", Audience: "agent", Subject: "actor", ActorID: "actor", WorkspaceID: "workspace", ProjectID: "project", Purpose: "agent", KeyID: "key", Scopes: []string{auth.ScopeWrite}, ExpiresAt: now.Add(time.Hour)}
	first, err := app.Transition(context.Background(), claims, auth.OpCancel, "workspace", "run", `"run:v3"`, runs.Command{Kind: runs.RequestCancellation, Traceparent: "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"})
	if err != nil || first.ETag != `"run:v4"` {
		t.Fatalf("first=%#v err=%v", first, err)
	}
	_, err = app.Transition(context.Background(), claims, auth.OpCancel, "workspace", "run", `"run:v3"`, runs.Command{Kind: runs.RequestCancellation, Traceparent: "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"})
	assertProblem(t, err, problem.CodeVersionConflict)
	if runStore.transitionCalls != 1 {
		t.Fatalf("transition calls=%d", runStore.transitionCalls)
	}
}

func assertProblem(t *testing.T, err error, code problem.Code) {
	t.Helper()
	var details problem.Details
	if !errors.As(err, &details) || details.Code != string(code) {
		t.Fatalf("got %v want %s", err, code)
	}
}

// TestCreateCommandCanonicalGovernance proves the create boundary enforces
// the canonical CreateAgentRunRequest wire contract, the declared target
// scope, and the approved definition binding — and that a missing concurrency
// precondition answers 428 while a stale one answers 412.
func TestCreateCommandCanonicalGovernance(t *testing.T) {
	now := time.Now()
	validator, _ := auth.NewValidator(auth.Config{Issuers: []string{"issuer"}, Audience: "agent", MaximumClockSkew: time.Second}, trust{}, clock{now})
	runStore := &store{snapshot: runs.Snapshot{RunID: "run", WorkspaceID: "workspace", Version: 3}}
	app := New(validator, runs.NewService(runStore, starter{}, ids{}, clock{now}, journal.NewMemoryStore(), runs.AdmitFunc(func(context.Context, runs.Scope) error { return nil })), eventReader{}, events.StreamConfig{}, appAuthoritySource{}, testGuard(t), testDefinitions{})
	claims := auth.Claims{Verified: true, Source: auth.SourceWorkload, Issuer: "issuer", Audience: "agent", Subject: "actor", ActorID: "actor", WorkspaceID: "workspace", ProjectID: "project", Purpose: "agent", KeyID: "key", Scopes: []string{auth.ScopeRead, auth.ScopeWrite}, ExpiresAt: now.Add(time.Hour)}
	trace := "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"
	body := func(projectID, definitionDigest string) []byte {
		return []byte(`{"kind":"CreateAgentRunRequest","definition":{"definitionId":"definition.test","definitionDigest":"` + definitionDigest + `"},"operation":"page-change","target":{"targetType":"page","targetId":"page-1","workspaceId":"workspace","projectId":"` + projectID + `"}}`)
	}
	digestOf := func(raw []byte) string {
		t.Helper()
		digest, err := canonical.Digest(raw)
		if err != nil {
			t.Fatal(err)
		}
		return digest
	}
	pinnedDigest := "sha256:" + strings.Repeat("a", 64)
	valid := body("project", pinnedDigest)
	if _, err := app.Create(context.Background(), claims, "workspace", "key-1", digestOf(valid), trace, valid); err != nil {
		t.Fatalf("canonical create failed: %v", err)
	}
	smuggled := []byte(`{"kind":"CreateAgentRunRequest","runId":"run-1","definition":{"definitionId":"definition.test","definitionDigest":"` + pinnedDigest + `"},"operation":"page-change","target":{"targetType":"page","targetId":"page-1","workspaceId":"workspace","projectId":"project"}}`)
	_, err := app.Create(context.Background(), claims, "workspace", "key-2", digestOf(smuggled), trace, smuggled)
	assertProblem(t, err, problem.CodeRequestInvalid)
	foreign := body("other-project", pinnedDigest)
	_, err = app.Create(context.Background(), claims, "workspace", "key-3", digestOf(foreign), trace, foreign)
	assertProblem(t, err, problem.CodeAuthorizationDenied)
	unapproved := body("project", "sha256:"+strings.Repeat("b", 64))
	_, err = app.Create(context.Background(), claims, "workspace", "key-4", digestOf(unapproved), trace, unapproved)
	assertProblem(t, err, problem.CodeContractInvalid)
	_, err = app.Transition(context.Background(), claims, auth.OpCancel, "workspace", "run", "", runs.Command{Kind: runs.RequestCancellation, Traceparent: trace})
	assertProblem(t, err, problem.CodePreconditionRequired)
	if definition, ok := problem.Lookup(problem.CodePreconditionRequired); !ok || definition.Status != 428 {
		t.Fatalf("PRECONDITION_REQUIRED must answer 428, got %+v", definition)
	}
	if definition, ok := problem.Lookup(problem.CodeVersionConflict); !ok || definition.Status != 412 {
		t.Fatalf("VERSION_CONFLICT must answer 412, got %+v", definition)
	}
}

// recordingResolver captures the scoped command the application derived, so a
// test can prove the resolving operator came from verified authority rather
// than from the request body.
type recordingResolver struct {
	calls      int
	authorized int
	denial     error
	scope      runs.Scope
	command    execution.OperatorResolution
	snapshot   runs.Snapshot
}

// AuthorizeOperatorRecovery stands in for the pipeline's current-authority
// re-read. The denial it is armed with is what a revoked operator would meet
// on a later request, so a test can prove the boundary consults it before any
// recorded outcome is answered.
func (r *recordingResolver) AuthorizeOperatorRecovery(context.Context, runs.Scope, runs.ID) error {
	r.authorized++
	return r.denial
}

func (r *recordingResolver) ResolveEscalation(_ context.Context, scope runs.Scope, _ runs.ID, _ uint64, command execution.OperatorResolution) (runs.Snapshot, error) {
	r.calls++
	r.scope, r.command = scope, command
	return r.snapshot, nil
}

// TestResolveEscalationCommandCanonicalGovernance proves the operator recovery
// boundary enforces the canonical ResolveDomainOperationRequest wire contract
// before it decodes anything, binds the decision to the addressed operation,
// and derives the resolving operator from verified authority — so a caller can
// neither smuggle an operator identity nor decide an operation it did not
// address.
func TestResolveEscalationCommandCanonicalGovernance(t *testing.T) {
	now := time.Now()
	validator, _ := auth.NewValidator(auth.Config{Issuers: []string{"issuer"}, Audience: "agent", MaximumClockSkew: time.Second}, trust{}, clock{now})
	runStore := &store{snapshot: runs.Snapshot{RunID: "run", WorkspaceID: "workspace", Version: 3}}
	resolver := &recordingResolver{snapshot: runs.Snapshot{RunID: "run", WorkspaceID: "workspace", Version: 4}}
	app := New(validator, runs.NewService(runStore, starter{}, ids{}, clock{now}, journal.NewMemoryStore(), runs.AdmitFunc(func(context.Context, runs.Scope) error { return nil })), eventReader{}, events.StreamConfig{}, appAuthoritySource{}, testGuard(t), testDefinitions{})
	app.WithEscalations(resolver, NewMemoryCommandReceipts(func() time.Time { return now }, time.Minute))
	trace := "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"
	operationID := "domain.0123456789abcdef0123456789abcdef"
	operator := auth.Claims{Verified: true, Source: auth.SourceWorkload, Issuer: "issuer", Audience: "agent", Subject: "operator", ActorID: "operator", WorkspaceID: "workspace", ProjectID: "project", Purpose: "agent", KeyID: "key", Scopes: []string{auth.ScopeOperator}, ExpiresAt: now.Add(time.Hour)}
	digestOf := func(raw []byte) string {
		t.Helper()
		digest, err := canonical.Digest(raw)
		if err != nil {
			t.Fatal(err)
		}
		return digest
	}
	call := func(claims auth.Claims, addressed string, raw []byte) error {
		t.Helper()
		_, err := app.ResolveEscalation(context.Background(), claims, ControlInput{
			WorkspaceID: "workspace",
			RunID:       "run",
			ETag:        `"run:v3"`,
			Key:         "operator-key",
			Digest:      digestOf(raw),
			Traceparent: trace,
		}, addressed, raw)
		return err
	}

	canonicalBody := []byte(`{"kind":"ResolveDomainOperationRequest","operationId":"` + operationID + `","outcome":"rejected","basis":"` + testEvidenceBasis + `"}`)
	if err := call(operator, operationID, canonicalBody); err != nil {
		t.Fatalf("canonical resolution failed: %v", err)
	}
	if resolver.calls != 1 || resolver.command.OperationID != operationID || resolver.command.Outcome != "rejected" {
		t.Fatalf("resolver command = %+v calls=%d", resolver.command, resolver.calls)
	}
	// The resolving operator is the verified actor, never a body field.
	if resolver.command.OperatorID != "operator" || resolver.scope.ActorID != "operator" {
		t.Fatalf("operator identity = %q scope actor = %q, want the verified actor", resolver.command.OperatorID, resolver.scope.ActorID)
	}

	// A body smuggling a resolving operator is structurally rejected by the
	// canonical contract before anything is decoded.
	smuggled := []byte(`{"kind":"ResolveDomainOperationRequest","operationId":"` + operationID + `","outcome":"rejected","basis":"` + testEvidenceBasis + `","resolvedBy":"operator.impersonated"}`)
	assertProblem(t, call(operator, operationID, smuggled), problem.CodeRequestInvalid)
	// So is a foreign discriminator, an outcome outside the domain vocabulary,
	// a missing field, and — because the basis is a bounded evidence reference
	// rather than free text — an empty basis, operator prose, and a reference
	// outside the canonical form.
	for name, raw := range map[string][]byte{
		"wrong-kind":       []byte(`{"kind":"SubmitApprovalDecisionRequest","operationId":"` + operationID + `","outcome":"rejected","basis":"` + testEvidenceBasis + `"}`),
		"bad-outcome":      []byte(`{"kind":"ResolveDomainOperationRequest","operationId":"` + operationID + `","outcome":"settled-somehow","basis":"` + testEvidenceBasis + `"}`),
		"blank-basis":      []byte(`{"kind":"ResolveDomainOperationRequest","operationId":"` + operationID + `","outcome":"rejected","basis":""}`),
		"missing-basis":    []byte(`{"kind":"ResolveDomainOperationRequest","operationId":"` + operationID + `","outcome":"rejected"}`),
		"prose-basis":      []byte(`{"kind":"ResolveDomainOperationRequest","operationId":"` + operationID + `","outcome":"rejected","basis":"the owner has no record of the operation, see ticket OPS-7"}`),
		"foreign-scheme":   []byte(`{"kind":"ResolveDomainOperationRequest","operationId":"` + operationID + `","outcome":"rejected","basis":"https://audit.example.com/OPS-7-no-record"}`),
		"authorityless":    []byte(`{"kind":"ResolveDomainOperationRequest","operationId":"` + operationID + `","outcome":"rejected","basis":"anvilkit://evidence/OPS-7-no-record-of-the-operation"}`),
		"uppercase-issuer": []byte(`{"kind":"ResolveDomainOperationRequest","operationId":"` + operationID + `","outcome":"rejected","basis":"anvilkit://evidence/Domain-Owner-Audit/OPS-7-no-record"}`),
	} {
		if err := call(operator, operationID, raw); !isProblem(err, problem.CodeRequestInvalid) {
			t.Fatalf("%s was accepted: %v", name, err)
		}
	}

	// A decision whose body names a different operation than the resource it
	// addresses is refused rather than redirected.
	elsewhere := []byte(`{"kind":"ResolveDomainOperationRequest","operationId":"domain.ffffffffffffffffffffffffffffffff","outcome":"rejected","basis":"` + testEvidenceBasis + `"}`)
	assertProblem(t, call(operator, operationID, elsewhere), problem.CodeRequestInvalid)

	// The operate scope is required; a run writer cannot decide an escalation.
	writer := operator
	writer.Scopes = []string{auth.ScopeWrite}
	assertProblem(t, call(writer, operationID, canonicalBody), problem.CodeAuthorizationDenied)

	// A digest that does not match the canonical command bytes is refused.
	_, err := app.ResolveEscalation(context.Background(), operator, ControlInput{
		WorkspaceID: "workspace", RunID: "run", ETag: `"run:v3"`, Key: "operator-key",
		Digest: "sha256:" + strings.Repeat("c", 64), Traceparent: trace,
	}, operationID, canonicalBody)
	assertProblem(t, err, problem.CodeRequestInvalid)

	if resolver.calls != 1 {
		t.Fatalf("resolver reached %d times, want only the canonical command", resolver.calls)
	}
}

func isProblem(err error, code problem.Code) bool {
	var details problem.Details
	return errors.As(err, &details) && details.Code == string(code)
}
