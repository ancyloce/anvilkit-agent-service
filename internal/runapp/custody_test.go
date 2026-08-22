package runapp

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/artifacts"
	"github.com/ancyloce/anvilkit-agent-service/internal/auth"
	"github.com/ancyloce/anvilkit-agent-service/internal/canonical"
	"github.com/ancyloce/anvilkit-agent-service/internal/events"
	"github.com/ancyloce/anvilkit-agent-service/internal/journal"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/runs"
)

const custodyArtifactID = "artifact.0123456789abcdef0123456789abcdef"
const custodyTrace = "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"
const custodyBasis = "anvilkit://evidence/records-retention-review/LEGAL-114-hold-instruction"

// recordingCustodian records exactly what the boundary asked the artifact
// lifecycle to do, so a test can prove which identity and which tenant the
// decision was made under rather than only that it succeeded.
type recordingCustodian struct {
	lock               sync.Mutex
	holds, deletes     int
	workspace, project string
	id                 artifacts.ID
	expected           uint64
	hold               bool
	custody            artifacts.Custody
	failWith           error
}

func (c *recordingCustodian) record(workspace, project string, id artifacts.ID, expected uint64, custody artifacts.Custody) (artifacts.Record, error) {
	c.workspace, c.project, c.id, c.expected, c.custody = workspace, project, id, expected, custody
	if c.failWith != nil {
		return artifacts.Record{}, c.failWith
	}
	return artifacts.Record{WorkspaceID: workspace, ProjectID: project, ID: id, Version: expected + 1}, nil
}

func (c *recordingCustodian) SetLegalHold(_ context.Context, workspace, project string, id artifacts.ID, expected uint64, hold bool, custody artifacts.Custody, _ time.Time) (artifacts.Record, error) {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.holds++
	c.hold = hold
	return c.record(workspace, project, id, expected, custody)
}

func (c *recordingCustodian) Delete(_ context.Context, workspace, project string, id artifacts.ID, expected uint64, custody artifacts.Custody, _ time.Time) (artifacts.Record, error) {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.deletes++
	return c.record(workspace, project, id, expected, custody)
}

func (c *recordingCustodian) calls() (int, int) {
	c.lock.Lock()
	defer c.lock.Unlock()
	return c.holds, c.deletes
}

func custodyApp(t *testing.T, custodian ArtifactCustodian) (*App, *MemoryCommandReceipts) {
	t.Helper()
	now := time.Now()
	validator, err := auth.NewValidator(auth.Config{Issuers: []string{"issuer"}, Audience: "agent", MaximumClockSkew: time.Second}, trust{}, clock{now})
	if err != nil {
		t.Fatal(err)
	}
	runStore := &store{snapshot: runs.Snapshot{RunID: "run", WorkspaceID: "workspace", Version: 3}}
	app := New(validator, runs.NewService(runStore, starter{}, ids{}, clock{now}, journal.NewMemoryStore(), runs.AdmitFunc(func(context.Context, runs.Scope) error { return nil })), eventReader{}, events.StreamConfig{}, appAuthoritySource{}, testGuard(t), testDefinitions{})
	receipts := NewMemoryCommandReceipts(func() time.Time { return now }, time.Minute)
	app.WithArtifactCustody(custodian, receipts, func() time.Time { return now })
	return app, receipts
}

func custodianClaims() auth.Claims {
	return auth.Claims{
		Verified: true, Source: auth.SourceWorkload, Issuer: "issuer", Audience: "agent",
		Subject: "custodian", ActorID: "custodian", WorkspaceID: "workspace", ProjectID: "project",
		Purpose: "agent", KeyID: "key", Scopes: []string{auth.ScopeCustodian},
		ExpiresAt: time.Now().Add(time.Hour),
	}
}

func custodyBody(decision string) []byte {
	return []byte(`{"kind":"DecideArtifactCustodyRequest","artifactId":"` + custodyArtifactID + `","decision":"` + decision + `","basis":"` + custodyBasis + `","ticket":"CHG-2291"}`)
}

func custodyDigest(t *testing.T, raw []byte) string {
	t.Helper()
	digest, err := canonical.Digest(raw)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func custodyInput(t *testing.T, raw []byte, key string) CustodyInput {
	t.Helper()
	return CustodyInput{
		WorkspaceID: "workspace",
		ArtifactID:  custodyArtifactID,
		ETag:        `"` + custodyArtifactID + `:v3"`,
		Key:         key,
		Digest:      custodyDigest(t, raw),
		Traceparent: custodyTrace,
	}
}

// An authorized custody decision reaches the artifact lifecycle, and reaches
// it under the identity the verified request authority projected: the actor,
// the workspace, and the project all come from the token, never from the
// command, and the command's accountability fields are carried through intact.
func TestAnAuthorizedCustodyDecisionReachesTheArtifactLifecycle(t *testing.T) {
	for _, testCase := range []struct {
		decision       string
		holds, deletes int
		hold           bool
	}{
		{decision: CustodyLegalHoldPlaced, holds: 1, hold: true},
		{decision: CustodyLegalHoldLifted, holds: 1},
		{decision: CustodyDeleted, deletes: 1},
	} {
		t.Run(testCase.decision, func(t *testing.T) {
			custodian := &recordingCustodian{}
			app, _ := custodyApp(t, custodian)
			raw := custodyBody(testCase.decision)
			result, err := app.DecideArtifactCustody(context.Background(), custodianClaims(), custodyInput(t, raw, "custody-key"), raw)
			if err != nil {
				t.Fatalf("an authorized custody decision was refused: %v", err)
			}
			if len(result.Body) != 0 || result.ETag != `"`+custodyArtifactID+`:v4"` {
				t.Fatalf("result = %+v, want the new revision and no representation", result)
			}
			holds, deletes := custodian.calls()
			if holds != testCase.holds || deletes != testCase.deletes || custodian.hold != testCase.hold {
				t.Fatalf("holds=%d deletes=%d hold=%v, want %d/%d/%v", holds, deletes, custodian.hold, testCase.holds, testCase.deletes, testCase.hold)
			}
			if custodian.workspace != "workspace" || custodian.project != "project" || custodian.id != custodyArtifactID || custodian.expected != 3 {
				t.Fatalf("scope = %s/%s/%s@%d, want the verified tenant and the pinned revision", custodian.workspace, custodian.project, custodian.id, custodian.expected)
			}
			if custodian.custody.ActorID != "custodian" || custodian.custody.Workload != custodyWorkload {
				t.Fatalf("custody identity = %+v, want the verified actor under the server-owned workload", custodian.custody)
			}
			if custodian.custody.Reason != custodyBasis || custodian.custody.Ticket != "CHG-2291" || custodian.custody.Traceparent != custodyTrace {
				t.Fatalf("custody accountability = %+v, want the command's basis, ticket, and trace", custodian.custody)
			}
		})
	}
}

// Nothing about who is deciding, or where, may come from the command. Each
// body below smuggles a server-owned field, and the canonical contract rejects
// every one of them structurally — before anything is decoded, and long before
// the artifact lifecycle is reached.
func TestACustodyCommandCannotCarryIdentityOrTenant(t *testing.T) {
	custodian := &recordingCustodian{}
	app, _ := custodyApp(t, custodian)
	for name, raw := range map[string][]byte{
		"custodian":  []byte(`{"kind":"DecideArtifactCustodyRequest","artifactId":"` + custodyArtifactID + `","decision":"deleted","basis":"` + custodyBasis + `","ticket":"CHG-2291","custodianId":"custodian.impersonated"}`),
		"actor":      []byte(`{"kind":"DecideArtifactCustodyRequest","artifactId":"` + custodyArtifactID + `","decision":"deleted","basis":"` + custodyBasis + `","ticket":"CHG-2291","actorId":"actor.impersonated"}`),
		"role":       []byte(`{"kind":"DecideArtifactCustodyRequest","artifactId":"` + custodyArtifactID + `","decision":"deleted","basis":"` + custodyBasis + `","ticket":"CHG-2291","actorRole":"agent-artifact-custodian"}`),
		"scope":      []byte(`{"kind":"DecideArtifactCustodyRequest","artifactId":"` + custodyArtifactID + `","decision":"deleted","basis":"` + custodyBasis + `","ticket":"CHG-2291","scope":"workspace"}`),
		"workspace":  []byte(`{"kind":"DecideArtifactCustodyRequest","artifactId":"` + custodyArtifactID + `","decision":"deleted","basis":"` + custodyBasis + `","ticket":"CHG-2291","workspaceId":"workspace.attacker"}`),
		"project":    []byte(`{"kind":"DecideArtifactCustodyRequest","artifactId":"` + custodyArtifactID + `","decision":"deleted","basis":"` + custodyBasis + `","ticket":"CHG-2291","projectId":"project.attacker"}`),
		"capability": []byte(`{"kind":"DecideArtifactCustodyRequest","artifactId":"` + custodyArtifactID + `","decision":"deleted","basis":"` + custodyBasis + `","ticket":"CHG-2291","capability":"artifact-custody.delete"}`),
		"wrong-kind": []byte(`{"kind":"ResolveDomainOperationRequest","artifactId":"` + custodyArtifactID + `","decision":"deleted","basis":"` + custodyBasis + `","ticket":"CHG-2291"}`),
		"decision":   []byte(`{"kind":"DecideArtifactCustodyRequest","artifactId":"` + custodyArtifactID + `","decision":"erased-quietly","basis":"` + custodyBasis + `","ticket":"CHG-2291"}`),
		"prose":      []byte(`{"kind":"DecideArtifactCustodyRequest","artifactId":"` + custodyArtifactID + `","decision":"deleted","basis":"the legal team asked for it, see the thread","ticket":"CHG-2291"}`),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := app.DecideArtifactCustody(context.Background(), custodianClaims(), custodyInput(t, raw, "custody-"+name), raw)
			if !isProblem(err, problem.CodeRequestInvalid) {
				t.Fatalf("a forged command was admitted: %v", err)
			}
		})
	}
	if holds, deletes := custodian.calls(); holds != 0 || deletes != 0 {
		t.Fatalf("a forged command reached the artifact lifecycle: holds=%d deletes=%d", holds, deletes)
	}
}

// The scope the caller presents, the workspace the path addresses, and the
// revision the caller pinned are each checked on their own terms, and a
// workspace the caller has no authority for is answered as absent rather than
// denied: the path cannot be used to learn which workspaces exist.
func TestCustodyRefusesUnscopedForeignAndUnpinnedRequests(t *testing.T) {
	custodian := &recordingCustodian{}
	app, _ := custodyApp(t, custodian)
	raw := custodyBody(CustodyDeleted)
	digest := custodyDigest(t, raw)

	writer := custodianClaims()
	writer.Scopes = []string{auth.ScopeWrite, auth.ScopeRead, auth.ScopeOperator, auth.ScopeReviewer, auth.ScopeEvidence}
	if err := decideErr(app, writer, custodyInput(t, raw, "no-scope"), raw); !isProblem(err, problem.CodeAuthorizationDenied) {
		t.Fatalf("a caller without the custody scope was admitted: %v", err)
	}

	foreign := custodyInput(t, raw, "foreign")
	foreign.WorkspaceID = "workspace.other"
	if err := decideErr(app, custodianClaims(), foreign, raw); !isProblem(err, problem.CodeResourceNotFound) {
		t.Fatalf("a cross-tenant request = %v, want a non-disclosing absence", err)
	}

	unpinned := custodyInput(t, raw, "unpinned")
	unpinned.ETag = ""
	if err := decideErr(app, custodianClaims(), unpinned, raw); !isProblem(err, problem.CodePreconditionRequired) {
		t.Fatalf("an unpinned decision = %v, want a required precondition", err)
	}

	stale := custodyInput(t, raw, "stale")
	stale.ETag = `"` + custodyArtifactID + `:v0"`
	if err := decideErr(app, custodianClaims(), stale, raw); !isProblem(err, problem.CodeVersionConflict) {
		t.Fatalf("a zero revision = %v, want a version conflict", err)
	}

	elsewhere := custodyInput(t, raw, "elsewhere")
	elsewhere.ArtifactID = "artifact.ffffffffffffffffffffffffffffffff"
	elsewhere.ETag = `"artifact.ffffffffffffffffffffffffffffffff:v3"`
	if err := decideErr(app, custodianClaims(), elsewhere, raw); !isProblem(err, problem.CodeRequestInvalid) {
		t.Fatalf("a decision addressed elsewhere = %v, want a refusal", err)
	}

	mismatched := custodyInput(t, raw, "mismatched")
	mismatched.Digest = "sha256:" + strings.Repeat("c", 64)
	if err := decideErr(app, custodianClaims(), mismatched, raw); !isProblem(err, problem.CodeRequestInvalid) {
		t.Fatalf("a mismatched digest = %v, want a refusal", err)
	}
	_ = digest

	if holds, deletes := custodian.calls(); holds != 0 || deletes != 0 {
		t.Fatalf("a refused request reached the artifact lifecycle: holds=%d deletes=%d", holds, deletes)
	}
}

func decideErr(app *App, claims auth.Claims, input CustodyInput, raw []byte) error {
	_, err := app.DecideArtifactCustody(context.Background(), claims, input, raw)
	return err
}

// A custody path that was never composed answers as unavailable rather than as
// absent or, worse, as permitted. Reachability is a composition fact, and a
// service that could not compose the artifact lifecycle has no custody
// surface — it does not have a permissive one.
func TestAnUncomposedCustodyPathFailsClosed(t *testing.T) {
	now := time.Now()
	validator, err := auth.NewValidator(auth.Config{Issuers: []string{"issuer"}, Audience: "agent", MaximumClockSkew: time.Second}, trust{}, clock{now})
	if err != nil {
		t.Fatal(err)
	}
	runStore := &store{snapshot: runs.Snapshot{RunID: "run", WorkspaceID: "workspace", Version: 3}}
	app := New(validator, runs.NewService(runStore, starter{}, ids{}, clock{now}, journal.NewMemoryStore(), runs.AdmitFunc(func(context.Context, runs.Scope) error { return nil })), eventReader{}, events.StreamConfig{}, appAuthoritySource{}, testGuard(t), testDefinitions{})
	raw := custodyBody(CustodyDeleted)
	if err := decideErr(app, custodianClaims(), custodyInput(t, raw, "unbound"), raw); !isProblem(err, problem.CodeInfrastructureUnavailable) {
		t.Fatalf("an uncomposed custody path = %v, want unavailable", err)
	}
	// Half a composition is no composition: the receipt store and the clock
	// are as required as the lifecycle itself.
	app.WithArtifactCustody(&recordingCustodian{}, nil, nil)
	if err := decideErr(app, custodianClaims(), custodyInput(t, raw, "half"), raw); !isProblem(err, problem.CodeInfrastructureUnavailable) {
		t.Fatalf("a half-composed custody path = %v, want unavailable", err)
	}
}

// The custody route keeps the whole receipt contract: an exact replay answers
// with the recorded revision without deciding anything a second time, the same
// key with different bytes is the governed reuse conflict, and a key aimed at
// a different artifact conflicts rather than answering with another artifact's
// outcome.
func TestCustodyReceiptsReplayAndConflict(t *testing.T) {
	custodian := &recordingCustodian{}
	app, _ := custodyApp(t, custodian)
	raw := custodyBody(CustodyLegalHoldPlaced)
	first, err := app.DecideArtifactCustody(context.Background(), custodianClaims(), custodyInput(t, raw, "custody-key"), raw)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := app.DecideArtifactCustody(context.Background(), custodianClaims(), custodyInput(t, raw, "custody-key"), raw)
	if err != nil || !replay.Replayed || replay.ETag != first.ETag {
		t.Fatalf("replay = %+v err=%v, want the recorded revision marked replayed", replay, err)
	}
	if holds, _ := custodian.calls(); holds != 1 {
		t.Fatalf("a replay decided again: holds=%d", holds)
	}

	other := custodyBody(CustodyDeleted)
	if err := decideErr(app, custodianClaims(), custodyInput(t, other, "custody-key"), other); !isProblem(err, problem.CodeIdempotencyKeyReused) {
		t.Fatalf("key reuse with different bytes = %v, want IDEMPOTENCY_KEY_REUSED", err)
	}

	// The addressed artifact is carried in the command as well as the path, so
	// aiming a claimed key at another artifact necessarily changes the bytes
	// it was claimed with. It is caught as the governed reuse of a key rather
	// than reaching the addressed-resource check behind it, which is the
	// stronger of the two answers: the caller changed the command.
	elsewhere := custodyInput(t, raw, "custody-key")
	elsewhere.ArtifactID = "artifact.ffffffffffffffffffffffffffffffff"
	elsewhere.ETag = `"artifact.ffffffffffffffffffffffffffffffff:v3"`
	elsewhereBody := []byte(`{"kind":"DecideArtifactCustodyRequest","artifactId":"artifact.ffffffffffffffffffffffffffffffff","decision":"legal-hold-placed","basis":"` + custodyBasis + `","ticket":"CHG-2291"}`)
	elsewhere.Digest = custodyDigest(t, elsewhereBody)
	if err := decideErr(app, custodianClaims(), elsewhere, elsewhereBody); !isProblem(err, problem.CodeIdempotencyKeyReused) {
		t.Fatalf("a key aimed at a different artifact = %v, want the governed key reuse", err)
	}
	// A revision the key was not claimed against is the remaining conflict
	// axis, and it keeps the general conflict code.
	revision := custodyInput(t, raw, "custody-key")
	revision.ETag = `"` + custodyArtifactID + `:v9"`
	if err := decideErr(app, custodianClaims(), revision, raw); !isProblem(err, problem.CodeIdempotencyConflict) {
		t.Fatalf("a key aimed at a different revision = %v, want a conflict", err)
	}
	if holds, deletes := custodian.calls(); holds != 1 || deletes != 0 {
		t.Fatalf("a conflicting key decided again: holds=%d deletes=%d", holds, deletes)
	}
}

// A refused decision releases its key. The custodian can correct the cause and
// retry under the same key rather than being left holding one they can never
// use again.
func TestARefusedCustodyDecisionReleasesItsKey(t *testing.T) {
	denial := problem.New(problem.CodeArtifactAccessDenied, "")
	custodian := &recordingCustodian{failWith: denial}
	app, _ := custodyApp(t, custodian)
	raw := custodyBody(CustodyDeleted)
	var details problem.Details
	err := decideErr(app, custodianClaims(), custodyInput(t, raw, "custody-key"), raw)
	if !errors.As(err, &details) || details.Code != string(problem.CodeArtifactAccessDenied) {
		t.Fatalf("err = %v, want the lifecycle's own denial", err)
	}
	custodian.failWith = nil
	if _, err := app.DecideArtifactCustody(context.Background(), custodianClaims(), custodyInput(t, raw, "custody-key"), raw); err != nil {
		t.Fatalf("the corrected retry could not reuse its key: %v", err)
	}
	if _, deletes := custodian.calls(); deletes != 2 {
		t.Fatalf("deletes=%d, want the refusal and the corrected retry", deletes)
	}
}

// Concurrent duplicates of one custody decision resolve to a single execution:
// one holds the key and decides, and the rest are told the key is in flight or
// answered with what it recorded. Nothing decides twice.
func TestConcurrentCustodyDuplicatesDecideOnce(t *testing.T) {
	custodian := &recordingCustodian{}
	app, _ := custodyApp(t, custodian)
	raw := custodyBody(CustodyLegalHoldPlaced)
	const attempts = 8
	results := make([]error, attempts)
	start := make(chan struct{})
	var group sync.WaitGroup
	for index := range attempts {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			results[index] = decideErr(app, custodianClaims(), custodyInput(t, raw, "custody-key"), raw)
		}()
	}
	close(start)
	group.Wait()
	succeeded := 0
	for _, err := range results {
		switch {
		case err == nil:
			succeeded++
		case isProblem(err, problem.CodeIdempotencyConflict):
		default:
			t.Fatalf("a concurrent duplicate failed unexpectedly: %v", err)
		}
	}
	if succeeded == 0 {
		t.Fatal("no concurrent attempt decided anything")
	}
	if holds, _ := custodian.calls(); holds != 1 {
		t.Fatalf("concurrent duplicates decided %d times, want exactly one", holds)
	}
}
