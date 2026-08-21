package runapp

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/auth"
	"github.com/ancyloce/anvilkit-agent-service/internal/canonical"
	"github.com/ancyloce/anvilkit-agent-service/internal/events"
	"github.com/ancyloce/anvilkit-agent-service/internal/execution"
	"github.com/ancyloce/anvilkit-agent-service/internal/journal"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/runs"
)

// testEvidenceBasis is the canonical bounded evidence reference an operator
// recovery command carries.
const testEvidenceBasis = "anvilkit://evidence/domain-owner-audit/OPS-7-no-record-of-operation"

// gatedResolver counts executions and can be held inside the command so a test
// can put two requests in flight at once.
type gatedResolver struct {
	lock       sync.Mutex
	calls      int
	authorized int
	entered    chan struct{}
	release    chan struct{}
	failWith   error
	denyAuth   error
	snapshot   runs.Snapshot
}

// AuthorizeOperatorRecovery stands in for the pipeline's current-authority
// re-read. Arming denyAuth is what a caller whose operator authority has been
// withdrawn since its first request meets on every later one, replay included.
func (r *gatedResolver) AuthorizeOperatorRecovery(context.Context, runs.Scope, runs.ID) error {
	r.lock.Lock()
	defer r.lock.Unlock()
	r.authorized++
	return r.denyAuth
}

func (r *gatedResolver) revoke(err error) {
	r.lock.Lock()
	defer r.lock.Unlock()
	r.denyAuth = err
}

func (r *gatedResolver) authorizations() int {
	r.lock.Lock()
	defer r.lock.Unlock()
	return r.authorized
}

func (r *gatedResolver) ResolveEscalation(_ context.Context, _ runs.Scope, _ runs.ID, _ uint64, _ execution.OperatorResolution) (runs.Snapshot, error) {
	r.lock.Lock()
	r.calls++
	r.lock.Unlock()
	if r.entered != nil {
		r.entered <- struct{}{}
		<-r.release
	}
	if r.failWith != nil {
		return runs.Snapshot{}, r.failWith
	}
	return r.snapshot, nil
}

func (r *gatedResolver) count() int {
	r.lock.Lock()
	defer r.lock.Unlock()
	return r.calls
}

// receiptHarness builds the operator recovery boundary over an explicit clock
// so a test can move time past a claim lease.
type receiptHarness struct {
	app      *App
	resolver *gatedResolver
	receipts *MemoryCommandReceipts
	now      *movingClock
	operator auth.Claims
	body     []byte
	digest   string
}

type movingClock struct {
	lock  sync.Mutex
	value time.Time
}

func (c *movingClock) Now() time.Time {
	c.lock.Lock()
	defer c.lock.Unlock()
	return c.value
}
func (c *movingClock) advance(by time.Duration) {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.value = c.value.Add(by)
}

const receiptOperationID = "domain.0123456789abcdef0123456789abcdef"
const receiptTrace = "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"

func newReceiptHarness(t *testing.T, resolver *gatedResolver, lease time.Duration) *receiptHarness {
	t.Helper()
	now := time.Now()
	moving := &movingClock{value: now}
	validator, err := auth.NewValidator(auth.Config{Issuers: []string{"issuer"}, Audience: "agent", MaximumClockSkew: time.Second}, trust{}, clock{now})
	if err != nil {
		t.Fatal(err)
	}
	runStore := &store{snapshot: runs.Snapshot{RunID: "run", WorkspaceID: "workspace", Version: 3}}
	app := New(validator, runs.NewService(runStore, starter{}, ids{}, clock{now}, journal.NewMemoryStore(), runs.AdmitFunc(func(context.Context, runs.Scope) error { return nil })), eventReader{}, events.StreamConfig{}, appAuthoritySource{}, testGuard(t), testDefinitions{})
	receipts := NewMemoryCommandReceipts(moving.Now, lease)
	app.WithEscalations(resolver, receipts)
	body := []byte(`{"kind":"ResolveDomainOperationRequest","operationId":"` + receiptOperationID + `","outcome":"rejected","basis":"` + testEvidenceBasis + `"}`)
	digest, err := canonical.Digest(body)
	if err != nil {
		t.Fatal(err)
	}
	return &receiptHarness{
		app:      app,
		resolver: resolver,
		receipts: receipts,
		now:      moving,
		operator: auth.Claims{Verified: true, Source: auth.SourceWorkload, Issuer: "issuer", Audience: "agent", Subject: "operator", ActorID: "operator", WorkspaceID: "workspace", ProjectID: "project", Purpose: "agent", KeyID: "key", Scopes: []string{auth.ScopeOperator}, ExpiresAt: now.Add(time.Hour)},
		body:     body,
		digest:   digest,
	}
}

func (h *receiptHarness) resolve(claims auth.Claims, key, etag string, body []byte, digest string) (Representation, error) {
	return h.app.ResolveEscalation(context.Background(), claims, ControlInput{
		WorkspaceID: "workspace",
		RunID:       "run",
		ETag:        etag,
		Key:         key,
		Digest:      digest,
		Traceparent: receiptTrace,
	}, receiptOperationID, body)
}

// TestOperatorResolutionReceiptReplaysConflictsAndIsolates proves the route
// keeps the whole ADR-021 §4 contract: the first command executes and is
// recorded, an exact replay returns the recorded representation marked
// replayed without executing again, and every form of key misuse is a stable
// conflict rather than a second execution or a misleading success.
func TestOperatorResolutionReceiptReplaysConflictsAndIsolates(t *testing.T) {
	harness := newReceiptHarness(t, &gatedResolver{snapshot: runs.Snapshot{RunID: "run", WorkspaceID: "workspace", Version: 4}}, time.Minute)

	first, err := harness.resolve(harness.operator, "key-1", `"run:v3"`, harness.body, harness.digest)
	if err != nil {
		t.Fatalf("first resolution failed: %v", err)
	}
	if first.Replayed {
		t.Fatal("the first command reported itself as a replay")
	}
	if harness.resolver.count() != 1 {
		t.Fatalf("resolver calls=%d, want one", harness.resolver.count())
	}

	// An exact replay returns the recorded representation and does not reach
	// the command again.
	replay, err := harness.resolve(harness.operator, "key-1", `"run:v3"`, harness.body, harness.digest)
	if err != nil {
		t.Fatalf("replay failed: %v", err)
	}
	if !replay.Replayed {
		t.Fatal("an exact replay was not marked Idempotency-Replayed")
	}
	if string(replay.Body) != string(first.Body) || replay.ETag != first.ETag {
		t.Fatalf("replay body/etag = %q/%q, want the recorded %q/%q", replay.Body, replay.ETag, first.Body, first.ETag)
	}
	if replay.Digest != harness.digest {
		t.Fatalf("replay digest = %q, want the accepted request digest", replay.Digest)
	}
	if harness.resolver.count() != 1 {
		t.Fatalf("a replay executed the command again: calls=%d", harness.resolver.count())
	}

	// Reusing the key with different command bytes is a conflict.
	other := []byte(`{"kind":"ResolveDomainOperationRequest","operationId":"` + receiptOperationID + `","outcome":"confirmed","basis":"` + testEvidenceBasis + `"}`)
	otherDigest, err := canonical.Digest(other)
	if err != nil {
		t.Fatal(err)
	}
	_, err = harness.resolve(harness.operator, "key-1", `"run:v3"`, other, otherDigest)
	assertReceiptConflict(t, err, ReceiptBytesReused)

	// Reusing the key against a different observed revision is a conflict:
	// the recorded outcome was produced against the revision the operator saw.
	_, err = harness.resolve(harness.operator, "key-1", `"run:v9"`, harness.body, harness.digest)
	assertReceiptConflict(t, err, ReceiptRevisionReused)

	// Reusing the key against a different run is a conflict, never another
	// resource's recorded outcome.
	_, err = harness.app.ResolveEscalation(context.Background(), harness.operator, ControlInput{
		WorkspaceID: "workspace", RunID: "other-run", ETag: `"other-run:v3"`, Key: "key-1",
		Digest: harness.digest, Traceparent: receiptTrace,
	}, receiptOperationID, harness.body)
	assertReceiptConflict(t, err, ReceiptResourceReused)

	// A different authenticated subject holds its own key space: the same key
	// executes rather than replaying somebody else's recorded outcome.
	second := harness.operator
	second.Subject, second.ActorID = "operator-two", "operator-two"
	isolated, err := harness.resolve(second, "key-1", `"run:v3"`, harness.body, harness.digest)
	if err != nil {
		t.Fatalf("a second subject could not use its own key: %v", err)
	}
	if isolated.Replayed {
		t.Fatal("one subject replayed another subject's recorded outcome")
	}
	if harness.resolver.count() != 2 {
		t.Fatalf("resolver calls=%d, want the second subject's own execution", harness.resolver.count())
	}
}

// TestOperatorResolutionReceiptHandlesConcurrentDuplicates proves two
// simultaneous duplicates resolve deterministically: exactly one executes the
// command and the other is told the key is in flight, so the governed effect
// is never decided twice by a retry that raced its own original.
func TestOperatorResolutionReceiptHandlesConcurrentDuplicates(t *testing.T) {
	resolver := &gatedResolver{
		entered:  make(chan struct{}, 1),
		release:  make(chan struct{}),
		snapshot: runs.Snapshot{RunID: "run", WorkspaceID: "workspace", Version: 4},
	}
	harness := newReceiptHarness(t, resolver, time.Minute)

	type outcome struct {
		result Representation
		err    error
	}
	results := make(chan outcome, 2)
	go func() {
		result, err := harness.resolve(harness.operator, "key-concurrent", `"run:v3"`, harness.body, harness.digest)
		results <- outcome{result, err}
	}()
	<-resolver.entered
	// The first command is inside the pipeline. The duplicate arrives now.
	duplicate, duplicateErr := harness.resolve(harness.operator, "key-concurrent", `"run:v3"`, harness.body, harness.digest)
	close(resolver.release)
	winner := <-results

	if winner.err != nil {
		t.Fatalf("the claiming command failed: %v", winner.err)
	}
	if winner.result.Replayed {
		t.Fatal("the claiming command reported itself as a replay")
	}
	assertReceiptConflict(t, duplicateErr, ReceiptInFlight)
	if duplicate.Body != nil {
		t.Fatalf("an in-flight duplicate returned a body: %q", duplicate.Body)
	}
	if resolver.count() != 1 {
		t.Fatalf("the command executed %d times under concurrent duplicates, want once", resolver.count())
	}

	// Once the claim is recorded, the same duplicate replays it.
	replay, err := harness.resolve(harness.operator, "key-concurrent", `"run:v3"`, harness.body, harness.digest)
	if err != nil || !replay.Replayed {
		t.Fatalf("post-flight duplicate = %+v err=%v, want the recorded replay", replay, err)
	}
	if resolver.count() != 1 {
		t.Fatalf("the command executed %d times, want once", resolver.count())
	}
}

// TestOperatorResolutionReceiptReleasesDeniedClaims proves a command that
// produced no outcome leaves its key usable: a denial the operator can correct
// must not burn the idempotency key it was sent under.
func TestOperatorResolutionReceiptReleasesDeniedClaims(t *testing.T) {
	denial := problem.New(problem.CodeAuthorityStale, "")
	resolver := &gatedResolver{failWith: denial, snapshot: runs.Snapshot{RunID: "run", WorkspaceID: "workspace", Version: 4}}
	harness := newReceiptHarness(t, resolver, time.Minute)

	if _, err := harness.resolve(harness.operator, "key-denied", `"run:v3"`, harness.body, harness.digest); !isProblem(err, problem.CodeAuthorityStale) {
		t.Fatalf("denial = %v, want the pipeline's own problem", err)
	}
	// The cause is corrected and the same key is used again.
	resolver.failWith = nil
	retry, err := harness.resolve(harness.operator, "key-denied", `"run:v3"`, harness.body, harness.digest)
	if err != nil {
		t.Fatalf("a corrected retry on the same key was refused: %v", err)
	}
	if retry.Replayed {
		t.Fatal("a retry after a denial replayed a receipt that was never recorded")
	}
	if resolver.count() != 2 {
		t.Fatalf("resolver calls=%d, want the denial and the corrected retry", resolver.count())
	}
}

// TestAbandonedClaimStillRemembersItsBytes proves releasing a claim does not
// turn the key back into a fresh one: ADR-021 §4 makes reuse with different
// command bytes a conflict unconditionally, whether or not the first attempt
// produced an outcome.
func TestAbandonedClaimStillRemembersItsBytes(t *testing.T) {
	denial := problem.New(problem.CodeAuthorityStale, "")
	resolver := &gatedResolver{failWith: denial, snapshot: runs.Snapshot{RunID: "run", WorkspaceID: "workspace", Version: 4}}
	harness := newReceiptHarness(t, resolver, time.Minute)
	if _, err := harness.resolve(harness.operator, "key-reused", `"run:v3"`, harness.body, harness.digest); !isProblem(err, problem.CodeAuthorityStale) {
		t.Fatalf("denial = %v, want the pipeline's own problem", err)
	}
	resolver.failWith = nil
	other := []byte(`{"kind":"ResolveDomainOperationRequest","operationId":"` + receiptOperationID + `","outcome":"confirmed","basis":"` + testEvidenceBasis + `"}`)
	otherDigest, err := canonical.Digest(other)
	if err != nil {
		t.Fatal(err)
	}
	_, err = harness.resolve(harness.operator, "key-reused", `"run:v3"`, other, otherDigest)
	assertReceiptConflict(t, err, ReceiptBytesReused)
	if resolver.count() != 1 {
		t.Fatalf("resolver calls=%d, want the denied attempt only", resolver.count())
	}
}

// TestOperatorResolutionReceiptReclaimsAbandonedClaims proves a claim whose
// process died does not hold its key for ever: once the lease elapses the
// retry executes, and the command it drives converges on its own durable state.
func TestOperatorResolutionReceiptReclaimsAbandonedClaims(t *testing.T) {
	harness := newReceiptHarness(t, &gatedResolver{snapshot: runs.Snapshot{RunID: "run", WorkspaceID: "workspace", Version: 4}}, time.Minute)
	receipt := CommandReceiptRequest{
		WorkspaceID: "workspace", ProjectID: "project", Subject: "operator",
		Method: ReceiptMethod, Route: ResolveDomainOperationRoute, Key: "key-crashed",
		RunID: "run", Digest: harness.digest, Version: 3,
	}
	// A previous process claimed the key and died before recording anything.
	if _, _, replayed, err := harness.receipts.Begin(context.Background(), receipt); err != nil || replayed {
		t.Fatalf("seeding the abandoned claim failed: replayed=%v err=%v", replayed, err)
	}
	// Inside the lease the retry is told the key is in flight.
	_, err := harness.resolve(harness.operator, "key-crashed", `"run:v3"`, harness.body, harness.digest)
	assertReceiptConflict(t, err, ReceiptInFlight)
	if harness.resolver.count() != 0 {
		t.Fatalf("an in-flight claim was executed anyway: calls=%d", harness.resolver.count())
	}
	// Past the lease the retry takes the claim over and completes it.
	harness.now.advance(2 * time.Minute)
	reclaimed, err := harness.resolve(harness.operator, "key-crashed", `"run:v3"`, harness.body, harness.digest)
	if err != nil {
		t.Fatalf("an abandoned claim was never reclaimable: %v", err)
	}
	if reclaimed.Replayed {
		t.Fatal("a reclaimed command reported itself as a replay")
	}
	if harness.resolver.count() != 1 {
		t.Fatalf("resolver calls=%d, want the reclaiming execution", harness.resolver.count())
	}
	// The reclaimed outcome is now the recorded one.
	replay, err := harness.resolve(harness.operator, "key-crashed", `"run:v3"`, harness.body, harness.digest)
	if err != nil || !replay.Replayed {
		t.Fatalf("replay after reclaim = %+v err=%v, want the recorded outcome", replay, err)
	}
}

// TestOperatorResolutionRequiresAReceiptStore proves the route fails closed
// when its receipt store is absent: a governed mutation with undefined replay
// semantics is never served.
func TestOperatorResolutionRequiresAReceiptStore(t *testing.T) {
	harness := newReceiptHarness(t, &gatedResolver{snapshot: runs.Snapshot{RunID: "run"}}, time.Minute)
	harness.app.receipts = nil
	if _, err := harness.resolve(harness.operator, "key-1", `"run:v3"`, harness.body, harness.digest); !isProblem(err, problem.CodeInfrastructureUnavailable) {
		t.Fatalf("resolution without a receipt store = %v, want INFRASTRUCTURE_UNAVAILABLE", err)
	}
}

// TestRecordedReceiptBodyIsTheRepresentationTheCallerReceived proves a replay
// reproduces the exact representation rather than re-rendering the resource,
// which is what makes the receipt an answer to the original request.
func TestRecordedReceiptBodyIsTheRepresentationTheCallerReceived(t *testing.T) {
	harness := newReceiptHarness(t, &gatedResolver{snapshot: runs.Snapshot{RunID: "run", WorkspaceID: "workspace", Version: 4}}, time.Minute)
	first, err := harness.resolve(harness.operator, "key-body", `"run:v3"`, harness.body, harness.digest)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(first.Body, &decoded); err != nil {
		t.Fatalf("the recorded representation is not the resource document: %v", err)
	}
	if !strings.Contains(first.ETag, "run") {
		t.Fatalf("etag = %q, want the run's strong revision", first.ETag)
	}
}

// assertReceiptConflict matches one conflict by its stable detail and by the
// governed code that detail must carry. Changed canonical bytes answers under
// IDEMPOTENCY_KEY_REUSED (ADR-021 §4); every other conflict is a different
// fault and keeps the general idempotency conflict.
func assertReceiptConflict(t *testing.T, err error, detail string) {
	t.Helper()
	want := problem.CodeIdempotencyConflict
	if detail == ReceiptBytesReused {
		want = problem.CodeIdempotencyKeyReused
	}
	var details problem.Details
	if !errors.As(err, &details) {
		t.Fatalf("error = %v, want a problem", err)
	}
	if details.Code != string(want) {
		t.Fatalf("code = %q, want %q", details.Code, want)
	}
	if details.Detail != detail {
		t.Fatalf("detail = %q, want %q", details.Detail, detail)
	}
	if definition, known := problem.Lookup(want); !known || definition.Status != 409 {
		t.Fatalf("%s must answer 409, got %+v", want, definition)
	}
}

// TestRevokedOperatorAuthorityCannotReplayARecordedResolution proves a
// recorded operator resolution is never handed back on authority alone that
// used to hold. The receipt is a privileged response: replaying it to a caller
// whose operator authority has since been withdrawn would return exactly the
// audited decision the revocation was meant to stop, and would do so without
// the pipeline — which owns the re-read — being reached at all.
func TestRevokedOperatorAuthorityCannotReplayARecordedResolution(t *testing.T) {
	resolver := &gatedResolver{snapshot: runs.Snapshot{RunID: "run", WorkspaceID: "workspace", Version: 4}}
	harness := newReceiptHarness(t, resolver, time.Minute)

	first, err := harness.resolve(harness.operator, "key-revoked", `"run:v3"`, harness.body, harness.digest)
	if err != nil {
		t.Fatalf("first resolution failed: %v", err)
	}
	if first.Replayed || resolver.count() != 1 {
		t.Fatalf("first resolution = %+v calls=%d, want one recorded execution", first, resolver.count())
	}
	authorizations := resolver.authorizations()
	if authorizations == 0 {
		t.Fatal("the command path never re-read current authority")
	}

	// Authority over the run's target is withdrawn. Every axis the pipeline
	// checks — activation, the operator role, target revocation, tenant
	// scope — reports through this one denial.
	revocation := problem.New(problem.CodeAuthorityStale, "")
	revocation.Detail = "authority over the run's target is revoked"
	resolver.revoke(revocation)

	replay, err := harness.resolve(harness.operator, "key-revoked", `"run:v3"`, harness.body, harness.digest)
	if !isProblem(err, problem.CodeAuthorityStale) {
		t.Fatalf("replay after revocation = %+v err=%v, want the authority denial", replay, err)
	}
	if replay.Body != nil || replay.ETag != "" || replay.Replayed {
		t.Fatalf("a revoked caller received the recorded privileged response: %+v", replay)
	}
	if resolver.authorizations() <= authorizations {
		t.Fatal("the replay path did not re-read current authority")
	}
	if resolver.count() != 1 {
		t.Fatalf("the revoked replay executed the command: calls=%d", resolver.count())
	}

	// A caller denied the operator role is refused on the same path, and so is
	// one reaching outside its tenant — both arrive as the pipeline's own
	// scoped problem rather than as a recorded outcome.
	resolver.revoke(problem.New(problem.CodeAuthorizationDenied, ""))
	if _, err := harness.resolve(harness.operator, "key-revoked", `"run:v3"`, harness.body, harness.digest); !isProblem(err, problem.CodeAuthorizationDenied) {
		t.Fatalf("replay without the operator role = %v, want the authorization denial", err)
	}
	resolver.revoke(problem.New(problem.CodeResourceNotFound, ""))
	if _, err := harness.resolve(harness.operator, "key-revoked", `"run:v3"`, harness.body, harness.digest); !isProblem(err, problem.CodeResourceNotFound) {
		t.Fatalf("replay outside the run's tenant = %v, want the scoped not-found", err)
	}

	// Authority is restored; the recorded outcome answers again.
	resolver.revoke(nil)
	restored, err := harness.resolve(harness.operator, "key-revoked", `"run:v3"`, harness.body, harness.digest)
	if err != nil || !restored.Replayed || string(restored.Body) != string(first.Body) {
		t.Fatalf("replay after restoration = %+v err=%v, want the recorded representation", restored, err)
	}
	if resolver.count() != 1 {
		t.Fatalf("the command executed %d times overall, want once", resolver.count())
	}
}

// TestDelegatedSubjectsDoNotShareOperatorReceipts proves receipt isolation
// follows the verified credential subject rather than the actor it acts as.
// Under delegation several subjects may be admitted to act as one actor;
// keying the receipt on the actor would merge their key spaces and replay one
// subject's recorded operator resolution to another, while the audited
// resolving operator must still be the actor the pipeline verified.
func TestDelegatedSubjectsDoNotShareOperatorReceipts(t *testing.T) {
	resolver := &gatedResolver{snapshot: runs.Snapshot{RunID: "run", WorkspaceID: "workspace", Version: 4}}
	harness := newReceiptHarness(t, resolver, time.Minute)

	delegated := func(subject string) auth.Claims {
		claims := harness.operator
		claims.Source = auth.SourceDelegated
		claims.Subject = subject
		claims.ActorID = "operator"
		return claims
	}
	one, two := delegated("subject.one"), delegated("subject.two")

	first, err := harness.resolve(one, "key-delegated", `"run:v3"`, harness.body, harness.digest)
	if err != nil {
		t.Fatalf("the first delegated subject was refused: %v", err)
	}
	if first.Replayed {
		t.Fatal("the first delegated command reported itself as a replay")
	}

	// The same key, the same route, the same actor — a different credential
	// subject. It must execute, never replay the other subject's outcome.
	second, err := harness.resolve(two, "key-delegated", `"run:v3"`, harness.body, harness.digest)
	if err != nil {
		t.Fatalf("the second delegated subject could not use its own key: %v", err)
	}
	if second.Replayed {
		t.Fatal("one delegated subject replayed another subject's recorded operator resolution")
	}
	if resolver.count() != 2 {
		t.Fatalf("resolver calls=%d, want one execution per credential subject", resolver.count())
	}

	// Each subject replays only its own recorded outcome.
	for name, claims := range map[string]auth.Claims{"subject.one": one, "subject.two": two} {
		replay, err := harness.resolve(claims, "key-delegated", `"run:v3"`, harness.body, harness.digest)
		if err != nil || !replay.Replayed {
			t.Fatalf("%s replay = %+v err=%v, want its own recorded outcome", name, replay, err)
		}
	}
	if resolver.count() != 2 {
		t.Fatalf("a replay executed the command again: calls=%d", resolver.count())
	}

	// The audited resolving operator stays the verified actor: delegation
	// changes who the receipt belongs to, never who the decision is recorded
	// against.
	if resolver.snapshot.RunID != "run" {
		t.Fatalf("unexpected resolver snapshot: %+v", resolver.snapshot)
	}
}

// TestReceiptClaimFencesStaleHolders proves the claim token — not the lease
// alone — is what protects a claim. A claimant whose lease elapsed is taken
// over; when it finally returns it must neither record its outcome over its
// successor's claim nor release the claim its successor is executing under.
func TestReceiptClaimFencesStaleHolders(t *testing.T) {
	moving := &movingClock{value: time.Now()}
	receipts := NewMemoryCommandReceipts(moving.Now, time.Minute)
	ctx := context.Background()
	request := CommandReceiptRequest{
		WorkspaceID: "workspace", ProjectID: "project", Subject: "subject.one",
		Method: ReceiptMethod, Route: ResolveDomainOperationRoute, Key: "key-fenced",
		RunID: "run", Digest: "sha256:" + strings.Repeat("a", 64), Version: 3,
	}
	stalePayload := CommandReceipt{Body: []byte(`{"status":"stale"}`), ETag: `"run:run:99"`}
	successorPayload := CommandReceipt{Body: []byte(`{"status":"successor"}`), ETag: `"run:run:4"`}

	_, stale, replayed, err := receipts.Begin(ctx, request)
	if err != nil || replayed || !stale.Held() {
		t.Fatalf("first claim = %+v replayed=%v err=%v, want a held claim", stale, replayed, err)
	}
	// Recording requires the claim Begin issued; the zero claim is refused.
	if err := receipts.Record(ctx, request, ReceiptClaim{}, stalePayload); err == nil {
		t.Fatal("recording without a claim token was accepted")
	}

	moving.advance(2 * time.Minute)
	_, successor, replayed, err := receipts.Begin(ctx, request)
	if err != nil || replayed || !successor.Held() {
		t.Fatalf("takeover = %+v replayed=%v err=%v, want a held claim", successor, replayed, err)
	}
	if successor == stale {
		t.Fatal("the takeover reused the timed-out claimant's token")
	}

	// The stale claimant returns. Neither of its calls may touch the claim.
	if err := receipts.Record(ctx, request, stale, stalePayload); !isProblem(err, problem.CodeIdempotencyConflict) {
		t.Fatalf("stale record = %v, want the lost-claim conflict", err)
	}
	if err := receipts.Abandon(ctx, request, stale); err != nil {
		t.Fatalf("stale abandon = %v, want a silent no-op", err)
	}
	if _, _, _, err := receipts.Begin(ctx, request); !isProblem(err, problem.CodeIdempotencyConflict) {
		t.Fatalf("the stale claimant's abandon released its successor's claim: %v", err)
	}

	// The successor's own outcome is the only one the key ever answers with.
	if err := receipts.Record(ctx, request, successor, successorPayload); err != nil {
		t.Fatal(err)
	}
	value, _, replayed, err := receipts.Begin(ctx, request)
	if err != nil || !replayed || string(value.Body) != string(successorPayload.Body) {
		t.Fatalf("replay = %+v replayed=%v err=%v, want the successor's outcome", value, replayed, err)
	}
	// Recording again under a retired token changes nothing.
	if err := receipts.Record(ctx, request, stale, stalePayload); !isProblem(err, problem.CodeIdempotencyConflict) {
		t.Fatalf("stale record after the successor recorded = %v, want the lost-claim conflict", err)
	}
	after, _, _, err := receipts.Begin(ctx, request)
	if err != nil || string(after.Body) != string(successorPayload.Body) {
		t.Fatalf("recorded outcome = %+v err=%v, want the successor's outcome intact", after, err)
	}
}

// TestReleasingHolderCannotRecordAfterwards proves the release retires the
// releasing holder's own token too: a command that gave its claim back cannot
// then record onto the claim the next arrival took.
func TestReleasingHolderCannotRecordAfterwards(t *testing.T) {
	moving := &movingClock{value: time.Now()}
	receipts := NewMemoryCommandReceipts(moving.Now, time.Minute)
	ctx := context.Background()
	request := CommandReceiptRequest{
		WorkspaceID: "workspace", ProjectID: "project", Subject: "subject.one",
		Method: ReceiptMethod, Route: ResolveDomainOperationRoute, Key: "key-released",
		RunID: "run", Digest: "sha256:" + strings.Repeat("a", 64), Version: 3,
	}
	_, claim, _, err := receipts.Begin(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if err := receipts.Abandon(ctx, request, claim); err != nil {
		t.Fatal(err)
	}
	if err := receipts.Record(ctx, request, claim, CommandReceipt{Body: []byte(`{"status":"late"}`)}); !isProblem(err, problem.CodeIdempotencyConflict) {
		t.Fatalf("recording after releasing = %v, want the lost-claim conflict", err)
	}
	// The key is immediately reclaimable and still remembers its bytes.
	_, next, replayed, err := receipts.Begin(ctx, request)
	if err != nil || replayed || !next.Held() || next == claim {
		t.Fatalf("reclaim after release = %+v replayed=%v err=%v, want a fresh claim", next, replayed, err)
	}
	reused := request
	reused.Digest = "sha256:" + strings.Repeat("b", 64)
	if _, _, _, err := receipts.Begin(ctx, reused); !isProblem(err, problem.CodeIdempotencyKeyReused) {
		t.Fatalf("released key reused with different bytes = %v, want IDEMPOTENCY_KEY_REUSED", err)
	}
}

// TestChangedCanonicalBytesAnswerTheGovernedReuseCode proves the code split
// ADR-021 §4 requires: reuse of a live key with different canonical bytes is
// its own 409 IDEMPOTENCY_KEY_REUSED, and the unrelated semantic conflicts —
// a different observed revision, a different addressed run, a duplicate in
// flight — stay distinguishable under IDEMPOTENCY_CONFLICT.
func TestChangedCanonicalBytesAnswerTheGovernedReuseCode(t *testing.T) {
	resolver := &gatedResolver{snapshot: runs.Snapshot{RunID: "run", WorkspaceID: "workspace", Version: 4}}
	harness := newReceiptHarness(t, resolver, time.Minute)
	if _, err := harness.resolve(harness.operator, "key-governed", `"run:v3"`, harness.body, harness.digest); err != nil {
		t.Fatal(err)
	}
	changed := []byte(`{"kind":"ResolveDomainOperationRequest","operationId":"` + receiptOperationID + `","outcome":"confirmed","basis":"` + testEvidenceBasis + `"}`)
	changedDigest, err := canonical.Digest(changed)
	if err != nil {
		t.Fatal(err)
	}
	_, err = harness.resolve(harness.operator, "key-governed", `"run:v3"`, changed, changedDigest)
	if !isProblem(err, problem.CodeIdempotencyKeyReused) {
		t.Fatalf("changed canonical bytes = %v, want IDEMPOTENCY_KEY_REUSED", err)
	}
	definition, known := problem.Lookup(problem.CodeIdempotencyKeyReused)
	if !known || definition.Status != 409 || definition.Retryability != "never" {
		t.Fatalf("governed code definition = %+v, want a non-retryable 409", definition)
	}

	// The unrelated conflicts keep their own code.
	if _, err := harness.resolve(harness.operator, "key-governed", `"run:v9"`, harness.body, harness.digest); !isProblem(err, problem.CodeIdempotencyConflict) {
		t.Fatalf("different observed revision = %v, want IDEMPOTENCY_CONFLICT", err)
	}
	_, err = harness.app.ResolveEscalation(context.Background(), harness.operator, ControlInput{
		WorkspaceID: "workspace", RunID: "other-run", ETag: `"other-run:v3"`, Key: "key-governed",
		Digest: harness.digest, Traceparent: receiptTrace,
	}, receiptOperationID, harness.body)
	if !isProblem(err, problem.CodeIdempotencyConflict) {
		t.Fatalf("different addressed run = %v, want IDEMPOTENCY_CONFLICT", err)
	}
}
