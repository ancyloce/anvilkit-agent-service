package artifacts

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/authority"
	"github.com/ancyloce/anvilkit-agent-service/internal/journal"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/securityaudit"
)

var artifactNow = time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)

// memoryReader mirrors the durable reader's contract: every issued grant has
// a durable record, Verify proves a presented capability against that record
// including its revocation state, and Revoke marks the records immutably —
// nothing is deleted.
type memoryReader struct {
	lock   sync.Mutex
	fail   bool
	serial int
	grants map[string]memoryGrant
}

type memoryGrant struct {
	artifact   ID
	actor      string
	purpose    Purpose
	generation uint64
	expires    time.Time
	revoked    bool
}

func (r *memoryReader) SignRead(_ context.Context, value Record, grant Grant, _ time.Duration) (string, error) {
	r.lock.Lock()
	defer r.lock.Unlock()
	r.serial++
	url := fmt.Sprintf("memory-grant://%s/%d", value.ID, r.serial)
	if r.grants == nil {
		r.grants = map[string]memoryGrant{}
	}
	r.grants[url] = memoryGrant{artifact: value.ID, actor: grant.ActorID, purpose: grant.Purpose, generation: grant.SecurityGeneration, expires: grant.ExpiresAt, revoked: false}
	return url, nil
}

func (r *memoryReader) Verify(_ context.Context, value Record, grant Grant) error {
	r.lock.Lock()
	defer r.lock.Unlock()
	recorded, ok := r.grants[grant.URL]
	if !ok {
		return errors.New("no durable grant record")
	}
	if recorded.revoked {
		return errors.New("grant is revoked")
	}
	if recorded.artifact != value.ID || recorded.actor != grant.ActorID || recorded.purpose != grant.Purpose || recorded.generation != grant.SecurityGeneration || !recorded.expires.Equal(grant.ExpiresAt) {
		return errors.New("grant record does not match the presented capability")
	}
	return nil
}

func (r *memoryReader) Revoke(_ context.Context, value Record) error {
	r.lock.Lock()
	defer r.lock.Unlock()
	if r.fail {
		return errors.New("revocation backend unavailable")
	}
	for key, recorded := range r.grants {
		if recorded.artifact == value.ID && !recorded.revoked {
			recorded.revoked = true
			r.grants[key] = recorded
		}
	}
	return nil
}

// testAuthority admits the acting actor as an artifact custodian holding both
// custody capabilities and a clearance for artifact content, which is what
// every custody operation now requires.
func testAuthority() *authority.Static {
	return authority.NewStatic(custodianAuthority())
}

func custodianAuthority() authority.Current {
	material := json.RawMessage(`{"synthetic":true}`)
	return authority.Current{
		Definition: material, ContractBOM: material, Policy: material, Budget: material,
		WorkspaceActive: true, ActorActive: true, PermissionActive: true, PolicyActive: true,
		ActorRole: authority.RoleArtifactCustodian,
		Grants: authority.Grants{
			AllowedCapabilities: []string{string(LegalHoldCapability), string(DeleteCapability)},
			DataClasses:         []string{CustodyDataClass},
		},
	}
}

func testService(t *testing.T) (*Service, *MemoryStore, *MemoryObjects) {
	t.Helper()
	store := NewMemoryStore()
	objects := NewMemoryObjects()
	service, err := New(store, objects, &memoryReader{}, testAuthority(), testAudit(t), time.Hour, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return service, store, objects
}

// testAudit is the real protected audit protocol over the in-memory sink, so
// artifact lifecycle tests exercise the same record validation, chaining, and
// receipt handling production uses rather than a permissive stand-in.
func testAudit(t *testing.T) *securityaudit.Service {
	t.Helper()
	service, _ := testAuditWithSink(t)
	return service
}

func testAuditWithSink(t *testing.T) (*securityaudit.Service, *securityaudit.MemorySink) {
	t.Helper()
	sink := &securityaudit.MemorySink{}
	clock, err := securityaudit.NewAuthoritativeClock(fixedTimeSource{}, fixedClock{}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	service, err := securityaudit.NewService(sink, clock, &securityaudit.MemoryAlerts{}, journal.NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	return service, sink
}

type fixedClock struct{}

func (fixedClock) Now() time.Time { return artifactNow }

type fixedTimeSource struct{}

func (fixedTimeSource) Now(context.Context) (time.Time, error) { return artifactNow, nil }

// testCustody is a complete accountable identity for one lifecycle decision.
func testCustody(reason string) Custody {
	return Custody{
		ActorID:     "actor-01",
		Workload:    "artifact-lifecycle-test",
		Reason:      reason,
		Ticket:      "change-0001",
		Traceparent: "00-" + strings.Repeat("1", 32) + "-" + strings.Repeat("2", 16) + "-01",
	}
}
func bytesDigest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func validCreate(id ID, now time.Time) Create {
	value := []byte("immutable artifact bytes")
	return Create{WorkspaceID: "workspace-01", ProjectID: "project-01", RunID: "run-01", ID: id, Bytes: value, ClaimedDigest: bytesDigest(value), Reference: Reference{Bucket: "artifacts", ObjectKey: string(id), SizeBytes: int64(len(value)), MediaType: "application/json"}, Schema: SchemaIdentity{Component: "plan", Version: "1.0.0", Digest: "sha256:" + strings.Repeat("e", 64)}, Lineage: Lineage{RunID: "run-01", TaskID: "task-01", PhysicalAttemptID: "attempt-01", Producer: Producer{TaskID: "task-01", PhysicalAttemptID: "attempt-01", RecoveryEpoch: 1, ExecutionGeneration: 1, LeaseEpoch: 1, BuildIdentity: "worker-build-01", Provider: "fake-worker"}, BOMDigest: "sha256:" + strings.Repeat("a", 64), SchemaDigest: "sha256:" + strings.Repeat("b", 64), CatalogDigest: "sha256:" + strings.Repeat("c", 64)}, CreatedAt: now}
}

func TestLifecycleCASMatrixAndDigestMismatchQuarantine(t *testing.T) {
	states := []State{Pending, Scanning, Valid, Finalized, Committed, Quarantined, Expired, Deleted}
	for _, from := range states {
		for _, to := range states {
			t.Run(string(from)+"_to_"+string(to), func(t *testing.T) {
				service, store, _ := testService(t)
				input := validCreate("artifact-01", artifactNow)
				record, err := service.Create(context.Background(), input)
				if err != nil {
					t.Fatal(err)
				}
				record.State = from
				store.Force(record)
				_, err = service.Transition(context.Background(), input.WorkspaceID, input.ProjectID, input.ID, record.Version, to, artifactNow.Add(time.Minute))
				if (err == nil) != allowed(from, to) {
					t.Fatalf("transition allowed=%v want=%v err=%v", err == nil, allowed(from, to), err)
				}
			})
		}
	}
	service, _, _ := testService(t)
	input := validCreate("artifact-mismatch", artifactNow)
	input.ClaimedDigest = "sha256:" + strings.Repeat("f", 64)
	record, err := service.Create(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if record.State != Quarantined || record.ActualDigest == record.Digest {
		t.Fatalf("digest mismatch not preserved and quarantined: %#v", record)
	}
	input.Bytes = []byte("changed")
	input.Reference.SizeBytes = int64(len(input.Bytes))
	if _, err := service.Create(context.Background(), input); err == nil {
		t.Fatal("immutable identity accepted changed bytes")
	}
}

func TestAccessEligibilityMatrixAndQuarantineRevokesOldGrant(t *testing.T) {
	states := []State{Pending, Scanning, Valid, Finalized, Committed, Quarantined, Expired, Deleted}
	purposes := []Purpose{ProducerAccess, ScannerAccess, ReviewAccess, ApprovalAccess, FinalizationAccess, CommitAccess, ReadAccess}
	for _, state := range states {
		for _, purpose := range purposes {
			service, store, _ := testService(t)
			input := validCreate(ID("artifact-"+string(state)+"-"+string(purpose)), artifactNow)
			record, err := service.Create(context.Background(), input)
			if err != nil {
				t.Fatal(err)
			}
			record.State = state
			store.Force(record)
			grant, err := service.Grant(context.Background(), input.WorkspaceID, input.ProjectID, input.ID, purpose, "actor-01", artifactNow)
			if (err == nil) != eligible(state, purpose) {
				t.Fatalf("state=%s purpose=%s granted=%v", state, purpose, err == nil)
			}
			if err == nil {
				if _, err := service.UseGrant(context.Background(), input.WorkspaceID, input.ProjectID, "actor-01", grant, artifactNow.Add(time.Minute)); err != nil {
					t.Fatalf("eligible grant unusable: %v", err)
				}
			}
		}
	}
	service, store, _ := testService(t)
	input := validCreate("artifact-revocation", artifactNow)
	record, _ := service.Create(context.Background(), input)
	record.State = Valid
	store.Force(record)
	grant, err := service.Grant(context.Background(), input.WorkspaceID, input.ProjectID, input.ID, ReviewAccess, "actor-01", artifactNow)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.UseGrant(context.Background(), input.WorkspaceID, input.ProjectID, "actor-02", grant, artifactNow.Add(time.Second)); err == nil {
		t.Fatal("actor-substituted grant succeeded")
	}
	quarantined, err := service.Transition(context.Background(), input.WorkspaceID, input.ProjectID, input.ID, record.Version, Quarantined, artifactNow.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if quarantined.SecurityGeneration == grant.SecurityGeneration {
		t.Fatal("quarantine did not revoke grants")
	}
	if _, err := service.UseGrant(context.Background(), input.WorkspaceID, input.ProjectID, "actor-01", grant, artifactNow.Add(2*time.Second)); err == nil {
		t.Fatal("old grant survived quarantine")
	}
}

// Forged, expired, revoked, and cross-scope grants are all denied: access
// requires the signed capability, its durable audited record, the current
// record's binding, and current authority — every axis on every use.
func TestForgedExpiredRevokedAndCrossScopeGrantsAreDenied(t *testing.T) {
	service, store, _ := testService(t)
	input := validCreate("artifact-grant-abuse", artifactNow)
	record, err := service.Create(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	record.State = Valid
	store.Force(record)
	grant, err := service.Grant(context.Background(), input.WorkspaceID, input.ProjectID, input.ID, ReviewAccess, "actor-01", artifactNow)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("forged capability with no durable record", func(t *testing.T) {
		forged := grant
		forged.URL = "memory-grant://" + string(input.ID) + "/9999"
		if _, err := service.UseGrant(context.Background(), input.WorkspaceID, input.ProjectID, "actor-01", forged, artifactNow.Add(time.Second)); err == nil {
			t.Fatal("a forged capability was accepted")
		}
	})
	t.Run("capability without its signed token", func(t *testing.T) {
		bare := grant
		bare.URL = ""
		if _, err := service.UseGrant(context.Background(), input.WorkspaceID, input.ProjectID, "actor-01", bare, artifactNow.Add(time.Second)); err == nil {
			t.Fatal("an unsigned capability was accepted")
		}
	})
	t.Run("expired grant", func(t *testing.T) {
		if _, err := service.UseGrant(context.Background(), input.WorkspaceID, input.ProjectID, "actor-01", grant, grant.ExpiresAt.Add(time.Second)); err == nil {
			t.Fatal("an expired grant was accepted")
		}
	})
	t.Run("cross-actor grant", func(t *testing.T) {
		if _, err := service.UseGrant(context.Background(), input.WorkspaceID, input.ProjectID, "actor-02", grant, artifactNow.Add(time.Second)); err == nil {
			t.Fatal("a cross-actor grant was accepted")
		}
	})
	t.Run("cross-purpose grant", func(t *testing.T) {
		crossed := grant
		crossed.Purpose = CommitAccess
		if _, err := service.UseGrant(context.Background(), input.WorkspaceID, input.ProjectID, "actor-01", crossed, artifactNow.Add(time.Second)); err == nil {
			t.Fatal("a cross-purpose grant was accepted")
		}
	})
	t.Run("valid grant still admits", func(t *testing.T) {
		if _, err := service.UseGrant(context.Background(), input.WorkspaceID, input.ProjectID, "actor-01", grant, artifactNow.Add(time.Second)); err != nil {
			t.Fatalf("the genuine grant was denied: %v", err)
		}
	})
}

// Artifact access re-reads the one current-authority source on every grant
// issuance and every use: revoked authority denies access even while the
// signed capability itself is still fresh and unrevoked.
func TestAuthorityRevocationDeniesArtifactAccess(t *testing.T) {
	store := NewMemoryStore()
	objects := NewMemoryObjects()
	source := testAuthority()
	service, err := New(store, objects, &memoryReader{}, source, testAudit(t), time.Hour, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	input := validCreate("artifact-authority", artifactNow)
	record, _ := service.Create(context.Background(), input)
	record.State = Valid
	store.Force(record)
	grant, err := service.Grant(context.Background(), input.WorkspaceID, input.ProjectID, input.ID, ReviewAccess, "actor-01", artifactNow)
	if err != nil {
		t.Fatal(err)
	}
	source.Revoke()
	if _, err := service.UseGrant(context.Background(), input.WorkspaceID, input.ProjectID, "actor-01", grant, artifactNow.Add(time.Second)); err == nil {
		t.Fatal("revoked authority still admitted artifact access")
	}
	if _, err := service.Grant(context.Background(), input.WorkspaceID, input.ProjectID, input.ID, ReviewAccess, "actor-01", artifactNow.Add(time.Second)); err == nil {
		t.Fatal("revoked authority still issued a grant")
	}
	source.Restore()
	if _, err := service.UseGrant(context.Background(), input.WorkspaceID, input.ProjectID, "actor-01", grant, artifactNow.Add(2*time.Second)); err != nil {
		t.Fatalf("restored authority denied the genuine grant: %v", err)
	}
}

func TestAccessQuarantineRaceFailsClosedAfterRevocation(t *testing.T) {
	service, store, _ := testService(t)
	input := validCreate("artifact-race", artifactNow)
	record, _ := service.Create(context.Background(), input)
	record.State = Valid
	store.Force(record)
	grant, _ := service.Grant(context.Background(), input.WorkspaceID, input.ProjectID, input.ID, ReviewAccess, "actor-01", artifactNow)
	start := make(chan struct{})
	var wait sync.WaitGroup
	for index := 0; index < 32; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, _ = service.UseGrant(context.Background(), input.WorkspaceID, input.ProjectID, "actor-01", grant, artifactNow.Add(time.Second))
		}()
	}
	close(start)
	_, err := service.Transition(context.Background(), input.WorkspaceID, input.ProjectID, input.ID, record.Version, Quarantined, artifactNow.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	wait.Wait()
	for index := 0; index < 32; index++ {
		if _, err := service.UseGrant(context.Background(), input.WorkspaceID, input.ProjectID, "actor-01", grant, artifactNow.Add(2*time.Second)); err == nil {
			t.Fatal("post-revocation access succeeded")
		}
	}
}

func TestTTLOrphanDeleteTombstoneRestoreAndLegalHold(t *testing.T) {
	service, _, objects := testService(t)
	ctx := context.Background()
	input := validCreate("artifact-ttl", artifactNow)
	record, _ := service.Create(ctx, input)
	if err := service.Reconcile(ctx, testCustody("x").Traceparent, artifactNow.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	expired, _ := service.Get(ctx, input.WorkspaceID, input.ProjectID, input.ID)
	if expired.State != Expired || expired.SecurityGeneration <= record.SecurityGeneration {
		t.Fatalf("pending TTL did not expire and revoke: %#v", expired)
	}
	deleted, err := service.Delete(ctx, input.WorkspaceID, input.ProjectID, input.ID, expired.Version, testCustody("retention-expired"), artifactNow.Add(3*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	again, err := service.Delete(ctx, input.WorkspaceID, input.ProjectID, input.ID, 999, testCustody("ignored"), artifactNow.Add(4*time.Hour))
	if err != nil || again.DeletionReason != deleted.DeletionReason {
		t.Fatalf("delete not idempotent: %#v %v", again, err)
	}
	objects.Restore(input.Reference, input.Bytes)
	if err := service.Reconcile(ctx, testCustody("x").Traceparent, artifactNow.Add(5*time.Hour)); err != nil {
		t.Fatal(err)
	}
	restored, _ := service.Get(ctx, input.WorkspaceID, input.ProjectID, input.ID)
	if restored.State != Deleted || restored.DeletedAt == nil {
		t.Fatal("restore erased deletion tombstone")
	}

	input2 := validCreate("artifact-orphan", artifactNow)
	orphan, _ := service.Create(ctx, input2)
	_ = objects.Delete(ctx, input2.Reference)
	if err := service.Reconcile(ctx, testCustody("x").Traceparent, artifactNow.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	orphaned, _ := service.Get(ctx, input2.WorkspaceID, input2.ProjectID, input2.ID)
	if orphaned.State != Deleted || orphaned.DeletionReason != "orphaned-object" || orphaned.Version <= orphan.Version {
		t.Fatalf("orphan not tombstoned: %#v", orphaned)
	}

	input3 := validCreate("artifact-hold", artifactNow)
	held, _ := service.Create(ctx, input3)
	held, err = service.SetLegalHold(ctx, input3.WorkspaceID, input3.ProjectID, input3.ID, held.Version, true, testCustody("legal-hold-requested"), artifactNow)
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.Delete(ctx, input3.WorkspaceID, input3.ProjectID, input3.ID, held.Version, testCustody("requested"), artifactNow.Add(time.Minute))
	var details problem.Details
	if !errors.As(err, &details) || details.Code != string(problem.CodeArtifactAccessDenied) {
		t.Fatalf("legal hold did not block delete: %v", err)
	}
}

func TestDeleteAndRevocationFailureInjectionFailClosed(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	objects := NewMemoryObjects()
	reader := &memoryReader{}
	service, err := New(store, objects, reader, testAuthority(), testAudit(t), time.Hour, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	input := validCreate("artifact-failure", artifactNow)
	record, _ := service.Create(ctx, input)
	record.State = Valid
	store.Force(record)
	reader.fail = true
	if _, err := service.Transition(ctx, input.WorkspaceID, input.ProjectID, input.ID, record.Version, Quarantined, artifactNow.Add(time.Minute)); err == nil {
		t.Fatal("quarantine escaped failed grant revocation")
	}
	current, _ := service.Get(ctx, input.WorkspaceID, input.ProjectID, input.ID)
	if current.State != Valid {
		t.Fatalf("failed revocation mutated metadata: %#v", current)
	}
	reader.fail = false
	objects.FailDelete = true
	if _, err := service.Delete(ctx, input.WorkspaceID, input.ProjectID, input.ID, current.Version, testCustody("requested"), artifactNow.Add(2*time.Minute)); err == nil {
		t.Fatal("object delete failure reported success")
	}
	current, _ = service.Get(ctx, input.WorkspaceID, input.ProjectID, input.ID)
	if current.State == Deleted || current.DeletedAt != nil {
		t.Fatalf("failed object delete wrote tombstone: %#v", current)
	}
}

// Withdrawing access to an artifact is an authorization decision. It used to
// require nothing at all: neither a named actor, nor that actor's current
// authority, nor any account of who withdrew it or why. An artifact could be
// made undeletable, or destroyed outright, by any caller that reached the
// service — and afterwards nothing recorded that it had happened.
func TestAuthorizationChangesRequireCurrentAuthorityAndAreAudited(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	objects := NewMemoryObjects()
	audit, sink := testAuditWithSink(t)
	service, err := New(store, objects, &memoryReader{}, testAuthority(), audit, time.Hour, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	input := validCreate("artifact-authorized", artifactNow)
	record, err := service.Create(ctx, input)
	if err != nil {
		t.Fatal(err)
	}

	// An incomplete custody is refused before anything is read or changed.
	for name, custody := range map[string]Custody{
		"no actor":       {Workload: "w", Reason: "r", Ticket: "t", Traceparent: testCustody("r").Traceparent},
		"no workload":    {ActorID: "a", Reason: "r", Ticket: "t", Traceparent: testCustody("r").Traceparent},
		"no reason":      {ActorID: "a", Workload: "w", Ticket: "t", Traceparent: testCustody("r").Traceparent},
		"no ticket":      {ActorID: "a", Workload: "w", Reason: "r", Traceparent: testCustody("r").Traceparent},
		"no traceparent": {ActorID: "a", Workload: "w", Reason: "r", Ticket: "t"},
	} {
		if _, err := service.SetLegalHold(ctx, input.WorkspaceID, input.ProjectID, input.ID, record.Version, true, custody, artifactNow); err == nil {
			t.Fatalf("%s: a legal hold was placed without an accountable identity", name)
		}
		if _, err := service.Delete(ctx, input.WorkspaceID, input.ProjectID, input.ID, record.Version, custody, artifactNow); err == nil {
			t.Fatalf("%s: an artifact was destroyed without an accountable identity", name)
		}
	}

	held, err := service.SetLegalHold(ctx, input.WorkspaceID, input.ProjectID, input.ID, record.Version, true, testCustody("litigation-hold"), artifactNow)
	if err != nil {
		t.Fatal(err)
	}
	if !held.LegalHold {
		t.Fatal("the legal hold was not placed")
	}
	// The decision is in the protected audit: both the authorization to apply
	// it and the outcome of applying it.
	records, err := sink.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var authorized, applied bool
	for _, entry := range records {
		if entry.Action != "artifact-legal-hold-placed" {
			continue
		}
		if entry.Actor != "actor-01" || entry.Reason != "litigation-hold" || entry.Scope.ResourceID != string(input.ID) {
			t.Fatalf("the audit record does not name the decision: %+v", entry)
		}
		switch entry.Outcome {
		case "authorized-to-apply":
			authorized = true
		case "applied":
			applied = true
		}
	}
	if !authorized || !applied {
		t.Fatalf("the legal hold left no complete protected account: authorized=%v applied=%v", authorized, applied)
	}
	if err := sink.Verify(ctx); err != nil {
		t.Fatalf("the protected audit chain does not verify: %v", err)
	}
}

// Authority that has been withdrawn cannot withdraw access. Revocation is the
// most consequential change the lifecycle has, so the acting authority is
// re-read at the moment of the decision rather than assumed from whatever
// admitted the caller earlier.
func TestRevokedAuthorityCannotChangeArtifactAuthorization(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	objects := NewMemoryObjects()
	revoked := authority.NewStatic(authority.Current{
		Definition: json.RawMessage(`{"synthetic":true}`), ContractBOM: json.RawMessage(`{"synthetic":true}`),
		Policy: json.RawMessage(`{"synthetic":true}`), Budget: json.RawMessage(`{"synthetic":true}`),
		WorkspaceActive: true, ActorActive: false, PermissionActive: true, PolicyActive: true,
	})
	audit, sink := testAuditWithSink(t)
	service, err := New(store, objects, &memoryReader{}, revoked, audit, time.Hour, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	input := validCreate("artifact-revoked-actor", artifactNow)
	record, err := service.Create(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	var details problem.Details
	if _, err := service.SetLegalHold(ctx, input.WorkspaceID, input.ProjectID, input.ID, record.Version, true, testCustody("hold"), artifactNow); !errors.As(err, &details) || details.Code != string(problem.CodeArtifactAccessDenied) {
		t.Fatalf("a revoked actor placed a legal hold: %v", err)
	}
	if _, err := service.Delete(ctx, input.WorkspaceID, input.ProjectID, input.ID, record.Version, testCustody("destroy"), artifactNow); !errors.As(err, &details) || details.Code != string(problem.CodeArtifactAccessDenied) {
		t.Fatalf("a revoked actor destroyed an artifact: %v", err)
	}
	current, _, err := store.Get(ctx, input.WorkspaceID, input.ProjectID, input.ID)
	if err != nil {
		t.Fatal(err)
	}
	if current.LegalHold || current.State == Deleted || current.Version != record.Version {
		t.Fatalf("a denied decision still changed the record: %#v", current)
	}
	// Nothing was recorded either: a decision that was never authorized is not
	// one the audit should carry as having been authorized.
	records, err := sink.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range records {
		if entry.Scope.ResourceID == string(input.ID) {
			t.Fatalf("a denied decision was recorded as authorized: %+v", entry)
		}
	}
}

// Reconciliation revokes access on the lifecycle's own terms, so it is audited
// exactly as an operator's revocation is — and one artifact it cannot
// reconcile never stops it reconciling the rest.
func TestReconciliationIsAuditedAndOneStuckArtifactDoesNotStopTheSweep(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	objects := NewMemoryObjects()
	reader := &memoryReader{}
	audit, sink := testAuditWithSink(t)
	service, err := New(store, objects, reader, testAuthority(), audit, time.Hour, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	// Two artifacts past their retention. One of them cannot be reconciled,
	// because its object store refuses to answer for it.
	stuck := validCreate("artifact-stuck", artifactNow)
	healthy := validCreate("artifact-healthy", artifactNow)
	if _, err := service.Create(ctx, stuck); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Create(ctx, healthy); err != nil {
		t.Fatal(err)
	}
	objects.FailExists = map[string]bool{stuck.Reference.ObjectKey: true}

	err = service.Reconcile(ctx, testCustody("sweep").Traceparent, artifactNow.Add(2*time.Hour))
	if err == nil {
		t.Fatal("the sweep hid the artifact it could not reconcile")
	}
	if !strings.Contains(err.Error(), string(stuck.ID)) {
		t.Fatalf("the sweep's failure does not name the artifact it could not reconcile: %v", err)
	}
	// The healthy artifact was reconciled all the same.
	reconciled, _, err := store.Get(ctx, healthy.WorkspaceID, healthy.ProjectID, healthy.ID)
	if err != nil {
		t.Fatal(err)
	}
	if reconciled.State != Expired {
		t.Fatalf("one stuck artifact blocked the rest of the corpus: %#v", reconciled)
	}
	records, err := sink.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	audited := false
	for _, entry := range records {
		if entry.Action == "artifact-expired" && entry.Scope.ResourceID == string(healthy.ID) && entry.Actor == "artifact-reconciler" {
			audited = true
		}
	}
	if !audited {
		t.Fatal("automated revocation left no protected account")
	}
	if err := sink.Verify(ctx); err != nil {
		t.Fatalf("the protected audit chain does not verify: %v", err)
	}
}

// An artifact service cannot be composed without a protected audit: a
// lifecycle that can revoke access with no account of the revocation is not
// one the service is allowed to offer.
func TestArtifactServiceCannotBeComposedWithoutAProtectedAudit(t *testing.T) {
	if _, err := New(NewMemoryStore(), NewMemoryObjects(), &memoryReader{}, testAuthority(), nil, time.Hour, time.Minute); err == nil {
		t.Fatal("an artifact service was composed with no protected audit")
	}
}

// serviceWithAuthority composes the artifact service over one exact authority
// observation, so a test can say precisely what the acting subject holds.
func serviceWithAuthority(t *testing.T, current authority.Current) (*Service, *MemoryStore, *MemoryObjects) {
	t.Helper()
	store := NewMemoryStore()
	objects := NewMemoryObjects()
	service, err := New(store, objects, &memoryReader{}, authority.NewStatic(current), testAudit(t), time.Hour, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return service, store, objects
}

// Custody operations need authority of their own. An active subject is what
// everything in a workspace already is; if that alone admitted them, every
// actor that could produce an artifact could also destroy one, and the audit
// would record the destruction as authorized because the caller was logged in.
// The role comes from the scope's subject register and the capability from its
// bound grants, so neither is anything the caller can assert about itself.
func TestArtifactCustodyRequiresItsOwnRoleAndCapability(t *testing.T) {
	ctx := context.Background()
	both := []string{string(LegalHoldCapability), string(DeleteCapability)}
	for _, testCase := range []struct {
		name                  string
		role                  string
		capabilities          []string
		holdAllowed, delAllow bool
	}{
		{name: "an active subject with no custody role at all", role: "", capabilities: both},
		{name: "an active subject in some other role", role: authority.RoleOperator, capabilities: both},
		{name: "the custody role with no custody capability", role: authority.RoleArtifactCustodian, capabilities: nil},
		{name: "the custody role holding only an unrelated capability", role: authority.RoleArtifactCustodian, capabilities: []string{"artifact.scan"}},
		{name: "the hold capability alone does not authorize destruction", role: authority.RoleArtifactCustodian, capabilities: []string{string(LegalHoldCapability)}, holdAllowed: true},
		{name: "the delete capability alone does not authorize a hold", role: authority.RoleArtifactCustodian, capabilities: []string{string(DeleteCapability)}, delAllow: true},
		{name: "the role and both capabilities together", role: authority.RoleArtifactCustodian, capabilities: both, holdAllowed: true, delAllow: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			material := json.RawMessage(`{"synthetic":true}`)
			service, _, _ := serviceWithAuthority(t, authority.Current{
				Definition: material, ContractBOM: material, Policy: material, Budget: material,
				WorkspaceActive: true, ActorActive: true, PermissionActive: true, PolicyActive: true,
				ActorRole: testCase.role,
				Grants:    authority.Grants{AllowedCapabilities: testCase.capabilities, DataClasses: []string{CustodyDataClass}},
			})
			held := validCreate("artifact-custody-hold", artifactNow)
			holdRecord, err := service.Create(ctx, held)
			if err != nil {
				t.Fatal(err)
			}
			destroyed := validCreate("artifact-custody-delete", artifactNow)
			destroyed.Reference.ObjectKey = "artifact-custody-delete"
			deleteRecord, err := service.Create(ctx, destroyed)
			if err != nil {
				t.Fatal(err)
			}
			var details problem.Details
			_, holdErr := service.SetLegalHold(ctx, held.WorkspaceID, held.ProjectID, held.ID, holdRecord.Version, true, testCustody("litigation"), artifactNow)
			if testCase.holdAllowed {
				if holdErr != nil {
					t.Fatalf("an authorized hold was refused: %v", holdErr)
				}
			} else if !errors.As(holdErr, &details) || details.Code != string(problem.CodeArtifactAccessDenied) {
				t.Fatalf("an unauthorized hold was admitted: %v", holdErr)
			}
			_, deleteErr := service.Delete(ctx, destroyed.WorkspaceID, destroyed.ProjectID, destroyed.ID, deleteRecord.Version, testCustody("destroy"), artifactNow)
			if testCase.delAllow {
				if deleteErr != nil {
					t.Fatalf("an authorized deletion was refused: %v", deleteErr)
				}
			} else if !errors.As(deleteErr, &details) || details.Code != string(problem.CodeArtifactAccessDenied) {
				t.Fatalf("an unauthorized deletion was admitted: %v", deleteErr)
			}
			if !testCase.delAllow {
				current, err := service.Get(ctx, destroyed.WorkspaceID, destroyed.ProjectID, destroyed.ID)
				if err != nil || current.State == Deleted {
					t.Fatalf("a refused deletion still destroyed the artifact: %#v %v", current, err)
				}
			}
		})
	}
}

// holdRacingStore places a legal hold at the exact instant the deletion tries
// to take ownership of the artifact — the interleaving a real concurrent hold
// produces, made deterministic. The claim then meets a version that has moved
// and fails, which is the point: nothing may have been destroyed by then.
type holdRacingStore struct {
	Store
	hold func()
}

func (s holdRacingStore) ClaimDeletion(ctx context.Context, workspace, project string, id ID, expectedVersion uint64, claim DeletionClaim) (Record, error) {
	s.hold()
	return s.Store.ClaimDeletion(ctx, workspace, project, id, expectedVersion, claim)
}

// A legal hold and a deletion that race must never leave live metadata naming
// content that is already gone. Grants used to be revoked and the object
// destroyed before the metadata had moved anywhere, so a hold that landed in
// between made the closing compare-and-set fail and left the record live, held,
// and pointing at bytes that no longer existed. Ownership is taken first now,
// and it is the same compare-and-set that carries the artifact out of its live
// states — so the hold either wins and the deletion stops with everything
// intact, or it arrives too late to be placed at all.
func TestADeletionRacingALegalHoldNeverDestroysContentItStillPointsAt(t *testing.T) {
	ctx := context.Background()
	t.Run("the hold wins the version and nothing is destroyed", func(t *testing.T) {
		store := NewMemoryStore()
		objects := NewMemoryObjects()
		input := validCreate("artifact-race", artifactNow)
		var service *Service
		racing := holdRacingStore{Store: store}
		var err error
		service, err = New(racing, objects, &memoryReader{}, testAuthority(), testAudit(t), time.Hour, 5*time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		record, err := service.Create(ctx, input)
		if err != nil {
			t.Fatal(err)
		}
		// The hold commits between the deletion reading the record and the
		// deletion claiming ownership of it.
		racing.hold = func() {
			held := record
			held.LegalHold = true
			held.Version++
			held.UpdatedAt = artifactNow
			if _, err := store.Update(ctx, held, record.Version); err != nil {
				t.Errorf("seed the racing hold: %v", err)
			}
		}
		service, err = New(racing, objects, &memoryReader{}, testAuthority(), testAudit(t), time.Hour, 5*time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := service.Delete(ctx, input.WorkspaceID, input.ProjectID, input.ID, record.Version, testCustody("destroy"), artifactNow.Add(time.Minute)); err == nil {
			t.Fatal("the deletion completed although a hold won the version")
		}
		current, err := service.Get(ctx, input.WorkspaceID, input.ProjectID, input.ID)
		if err != nil {
			t.Fatal(err)
		}
		if current.State != Pending || !current.LegalHold || current.DeletionClaim != "" {
			t.Fatalf("the record is not the live held one the hold left: %#v", current)
		}
		// The decisive assertion: live metadata must still name content that
		// exists. A deletion that revoked and destroyed before it owned the
		// record left exactly this record naming nothing.
		exists, err := objects.Exists(ctx, current.Reference)
		if err != nil || !exists {
			t.Fatalf("live metadata names destroyed content: exists=%v err=%v", exists, err)
		}
	})

	t.Run("ownership wins and the hold is refused", func(t *testing.T) {
		service, store, objects := testService(t)
		input := validCreate("artifact-race-owned", artifactNow)
		record, err := service.Create(ctx, input)
		if err != nil {
			t.Fatal(err)
		}
		// The deletion took ownership and was interrupted before it finished.
		decision := decisionIdentity("artifact-deleted", input.WorkspaceID, input.ProjectID, input.ID, record.Version)
		claimed, err := store.ClaimDeletion(ctx, input.WorkspaceID, input.ProjectID, input.ID, record.Version, DeletionClaim{Decision: decision, Terminal: Expired, At: artifactNow})
		if err != nil {
			t.Fatal(err)
		}
		if claimed.State != Expired || claimed.DeletionClaim != decision || claimed.DeletionClaimedAt == nil {
			t.Fatalf("ownership did not carry the artifact out of its live state: %#v", claimed)
		}
		var details problem.Details
		_, holdErr := service.SetLegalHold(ctx, input.WorkspaceID, input.ProjectID, input.ID, claimed.Version, true, testCustody("too-late"), artifactNow.Add(time.Minute))
		if !errors.As(holdErr, &details) || details.Code != string(problem.CodeArtifactAccessDenied) {
			t.Fatalf("a hold was placed on an artifact whose destruction was already owned: %v", holdErr)
		}
		// And the interrupted destruction still finishes.
		final, err := service.Delete(ctx, input.WorkspaceID, input.ProjectID, input.ID, record.Version, testCustody("destroy"), artifactNow.Add(2*time.Minute))
		if err != nil {
			t.Fatalf("an owned destruction could not be finished: %v", err)
		}
		if final.State != Deleted || final.DeletedAt == nil {
			t.Fatalf("the destruction did not complete: %#v", final)
		}
		if exists, err := objects.Exists(ctx, input.Reference); err != nil || exists {
			t.Fatalf("the content survived a completed destruction: exists=%v err=%v", exists, err)
		}
	})
}

// Every custody change is idempotent under its own decision identity, which is
// what lets an interrupted one be retried at all. Each case here is the durable
// state one interruption leaves, handed to a fresh attempt at the same decision.
func TestAnInterruptedCustodyChangeConvergesOnRetry(t *testing.T) {
	ctx := context.Background()

	t.Run("a legal hold that applied before its outcome was recorded", func(t *testing.T) {
		service, store, _ := testService(t)
		input := validCreate("artifact-hold-resume", artifactNow)
		record, err := service.Create(ctx, input)
		if err != nil {
			t.Fatal(err)
		}
		// The interrupted attempt applied the hold and got no further.
		applied := record
		applied.LegalHold = true
		applied.Version++
		applied.UpdatedAt = artifactNow
		if _, err := store.Update(ctx, applied, record.Version); err != nil {
			t.Fatal(err)
		}
		// The retry carries the version it set out to change, which the
		// artifact has already moved past.
		held, err := service.SetLegalHold(ctx, input.WorkspaceID, input.ProjectID, input.ID, record.Version, true, testCustody("litigation-hold"), artifactNow)
		if err != nil {
			t.Fatalf("the retry reported a conflict against its own completed work: %v", err)
		}
		if !held.LegalHold || held.Version != record.Version+1 {
			t.Fatalf("the retry applied the hold a second time: %#v", held)
		}
	})

	t.Run("a destruction that was owned before it was finished", func(t *testing.T) {
		service, store, objects := testService(t)
		input := validCreate("artifact-delete-resume", artifactNow)
		record, err := service.Create(ctx, input)
		if err != nil {
			t.Fatal(err)
		}
		decision := decisionIdentity("artifact-deleted", input.WorkspaceID, input.ProjectID, input.ID, record.Version)
		if _, err := store.ClaimDeletion(ctx, input.WorkspaceID, input.ProjectID, input.ID, record.Version, DeletionClaim{Decision: decision, Terminal: Expired, At: artifactNow}); err != nil {
			t.Fatal(err)
		}
		final, err := service.Delete(ctx, input.WorkspaceID, input.ProjectID, input.ID, record.Version, testCustody("destroy"), artifactNow.Add(time.Minute))
		if err != nil {
			t.Fatalf("the retry could not finish an owned destruction: %v", err)
		}
		if final.State != Deleted || final.DeletionClaim != decision {
			t.Fatalf("the retry did not converge on the owning decision: %#v", final)
		}
		if exists, err := objects.Exists(ctx, input.Reference); err != nil || exists {
			t.Fatalf("the content survived: exists=%v err=%v", exists, err)
		}
		// And running it once more changes nothing.
		again, err := service.Delete(ctx, input.WorkspaceID, input.ProjectID, input.ID, record.Version, testCustody("destroy"), artifactNow.Add(2*time.Minute))
		if err != nil || again.Version != final.Version || again.DeletionReason != final.DeletionReason {
			t.Fatalf("a further retry moved the tombstone: %#v %v", again, err)
		}
	})
}

// Custody needs more than a role and a capability. Authority over one artifact
// can be withdrawn on its own, and the clearance the scope grants has to reach
// the classification artifact content is governed under — otherwise an actor
// admitted as a custodian for public material could destroy tenant content.
func TestArtifactCustodyRequiresClearanceAndUnrevokedAuthority(t *testing.T) {
	ctx := context.Background()
	material := json.RawMessage(`{"synthetic":true}`)
	custodian := func(mutate func(*authority.Current)) authority.Current {
		current := authority.Current{
			Definition: material, ContractBOM: material, Policy: material, Budget: material,
			WorkspaceActive: true, ActorActive: true, PermissionActive: true, PolicyActive: true,
			ActorRole: authority.RoleArtifactCustodian,
			Grants: authority.Grants{
				AllowedCapabilities: []string{string(LegalHoldCapability), string(DeleteCapability)},
				DataClasses:         []string{CustodyDataClass},
			},
		}
		mutate(&current)
		return current
	}
	for _, testCase := range []struct {
		name    string
		mutate  func(*authority.Current)
		allowed bool
	}{
		{name: "a custodian cleared for artifact content", mutate: func(*authority.Current) {}, allowed: true},
		{name: "a custodian cleared above artifact content", mutate: func(c *authority.Current) { c.Grants.DataClasses = []string{"restricted"} }, allowed: true},
		{name: "a custodian with no clearance at all", mutate: func(c *authority.Current) { c.Grants.DataClasses = nil }},
		{name: "a custodian cleared only for public material", mutate: func(c *authority.Current) { c.Grants.DataClasses = []string{"public"} }},
		{name: "a custodian holding an unregistered clearance", mutate: func(c *authority.Current) { c.Grants.DataClasses = []string{"unbounded"} }},
		{name: "a custodian whose authority over this artifact was revoked", mutate: func(c *authority.Current) { c.RevokedTargets = []string{"artifact-axes"} }},
		{name: "a custodian whose scope was deactivated", mutate: func(c *authority.Current) { c.WorkspaceActive = false }},
		{name: "a custodian whose governance material is incomplete", mutate: func(c *authority.Current) { c.Policy = nil }},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			service, _, _ := serviceWithAuthority(t, custodian(testCase.mutate))
			input := validCreate("artifact-axes", artifactNow)
			record, err := service.Create(ctx, input)
			if err != nil {
				t.Fatal(err)
			}
			_, holdErr := service.SetLegalHold(ctx, input.WorkspaceID, input.ProjectID, input.ID, record.Version, true, testCustody("clearance"), artifactNow)
			if testCase.allowed {
				if holdErr != nil {
					t.Fatalf("an authorized custodian was refused: %v", holdErr)
				}
				return
			}
			var details problem.Details
			if !errors.As(holdErr, &details) || details.Code != string(problem.CodeArtifactAccessDenied) {
				t.Fatalf("an unauthorized custodian was admitted: %v", holdErr)
			}
			current, err := service.Get(ctx, input.WorkspaceID, input.ProjectID, input.ID)
			if err != nil || current.LegalHold {
				t.Fatalf("a refused hold was applied anyway: %#v %v", current, err)
			}
		})
	}
}

// One tenant's custodian holds no authority in another tenant. The lookup is
// confined to the scope the request proved, so an artifact that exists next
// door is simply absent — the answer discloses nothing about it.
func TestArtifactCustodyCannotReachAnotherTenant(t *testing.T) {
	ctx := context.Background()
	service, _, _ := testService(t)
	input := validCreate("artifact-tenant", artifactNow)
	record, err := service.Create(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	var details problem.Details
	_, holdErr := service.SetLegalHold(ctx, "workspace-other", input.ProjectID, input.ID, record.Version, true, testCustody("cross-tenant"), artifactNow)
	if !errors.As(holdErr, &details) || details.Code != string(problem.CodeResourceNotFound) {
		t.Fatalf("a cross-workspace hold = %v, want a non-disclosing absence", holdErr)
	}
	_, deleteErr := service.Delete(ctx, input.WorkspaceID, "project-other", input.ID, record.Version, testCustody("cross-tenant"), artifactNow)
	if !errors.As(deleteErr, &details) || details.Code != string(problem.CodeResourceNotFound) {
		t.Fatalf("a cross-project deletion = %v, want a non-disclosing absence", deleteErr)
	}
	current, err := service.Get(ctx, input.WorkspaceID, input.ProjectID, input.ID)
	if err != nil || current.LegalHold || current.State == Deleted {
		t.Fatalf("a foreign custody request changed the artifact: %#v %v", current, err)
	}
}

// A custody decision the protected audit cannot record is a decision that is
// not made. Nothing changes, and the artifact is left exactly as it stood.
func TestCustodyFailsClosedWithoutTheProtectedAudit(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	objects := NewMemoryObjects()
	audit, sink := testAuditWithSink(t)
	service, err := New(store, objects, &memoryReader{}, testAuthority(), audit, time.Hour, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	input := validCreate("artifact-audit-down", artifactNow)
	record, err := service.Create(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	sink.SetUnavailable(true)
	if _, err := service.SetLegalHold(ctx, input.WorkspaceID, input.ProjectID, input.ID, record.Version, true, testCustody("audit-down"), artifactNow); err == nil {
		t.Fatal("a hold was applied with no protected account of it")
	}
	if _, err := service.Delete(ctx, input.WorkspaceID, input.ProjectID, input.ID, record.Version, testCustody("audit-down"), artifactNow); err == nil {
		t.Fatal("an artifact was destroyed with no protected account of it")
	}
	sink.SetUnavailable(false)
	current, err := service.Get(ctx, input.WorkspaceID, input.ProjectID, input.ID)
	if err != nil || current.LegalHold || current.State != Pending || current.Version != record.Version {
		t.Fatalf("an unaudited decision changed the artifact: %#v %v", current, err)
	}
}

// racingStore refuses a bounded number of compare-and-sets with a governed
// version conflict, which is what a custody decision that lost a race to
// another writer meets inside its audited mutation.
type racingStore struct {
	*MemoryStore
	refusals int
}

func (s *racingStore) Update(ctx context.Context, next Record, expected uint64) (Record, error) {
	if s.refusals > 0 {
		s.refusals--
		return Record{}, problem.New(problem.CodeVersionConflict, "")
	}
	return s.MemoryStore.Update(ctx, next, expected)
}

// The interruption that used to lose a custody refusal: the artifact lifecycle
// refused the change, the refusal was recorded in the protected audit, and the
// receipt that closes the decision could not be appended. The retry must
// converge on the refusal the first attempt actually reached — a version
// conflict stays a version conflict — rather than being told only that
// something, somewhere, was refused.
func TestAnUnacknowledgedCustodyRefusalConvergesOnItsOriginalResult(t *testing.T) {
	ctx := context.Background()
	store := &racingStore{MemoryStore: NewMemoryStore()}
	objects := NewMemoryObjects()
	sink := &securityaudit.MemorySink{}
	clock, err := securityaudit.NewAuthoritativeClock(fixedTimeSource{}, fixedClock{}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	receipts := journal.NewMemoryStore()
	audit, err := securityaudit.NewService(sink, clock, &securityaudit.MemoryAlerts{}, receipts)
	if err != nil {
		t.Fatal(err)
	}
	service, err := New(store, objects, &memoryReader{}, testAuthority(), audit, time.Hour, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	input := validCreate("artifact-unacknowledged", artifactNow)
	record, err := service.Create(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	custody := testCustody("litigation-hold")

	// The decision loses its compare-and-set, and the receipt that would close
	// it cannot be appended.
	store.refusals = 1
	receipts.SetAvailable(false)
	first := errorOf(service.SetLegalHold(ctx, input.WorkspaceID, input.ProjectID, input.ID, record.Version, true, custody, artifactNow))
	if first == nil {
		t.Fatal("an unacknowledged refusal reported success")
	}
	var details problem.Details
	if errors.As(first, &details) && details.Code == string(problem.CodeVersionConflict) {
		t.Fatal("the decision was reported as closed before its receipt was appended")
	}

	// The retry finds the refusal already recorded. It must not re-apply the
	// change, and it must answer with the result that refusal holds.
	receipts.SetAvailable(true)
	retry := errorOf(service.SetLegalHold(ctx, input.WorkspaceID, input.ProjectID, input.ID, record.Version, true, custody, artifactNow))
	if !errors.As(retry, &details) || details.Code != string(problem.CodeVersionConflict) {
		t.Fatalf("the retry = %v, want the version conflict the first attempt reached", retry)
	}
	current, err := service.Get(ctx, input.WorkspaceID, input.ProjectID, input.ID)
	if err != nil || current.LegalHold || current.Version != record.Version {
		t.Fatalf("a refused decision changed the artifact: %#v %v", current, err)
	}
	// One decision, one refusal: the retry recorded nothing new.
	records, err := sink.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	failed := 0
	for _, entry := range records {
		if entry.Outcome == "failed" {
			failed++
			if entry.Result != string(problem.CodeVersionConflict) {
				t.Fatalf("the recorded refusal lost its result: %#v", entry)
			}
		}
	}
	if failed != 1 {
		t.Fatalf("the refusal was recorded %d times, want exactly one", failed)
	}
}

func errorOf(_ Record, err error) error { return err }
