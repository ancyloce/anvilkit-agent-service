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
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
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

func testAuthority() *authority.Static {
	material := json.RawMessage(`{"synthetic":true}`)
	return authority.NewStatic(authority.Current{Definition: material, ContractBOM: material, Policy: material, Budget: material, WorkspaceActive: true, ActorActive: true, PermissionActive: true, PolicyActive: true})
}

func testService(t *testing.T) (*Service, *MemoryStore, *MemoryObjects) {
	t.Helper()
	store := NewMemoryStore()
	objects := NewMemoryObjects()
	service, err := New(store, objects, &memoryReader{}, testAuthority(), time.Hour, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return service, store, objects
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
	service, err := New(store, objects, &memoryReader{}, source, time.Hour, 5*time.Minute)
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
	if err := service.Reconcile(ctx, artifactNow.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	expired, _ := service.Get(ctx, input.WorkspaceID, input.ProjectID, input.ID)
	if expired.State != Expired || expired.SecurityGeneration <= record.SecurityGeneration {
		t.Fatalf("pending TTL did not expire and revoke: %#v", expired)
	}
	deleted, err := service.Delete(ctx, input.WorkspaceID, input.ProjectID, input.ID, expired.Version, "retention-expired", artifactNow.Add(3*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	again, err := service.Delete(ctx, input.WorkspaceID, input.ProjectID, input.ID, 999, "ignored", artifactNow.Add(4*time.Hour))
	if err != nil || again.DeletionReason != deleted.DeletionReason {
		t.Fatalf("delete not idempotent: %#v %v", again, err)
	}
	objects.Restore(input.Reference, input.Bytes)
	if err := service.Reconcile(ctx, artifactNow.Add(5*time.Hour)); err != nil {
		t.Fatal(err)
	}
	restored, _ := service.Get(ctx, input.WorkspaceID, input.ProjectID, input.ID)
	if restored.State != Deleted || restored.DeletedAt == nil {
		t.Fatal("restore erased deletion tombstone")
	}

	input2 := validCreate("artifact-orphan", artifactNow)
	orphan, _ := service.Create(ctx, input2)
	_ = objects.Delete(ctx, input2.Reference)
	if err := service.Reconcile(ctx, artifactNow.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	orphaned, _ := service.Get(ctx, input2.WorkspaceID, input2.ProjectID, input2.ID)
	if orphaned.State != Deleted || orphaned.DeletionReason != "orphaned-object" || orphaned.Version <= orphan.Version {
		t.Fatalf("orphan not tombstoned: %#v", orphaned)
	}

	input3 := validCreate("artifact-hold", artifactNow)
	held, _ := service.Create(ctx, input3)
	held, err = service.SetLegalHold(ctx, input3.WorkspaceID, input3.ProjectID, input3.ID, held.Version, true, artifactNow)
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.Delete(ctx, input3.WorkspaceID, input3.ProjectID, input3.ID, held.Version, "requested", artifactNow.Add(time.Minute))
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
	service, err := New(store, objects, reader, testAuthority(), time.Hour, time.Minute)
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
	if _, err := service.Delete(ctx, input.WorkspaceID, input.ProjectID, input.ID, current.Version, "requested", artifactNow.Add(2*time.Minute)); err == nil {
		t.Fatal("object delete failure reported success")
	}
	current, _ = service.Get(ctx, input.WorkspaceID, input.ProjectID, input.ID)
	if current.State == Deleted || current.DeletedAt != nil {
		t.Fatalf("failed object delete wrote tombstone: %#v", current)
	}
}
