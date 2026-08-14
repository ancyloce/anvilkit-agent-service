package artifacts

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
)

var artifactNow = time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)

type signedReader struct{}

func (signedReader) SignRead(_ context.Context, value Record, ttl time.Duration) (string, error) {
	return fmt.Sprintf("https://objects.invalid/%s?ttl=%s", value.ID, ttl), nil
}
func (signedReader) Revoke(context.Context, Record) error { return nil }

type failingReader struct{ fail bool }

func (*failingReader) SignRead(_ context.Context, value Record, _ time.Duration) (string, error) {
	return "https://objects.invalid/" + string(value.ID), nil
}
func (r *failingReader) Revoke(context.Context, Record) error {
	if r.fail {
		return errors.New("revocation backend unavailable")
	}
	return nil
}

func testService(t *testing.T) (*Service, *MemoryObjects) {
	t.Helper()
	objects := NewMemoryObjects()
	service, err := New(objects, signedReader{}, time.Hour, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return service, objects
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
				service, _ := testService(t)
				input := validCreate("artifact-01", artifactNow)
				record, err := service.Create(context.Background(), input)
				if err != nil {
					t.Fatal(err)
				}
				service.records[key(input.WorkspaceID, input.ProjectID, input.ID)] = func() Record { record.State = from; return record }()
				_, err = service.Transition(context.Background(), input.WorkspaceID, input.ProjectID, input.ID, record.Version, to, artifactNow.Add(time.Minute))
				if (err == nil) != allowed(from, to) {
					t.Fatalf("transition allowed=%v want=%v err=%v", err == nil, allowed(from, to), err)
				}
			})
		}
	}
	service, _ := testService(t)
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
			service, _ := testService(t)
			input := validCreate(ID("artifact-"+string(state)+"-"+string(purpose)), artifactNow)
			record, err := service.Create(context.Background(), input)
			if err != nil {
				t.Fatal(err)
			}
			record.State = state
			service.records[key(input.WorkspaceID, input.ProjectID, input.ID)] = record
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
	service, _ := testService(t)
	input := validCreate("artifact-revocation", artifactNow)
	record, _ := service.Create(context.Background(), input)
	record.State = Valid
	service.records[key(input.WorkspaceID, input.ProjectID, input.ID)] = record
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

func TestAccessQuarantineRaceFailsClosedAfterRevocation(t *testing.T) {
	service, _ := testService(t)
	input := validCreate("artifact-race", artifactNow)
	record, _ := service.Create(context.Background(), input)
	record.State = Valid
	service.records[key(input.WorkspaceID, input.ProjectID, input.ID)] = record
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
	service, objects := testService(t)
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
	objects := NewMemoryObjects()
	reader := &failingReader{}
	service, err := New(objects, reader, time.Hour, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	input := validCreate("artifact-failure", artifactNow)
	record, _ := service.Create(ctx, input)
	record.State = Valid
	service.records[key(input.WorkspaceID, input.ProjectID, input.ID)] = record
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
