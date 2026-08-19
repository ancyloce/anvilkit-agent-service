package scheduler

import (
	"context"
	"errors"
	"fmt"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"math/rand"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)

type clock struct{ value time.Time }

func (c *clock) Now() time.Time { return c.value }

type ids struct{ attempt, fence, dlq int }

func (i *ids) PhysicalAttemptID() (AttemptID, error) {
	i.attempt++
	return AttemptID(fmt.Sprintf("attempt-%d", i.attempt)), nil
}
func (i *ids) FenceToken() (string, error) {
	i.fence++
	return fmt.Sprintf("opaque-fence-%08d", i.fence), nil
}
func (i *ids) DLQID() (string, error) { i.dlq++; return fmt.Sprintf("dlq-%d", i.dlq), nil }
func create() Create {
	return Create{Scope: Scope{"workspace", "project"}, TaskID: "task", RunID: "run", RootRunID: "root", RecoveryEpoch: 2, ExecutionGeneration: 3, Capability: "fake.execute", ReservationID: "reservation", ReservationCurrent: true, PolicyAllowed: true, InputDigest: "sha256:" + strings.Repeat("a", 64), InputObjectKey: "inputs/task", CreatedAt: now}
}
func service(t *testing.T, inject FailureInjector) (*Service, *clock, *MemoryEffects) {
	t.Helper()
	c := &clock{now}
	effects := &MemoryEffects{}
	prerequisites := PrerequisiteFunc(func(_ context.Context, value Create) error {
		if !value.ReservationCurrent || !value.PolicyAllowed {
			return errors.New("dispatch denied")
		}
		return nil
	})
	s, err := New(&ids{}, c, prerequisites, time.Minute, effects, effects, effects, inject)
	if err != nil {
		t.Fatal(err)
	}
	return s, c, effects
}

func TestTaskCreationUsesAuthoritativePrerequisite(t *testing.T) {
	c := &clock{now}
	effects := &MemoryEffects{}
	denied := PrerequisiteFunc(func(context.Context, Create) error { return errors.New("reservation stale") })
	s, err := New(&ids{}, c, denied, time.Minute, effects, effects, effects, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Create(context.Background(), create()); err == nil {
		t.Fatal("caller-authored prerequisite flags bypassed authority")
	}
}
func result(task Task, lease Lease) Result {
	return Result{TaskID: task.TaskID, RecoveryEpoch: lease.RecoveryEpoch, ExecutionGeneration: lease.ExecutionGeneration, PhysicalAttemptID: lease.PhysicalAttemptID, LeaseEpoch: lease.LeaseEpoch, FenceToken: lease.FenceToken, Capability: task.Capability, BuildIdentity: "fake-worker-build", ArtifactID: "artifact", ArtifactDigest: "sha256:" + strings.Repeat("b", 64), PendingObjectKey: fmt.Sprintf("pending/%s/r%d/g%d/%s/output", task.TaskID, task.RecoveryEpoch, task.ExecutionGeneration, lease.PhysicalAttemptID), CompletedAt: now}
}
func TestTaskRequiresReservationAndPolicy(t *testing.T) {
	for _, mutate := range []func(*Create){func(v *Create) { v.ReservationCurrent = false }, func(v *Create) { v.PolicyAllowed = false }, func(v *Create) { v.ReservationID = "" }} {
		s, _, _ := service(t, nil)
		v := create()
		mutate(&v)
		if _, err := s.Create(context.Background(), v); err == nil {
			t.Fatal("unguarded task created")
		}
	}
}
func TestLeaseEpochAndAttemptIdentityProperty(t *testing.T) {
	s, c, _ := service(t, nil)
	task, _ := s.Create(context.Background(), create())
	seen := map[AttemptID]bool{}
	var epoch uint64
	for index := 0; index < 200; index++ {
		lease, err := s.Lease(context.Background(), task.Scope, task.TaskID, "worker")
		if err != nil {
			t.Fatal(err)
		}
		if lease.LeaseEpoch <= epoch || seen[lease.PhysicalAttemptID] || lease.RecoveryEpoch != 2 || lease.ExecutionGeneration != 3 || lease.FenceToken == "" {
			t.Fatalf("lease=%#v", lease)
		}
		epoch = lease.LeaseEpoch
		seen[lease.PhysicalAttemptID] = true
		c.value = lease.ExpiresAt
		if ok, err := s.ReclaimExpired(context.Background(), task.Scope, task.TaskID); err != nil || !ok {
			t.Fatalf("reclaim=%v %v", ok, err)
		}
	}
}
func TestHeartbeatOnlyCurrentUnexpiredCAS(t *testing.T) {
	s, c, _ := service(t, nil)
	task, _ := s.Create(context.Background(), create())
	first, _ := s.Lease(context.Background(), task.Scope, task.TaskID, "worker")
	c.value = c.value.Add(10 * time.Second)
	extended, err := s.Heartbeat(context.Background(), task.Scope, first, first.ExpiresAt)
	if err != nil || !extended.ExpiresAt.After(first.ExpiresAt) {
		t.Fatalf("heartbeat=%#v %v", extended, err)
	}
	if _, err := s.Heartbeat(context.Background(), task.Scope, first, first.ExpiresAt); err == nil {
		t.Fatal("stale expiry CAS extended")
	}
	c.value = extended.ExpiresAt
	if _, err := s.Heartbeat(context.Background(), task.Scope, extended, extended.ExpiresAt); err == nil {
		t.Fatal("expired lease extended")
	}
	_, _ = s.ReclaimExpired(context.Background(), task.Scope, task.TaskID)
	second, _ := s.Lease(context.Background(), task.Scope, task.TaskID, "other")
	if _, err := s.Heartbeat(context.Background(), task.Scope, first, extended.ExpiresAt); err == nil || second.LeaseEpoch <= first.LeaseEpoch {
		t.Fatal("superseded lease extended")
	}
}
func TestFullFenceMatrixLosesDiagnosticOnly(t *testing.T) {
	mutations := map[string]func(*Result){"recovery": func(v *Result) { v.RecoveryEpoch-- }, "generation": func(v *Result) { v.ExecutionGeneration-- }, "lease": func(v *Result) { v.LeaseEpoch-- }, "attempt": func(v *Result) { v.PhysicalAttemptID = "loser" }, "task": func(v *Result) { v.TaskID = "other" }, "token": func(v *Result) { v.FenceToken = "wrong-fence-token" }, "capability": func(v *Result) { v.Capability = "artifact.scan" }, "delayed": func(v *Result) { v.CompletedAt = now.Add(2 * time.Minute) }}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			s, _, effects := service(t, nil)
			task, _ := s.Create(context.Background(), create())
			lease, _ := s.Lease(context.Background(), task.Scope, task.TaskID, "worker")
			value := result(task, lease)
			mutate(&value)
			_, err := s.AcceptResult(context.Background(), task.Scope, value)
			var details problem.Details
			if !errors.As(err, &details) || details.Code != string(problem.CodeWorkerFenceStale) || len(effects.Promoted) != 0 || len(s.Diagnostics()) != 1 {
				t.Fatalf("err=%v effects=%#v diagnostics=%#v", err, effects, s.Diagnostics())
			}
		})
	}
}
func TestWinnerAtomicPromotionAdvanceReleaseAndInjectionRollback(t *testing.T) {
	for _, point := range []FailurePoint{AfterFenceCheck, AfterPromotion, AfterAdvancement, AfterRelease} {
		t.Run(string(point), func(t *testing.T) {
			s, _, effects := service(t, func(candidate FailurePoint) error {
				if candidate == point {
					return errors.New("injected")
				}
				return nil
			})
			task, _ := s.Create(context.Background(), create())
			lease, _ := s.Lease(context.Background(), task.Scope, task.TaskID, "worker")
			if _, err := s.AcceptResult(context.Background(), task.Scope, result(task, lease)); err == nil {
				t.Fatal("injection accepted")
			}
			stored, _ := s.Get(context.Background(), task.Scope, task.TaskID)
			if stored.State == Completed || len(effects.Promoted)+len(effects.Advanced)+len(effects.Released) != 0 {
				t.Fatalf("partial effects=%#v task=%#v", effects, stored)
			}
		})
	}
	s, _, effects := service(t, nil)
	task, _ := s.Create(context.Background(), create())
	lease, _ := s.Lease(context.Background(), task.Scope, task.TaskID, "worker")
	accepted, err := s.AcceptResult(context.Background(), task.Scope, result(task, lease))
	if err != nil || !accepted.Accepted || len(effects.Promoted) != 1 || len(effects.Advanced) != 1 || len(effects.Released) != 1 {
		t.Fatalf("accepted=%#v effects=%#v err=%v", accepted, effects, err)
	}
	duplicate, err := s.AcceptResult(context.Background(), task.Scope, result(task, lease))
	if err != nil || !duplicate.Duplicate || len(effects.Promoted) != 1 {
		t.Fatal("duplicate repeated effects")
	}
}
func TestDLQStableFieldsAndReplayFence(t *testing.T) {
	s, _, _ := service(t, nil)
	task, _ := s.Create(context.Background(), create())
	entry, err := s.DeadLetter(context.Background(), task.Scope, task.TaskID, "WORKER_FAILED", "execute", "boom")
	if err != nil || entry.Code == "" || entry.Stage == "" || entry.RunID == "" {
		t.Fatalf("entry=%#v %v", entry, err)
	}
	replayed, err := s.ReplayDLQ(context.Background(), task.Scope, entry.ID)
	if err != nil || replayed.State != Queued || replayed.Lease != nil {
		t.Fatalf("replay=%#v %v", replayed, err)
	}
	lease, _ := s.Lease(context.Background(), task.Scope, task.TaskID, "worker")
	loser := result(task, lease)
	loser.FenceToken = "old-fence-token"
	if _, err := s.AcceptResult(context.Background(), task.Scope, loser); err == nil {
		t.Fatal("DLQ replay skipped fence")
	}
}
func TestRandomFenceMutationsNeverAccept(t *testing.T) {
	random := rand.New(rand.NewSource(42))
	for index := 0; index < 500; index++ {
		s, _, _ := service(t, nil)
		task, _ := s.Create(context.Background(), create())
		lease, _ := s.Lease(context.Background(), task.Scope, task.TaskID, "worker")
		value := result(task, lease)
		switch random.Intn(6) {
		case 0:
			value.RecoveryEpoch++
		case 1:
			value.ExecutionGeneration++
		case 2:
			value.LeaseEpoch++
		case 3:
			value.PhysicalAttemptID = "random"
		case 4:
			value.FenceToken = "random-fence-token"
		case 5:
			value.CompletedAt = lease.ExpiresAt
		}
		if accepted, _ := s.AcceptResult(context.Background(), task.Scope, value); accepted.Accepted {
			t.Fatalf("stale case %d accepted", index)
		}
	}
}

func TestAuthoritativeTimeFailureCannotIssueOrExtendLease(t *testing.T) {
	s, c, _ := service(t, nil)
	task, _ := s.Create(context.Background(), create())
	c.value = time.Time{}
	if _, err := s.Lease(context.Background(), task.Scope, task.TaskID, "worker"); err == nil {
		t.Fatal("lease issued without authoritative time")
	}
	c.value = now
	lease, _ := s.Lease(context.Background(), task.Scope, task.TaskID, "worker")
	c.value = time.Time{}
	if _, err := s.Heartbeat(context.Background(), task.Scope, lease, lease.ExpiresAt); err == nil {
		t.Fatal("lease extended without authoritative time")
	}
}

func TestHeartbeatRejectsTamperedCompleteLease(t *testing.T) {
	s, c, _ := service(t, nil)
	task, _ := s.Create(context.Background(), create())
	lease, _ := s.Lease(context.Background(), task.Scope, task.TaskID, "worker")
	c.value = c.value.Add(time.Second)
	for _, mutate := range []func(*Lease){
		func(value *Lease) { value.AttemptNumber++ },
		func(value *Lease) { value.IssuedAt = value.IssuedAt.Add(time.Second) },
		func(value *Lease) { value.ExpiresAt = value.ExpiresAt.Add(time.Second) },
	} {
		changed := lease
		mutate(&changed)
		if _, err := s.Heartbeat(context.Background(), task.Scope, changed, lease.ExpiresAt); err == nil {
			t.Fatalf("tampered lease extended: %#v", changed)
		}
	}
}

func TestExpiredAttemptRemainsDiagnosableAndDLQIsScoped(t *testing.T) {
	s, c, _ := service(t, nil)
	task, _ := s.Create(context.Background(), create())
	first, _ := s.Lease(context.Background(), task.Scope, task.TaskID, "worker")
	c.value = first.ExpiresAt
	if reclaimed, err := s.ReclaimExpired(context.Background(), task.Scope, task.TaskID); err != nil || !reclaimed {
		t.Fatalf("reclaim=%v err=%v", reclaimed, err)
	}
	wrongTask := result(task, first)
	wrongTask.TaskID = "different-task"
	if _, err := s.AcceptResult(context.Background(), task.Scope, wrongTask); err == nil || len(s.Diagnostics()) != 1 {
		t.Fatalf("expired attempt diagnostic err=%v diagnostics=%#v", err, s.Diagnostics())
	}
	entry, err := s.DeadLetter(context.Background(), task.Scope, task.TaskID, "WORKER_FAILED", "execute", "failed")
	if err != nil {
		t.Fatal(err)
	}
	other := Scope{WorkspaceID: "other", ProjectID: task.Scope.ProjectID}
	if _, err := s.ReplayDLQ(context.Background(), other, entry.ID); err == nil {
		t.Fatal("cross-workspace DLQ replay succeeded")
	}
}

func TestResultTimeAndObjectKeyAreBounded(t *testing.T) {
	for name, mutate := range map[string]func(*Result){
		"before-issued": func(value *Result) { value.CompletedAt = now.Add(-time.Second) },
		"traversal":     func(value *Result) { value.PendingObjectKey += "/../visible" },
	} {
		t.Run(name, func(t *testing.T) {
			s, _, _ := service(t, nil)
			task, _ := s.Create(context.Background(), create())
			lease, _ := s.Lease(context.Background(), task.Scope, task.TaskID, "worker")
			value := result(task, lease)
			mutate(&value)
			if accepted, err := s.AcceptResult(context.Background(), task.Scope, value); err == nil || accepted.Accepted {
				t.Fatalf("invalid result accepted=%v err=%v", accepted.Accepted, err)
			}
		})
	}
}
