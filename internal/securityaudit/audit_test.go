package securityaudit

import (
	"context"
	"errors"
	"testing"
	"time"
)

type testTime struct {
	value time.Time
	err   error
}

func (t *testTime) Now(context.Context) (time.Time, error) { return t.value, t.err }

type localTime struct{ value time.Time }

func (t *localTime) Now() time.Time { return t.value }

func auditRecord(id string) Record {
	return Record{ID: id, Action: "epoch-change", Actor: "operator", Workload: "restore-controller", Reason: "PITR", Ticket: "SEC-1", NewDigest: "sha256:new", Traceparent: "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01", Scope: Scope{WorkspaceID: "workspace", ProjectID: "project", ResourceID: "epoch"}}
}

func TestProtectedAuditFailureBlocksPrivilegedMutationButTelemetryDoesNotAuthorize(t *testing.T) {
	now := time.Unix(700, 0).UTC()
	source, local := &testTime{value: now}, &localTime{value: now}
	clock, _ := NewAuthoritativeClock(source, local, time.Second)
	sink := &MemorySink{}
	alerts := &MemoryAlerts{}
	service, _ := NewService(sink, clock, alerts)
	sink.SetUnavailable(true)
	mutated := false
	if err := service.PrivilegedMutation(context.Background(), auditRecord("audit-1"), func(context.Context) error { mutated = true; return nil }); err == nil || mutated {
		t.Fatal("mutation ran without protected audit")
	}
	// Ordinary telemetry has no input to the authorization decision. Restoring
	// protected audit availability is sufficient even if telemetry is absent.
	sink.SetUnavailable(false)
	if err := service.PrivilegedMutation(context.Background(), auditRecord("audit-1"), func(context.Context) error { mutated = true; return nil }); err != nil || !mutated {
		t.Fatalf("audited mutation failed: %v", err)
	}
}

func TestTamperDetectionAlertsAndAuditReadIsAudited(t *testing.T) {
	now := time.Unix(700, 0).UTC()
	clock, _ := NewAuthoritativeClock(&testTime{value: now}, &localTime{value: now}, time.Second)
	sink := &MemorySink{}
	alerts := &MemoryAlerts{}
	service, _ := NewService(sink, clock, alerts)
	if err := service.PrivilegedMutation(context.Background(), auditRecord("audit-1"), func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	access := auditRecord("audit-access-1")
	access.NewDigest = "sha256:access-policy"
	records, err := service.Read(context.Background(), access)
	if err != nil || len(records) != 2 || records[1].Action != "audit-access" {
		t.Fatalf("records=%#v err=%v", records, err)
	}
	sink.Corrupt(0)
	if err := service.Verify(context.Background()); err == nil || len(alerts.Values) != 1 {
		t.Fatalf("tamper err=%v alerts=%#v", err, alerts.Values)
	}
}

func TestAuthoritativeTimeSkewRollbackAndOutageFailClosed(t *testing.T) {
	now := time.Unix(700, 0).UTC()
	source, local := &testTime{value: now}, &localTime{value: now}
	clock, _ := NewAuthoritativeClock(source, local, time.Second)
	if err := clock.ValidateWindow(context.Background(), now.Add(-time.Minute), now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	source.value = now.Add(-time.Second)
	local.value = source.value
	if _, err := clock.Now(context.Background()); err == nil {
		t.Fatal("clock rollback accepted")
	}
	source.value = now.Add(10 * time.Second)
	local.value = now
	if _, err := clock.Now(context.Background()); err == nil {
		t.Fatal("excess skew accepted")
	}
	source.err = errors.New("time service down")
	if _, err := clock.Now(context.Background()); err == nil {
		t.Fatal("time outage accepted")
	}
}

func TestEveryPrivilegedActionFamilyProducesBoundRecord(t *testing.T) {
	now := time.Unix(700, 0).UTC()
	clock, _ := NewAuthoritativeClock(&testTime{value: now}, &localTime{value: now}, time.Second)
	sink := &MemorySink{}
	service, _ := NewService(sink, clock, &MemoryAlerts{})
	actions := []string{"epoch-change", "restore-stage", "policy-disable", "key-revocation", "authorization-issuance", "deletion-legal-hold", "release-exception"}
	for index, action := range actions {
		record := auditRecord("audit-family-" + action)
		record.Action = action
		if err := service.PrivilegedMutation(context.Background(), record, func(context.Context) error { return nil }); err != nil {
			t.Fatalf("action %d %s: %v", index, action, err)
		}
	}
	records, err := sink.Read(context.Background())
	if err != nil || len(records) != len(actions) {
		t.Fatalf("records=%#v err=%v", records, err)
	}
	for _, record := range records {
		if record.UTC.IsZero() || record.Digest == "" || record.Outcome == "" || record.Actor == "" || record.Reason == "" || record.Traceparent == "" || record.Scope.ResourceID == "" {
			t.Fatalf("unbound audit record: %#v", record)
		}
	}
}
