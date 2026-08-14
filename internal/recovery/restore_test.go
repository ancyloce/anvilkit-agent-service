package recovery

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

type restoreHarness struct {
	operations []string
	audits     []StageRecord
	fail       string
	now        time.Time
}

type restoreEvidenceHarness struct {
	records []StageRecord
	reports []RestoreReport
}

func (*restoreEvidenceHarness) BeginRestore(context.Context, RestoreRequest, time.Time) error {
	return nil
}
func (h *restoreEvidenceHarness) RecordRestoreStage(_ context.Context, record StageRecord) error {
	h.records = append(h.records, record)
	return nil
}
func (h *restoreEvidenceHarness) CompleteRestore(_ context.Context, report RestoreReport) error {
	h.reports = append(h.reports, report)
	return nil
}
func (h *restoreEvidenceHarness) FailRestore(_ context.Context, report RestoreReport) error {
	h.reports = append(h.reports, report)
	return nil
}

func (h *restoreHarness) record(value string) error {
	h.operations = append(h.operations, value)
	if h.fail == value {
		return errors.New("injected")
	}
	return nil
}
func (h *restoreHarness) Disable(context.Context) error { return h.record("disable") }
func (h *restoreHarness) RestoreIsolated(context.Context, time.Time) error {
	return h.record("restore")
}
func (h *restoreHarness) Rotate(_ context.Context, epoch Epoch) error {
	return h.record("rotate-scheduler")
}
func (h *restoreHarness) EnableDualResultFence(context.Context, Epoch) error {
	return h.record("dual-fence")
}
func (h *restoreHarness) Reconcile(_ context.Context, kind Reconciliation) error {
	return h.record(string(kind))
}
func (h *restoreHarness) ReauthorizeNonterminal(context.Context) error {
	return h.record("reauthorize")
}
func (h *restoreHarness) ResumeWorkflows(context.Context) error { return h.record("resume") }
func (h *restoreHarness) EnableDispatch(context.Context) error  { return h.record("dispatch") }
func (h *restoreHarness) EnableIngress(context.Context) error   { return h.record("ingress") }
func (h *restoreHarness) VerifyProtectedAudit(context.Context) error {
	return h.record("verify-audit")
}
func (h *restoreHarness) Probe(_ context.Context, probe Probe) error {
	return h.record("probe:" + string(probe))
}
func (h *restoreHarness) RecordRestoreStage(_ context.Context, record StageRecord) error {
	h.audits = append(h.audits, record)
	return nil
}
func (h *restoreHarness) Now() time.Time { return h.now }

func restoreRequest(now time.Time) RestoreRequest {
	return RestoreRequest{DrillID: "drill-1", Actor: "operator", Workload: "restore-controller", Reason: "PITR drill", Ticket: "REC-1", Traceparent: "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01", RestorePoint: now.Add(-4 * time.Minute)}
}

func TestMandatoryThirteenStepOrderAndProbes(t *testing.T) {
	now := time.Unix(700, 0).UTC()
	harness := &restoreHarness{now: now}
	evidence := &restoreEvidenceHarness{}
	register, _ := NewMemoryRegister(10)
	orchestrator, _ := NewOrchestrator(register, harness, harness, harness, harness, harness, harness, harness, evidence, harness)
	report, err := orchestrator.Execute(context.Background(), restoreRequest(now))
	if err != nil || !report.Completed || report.ProductionProof || report.Epoch != 11 || len(report.Stages) != 13 || len(harness.audits) != 26 || len(evidence.records) != 26 || len(evidence.reports) != 1 {
		t.Fatalf("report=%#v audits=%d err=%v", report, len(harness.audits), err)
	}
	want := []string{"disable", "restore", "rotate-scheduler", "dual-fence", string(AcknowledgedFacts), string(CurrentAuthority), string(PagixEffects), string(UsageReservations), string(ArtifactsGrants), string(Deliveries), "reauthorize", "resume", "dispatch", "ingress", "verify-audit"}
	for _, probe := range RequiredProbes() {
		want = append(want, "probe:"+string(probe))
	}
	if !reflect.DeepEqual(harness.operations, want) {
		t.Fatalf("operations=%#v want=%#v", harness.operations, want)
	}
	for index, stage := range report.Stages {
		if stage.Stage != OrderedStages()[index] || stage.Outcome != "completed" {
			t.Fatalf("stage %d=%#v", index, stage)
		}
	}
}

func TestRestoreStopsBeforeResumeOnAnyReconciliationFailure(t *testing.T) {
	now := time.Unix(700, 0).UTC()
	harness := &restoreHarness{now: now, fail: string(UsageReservations)}
	evidence := &restoreEvidenceHarness{}
	register, _ := NewMemoryRegister(2)
	orchestrator, _ := NewOrchestrator(register, harness, harness, harness, harness, harness, harness, harness, evidence, harness)
	report, err := orchestrator.Execute(context.Background(), restoreRequest(now))
	if err == nil || report.Completed {
		t.Fatal("failed reconciliation declared restore complete")
	}
	for _, operation := range harness.operations {
		if operation == "resume" || operation == "dispatch" || operation == "ingress" {
			t.Fatalf("unsafe operation after failure: %s", operation)
		}
	}
	if len(report.Stages) == 0 || report.Stages[len(report.Stages)-1].Outcome != "failed" || harness.audits[len(harness.audits)-1].Outcome != "failed" {
		t.Fatalf("failure outcome missing report=%#v audits=%#v", report.Stages, harness.audits)
	}
}

func TestFailureAfterIngressReisolatesAndDuplicateDrillCannotRotateAgain(t *testing.T) {
	now := time.Unix(700, 0).UTC()
	harness := &restoreHarness{now: now, fail: "probe:" + string(DelayedPreRestoreResult)}
	evidence := &restoreEvidenceHarness{}
	register, _ := NewMemoryRegister(2)
	orchestrator, _ := NewOrchestrator(register, harness, harness, harness, harness, harness, harness, harness, evidence, harness)
	request := restoreRequest(now)
	if _, err := orchestrator.Execute(context.Background(), request); err == nil {
		t.Fatal("failed recovery probe declared completion")
	}
	if harness.operations[len(harness.operations)-1] != "disable" {
		t.Fatalf("post-ingress failure was not isolated: %#v", harness.operations)
	}
	if _, err := orchestrator.Execute(context.Background(), request); err == nil || register.IncrementCount() != 1 {
		t.Fatalf("duplicate drill rotated epoch again count=%d err=%v", register.IncrementCount(), err)
	}
}

type sequenceClock struct {
	values []time.Time
	index  int
}

func (c *sequenceClock) Now() time.Time {
	if c.index >= len(c.values) {
		return c.values[len(c.values)-1]
	}
	value := c.values[c.index]
	c.index++
	return value
}

func TestClockRollbackOrRTOExpiryStopsAndIsolatesRestore(t *testing.T) {
	now := time.Unix(700, 0).UTC()
	for name, values := range map[string][]time.Time{
		"rollback": {now, now.Add(time.Second), now.Add(-time.Second)},
		"rto":      {now, now.Add(31 * time.Minute)},
	} {
		t.Run(name, func(t *testing.T) {
			harness := &restoreHarness{now: now}
			evidence := &restoreEvidenceHarness{}
			register, _ := NewMemoryRegister(2)
			clock := &sequenceClock{values: values}
			orchestrator, _ := NewOrchestrator(register, harness, harness, harness, harness, harness, harness, harness, evidence, clock)
			if report, err := orchestrator.Execute(context.Background(), restoreRequest(now)); err == nil || report.Completed {
				t.Fatalf("unsafe time report=%#v err=%v", report, err)
			}
			if len(harness.operations) == 0 || harness.operations[len(harness.operations)-1] != "disable" {
				t.Fatalf("time failure did not isolate: %#v", harness.operations)
			}
		})
	}
}

func TestRestoreRejectsRPOOutsideBoundBeforeMutation(t *testing.T) {
	now := time.Unix(700, 0).UTC()
	harness := &restoreHarness{now: now}
	evidence := &restoreEvidenceHarness{}
	register, _ := NewMemoryRegister(2)
	orchestrator, _ := NewOrchestrator(register, harness, harness, harness, harness, harness, harness, harness, evidence, harness)
	request := restoreRequest(now)
	request.RestorePoint = now.Add(-6 * time.Minute)
	if _, err := orchestrator.Execute(context.Background(), request); err == nil || len(harness.operations) != 0 {
		t.Fatal("out-of-bound restore began mutation")
	}
}
