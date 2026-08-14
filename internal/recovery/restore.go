package recovery

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
)

type Stage uint8

const (
	DisableProcessing Stage = iota + 1
	RestoreDatabase
	RotateExternalEpoch
	FenceRecoveredScheduler
	EnableDualResultFence
	ReconcileAcknowledgements
	ReconcileCurrentAuthority
	ReconcilePagix
	ReconcileUsage
	ReconcileArtifacts
	RebuildDeliveries
	ResumeInSafeOrder
	VerifyRecovery
)

func OrderedStages() []Stage {
	return []Stage{
		DisableProcessing, RestoreDatabase, RotateExternalEpoch, FenceRecoveredScheduler,
		EnableDualResultFence, ReconcileAcknowledgements, ReconcileCurrentAuthority,
		ReconcilePagix, ReconcileUsage, ReconcileArtifacts, RebuildDeliveries,
		ResumeInSafeOrder, VerifyRecovery,
	}
}

func (s Stage) String() string {
	names := map[Stage]string{
		DisableProcessing:         "disable-processing",
		RestoreDatabase:           "restore-postgres-isolated",
		RotateExternalEpoch:       "rotate-external-epoch",
		FenceRecoveredScheduler:   "fence-recovered-scheduler",
		EnableDualResultFence:     "enable-dual-result-fence",
		ReconcileAcknowledgements: "reconcile-acknowledgements",
		ReconcileCurrentAuthority: "reconcile-current-authority",
		ReconcilePagix:            "reconcile-pagix-effects",
		ReconcileUsage:            "reconcile-reservations-usage",
		ReconcileArtifacts:        "reconcile-artifacts-grants",
		RebuildDeliveries:         "rebuild-deliveries-without-dispatch",
		ResumeInSafeOrder:         "reauthorize-resume-dispatch-ingress",
		VerifyRecovery:            "verify-audit-and-probes",
	}
	return names[s]
}

type Reconciliation string

const (
	AcknowledgedFacts Reconciliation = "acknowledged-facts"
	CurrentAuthority  Reconciliation = "current-authority"
	PagixEffects      Reconciliation = "pagix-effects-redemptions-outbox"
	UsageReservations Reconciliation = "reservations-all-attempt-usage"
	ArtifactsGrants   Reconciliation = "artifact-digests-lifecycle-grants"
	Deliveries        Reconciliation = "outbox-inbox-queues-dlq"
)

type Probe string

const (
	DelayedPreRestoreResult Probe = "delayed-pre-restore-result"
	RevokedAuthority        Probe = "revoked-authority"
	DeletedWorkspace        Probe = "deleted-workspace"
	ResurrectedDecision     Probe = "resurrected-human-decision"
	OldArtifactGrant        Probe = "old-artifact-grant"
	LostAcknowledgement     Probe = "lost-acknowledgement"
)

func RequiredProbes() []Probe {
	return []Probe{DelayedPreRestoreResult, RevokedAuthority, DeletedWorkspace, ResurrectedDecision, OldArtifactGrant, LostAcknowledgement}
}

type Isolation interface {
	Disable(context.Context) error
}
type DatabaseRestorer interface {
	RestoreIsolated(context.Context, time.Time) error
}
type SchedulerRecovery interface {
	Rotate(context.Context, Epoch) error
	EnableDualResultFence(context.Context, Epoch) error
}
type Reconciler interface {
	Reconcile(context.Context, Reconciliation) error
}
type RuntimeRecovery interface {
	ReauthorizeNonterminal(context.Context) error
	ResumeWorkflows(context.Context) error
	EnableDispatch(context.Context) error
	EnableIngress(context.Context) error
}
type RecoveryVerifier interface {
	VerifyProtectedAudit(context.Context) error
	Probe(context.Context, Probe) error
}
type RestoreAuditor interface {
	RecordRestoreStage(context.Context, StageRecord) error
}
type RestoreEvidence interface {
	BeginRestore(context.Context, RestoreRequest, time.Time) error
	RecordRestoreStage(context.Context, StageRecord) error
	CompleteRestore(context.Context, RestoreReport) error
	FailRestore(context.Context, RestoreReport) error
}
type RestoreClock interface{ Now() time.Time }

type StageRecord struct {
	DrillID, Actor, Workload, Reason, Ticket, Traceparent string
	Stage                                                 Stage
	Outcome                                               string
	Epoch                                                 Epoch
	At                                                    time.Time
}
type RestoreRequest struct {
	DrillID, Actor, Workload, Reason, Ticket, Traceparent string
	RestorePoint                                          time.Time
}
type RestoreReport struct {
	DrillID         string
	Epoch           Epoch
	StartedAt       time.Time
	CompletedAt     time.Time
	Stages          []StageRecord
	RPO, RTO        time.Duration
	Completed       bool
	ProductionProof bool
	FailedStage     Stage
	FailureCode     string
}

type Orchestrator struct {
	register   Register
	isolation  Isolation
	database   DatabaseRestorer
	scheduler  SchedulerRecovery
	reconciler Reconciler
	runtime    RuntimeRecovery
	verifier   RecoveryVerifier
	auditor    RestoreAuditor
	evidence   RestoreEvidence
	clock      RestoreClock
	lock       sync.Mutex
	drills     map[string]struct{}
}

func NewOrchestrator(register Register, isolation Isolation, database DatabaseRestorer, scheduler SchedulerRecovery, reconciler Reconciler, runtime RuntimeRecovery, verifier RecoveryVerifier, auditor RestoreAuditor, evidence RestoreEvidence, clock RestoreClock) (*Orchestrator, error) {
	if register == nil || isolation == nil || database == nil || scheduler == nil || reconciler == nil || runtime == nil || verifier == nil || auditor == nil || evidence == nil || clock == nil {
		return nil, fmt.Errorf("all restore dependencies are required")
	}
	return &Orchestrator{register: register, isolation: isolation, database: database, scheduler: scheduler, reconciler: reconciler, runtime: runtime, verifier: verifier, auditor: auditor, evidence: evidence, clock: clock, drills: map[string]struct{}{}}, nil
}

func (o *Orchestrator) Execute(ctx context.Context, request RestoreRequest) (RestoreReport, error) {
	started := o.clock.Now().UTC()
	if started.IsZero() || ValidateRestoreRequest(request) != nil || request.RestorePoint.After(started) {
		return RestoreReport{}, fmt.Errorf("restore request evidence is incomplete")
	}
	report := RestoreReport{DrillID: request.DrillID, StartedAt: started, RPO: started.Sub(request.RestorePoint)}
	if report.RPO > 5*time.Minute {
		return report, fmt.Errorf("restore point RPO %s exceeds five minutes", report.RPO)
	}
	o.lock.Lock()
	if _, exists := o.drills[request.DrillID]; exists {
		o.lock.Unlock()
		return RestoreReport{}, problem.New(problem.CodeIdempotencyConflict, "")
	}
	o.drills[request.DrillID] = struct{}{}
	o.lock.Unlock()
	if err := o.evidence.BeginRestore(ctx, request, started); err != nil {
		o.lock.Lock()
		delete(o.drills, request.DrillID)
		o.lock.Unlock()
		return report, fmt.Errorf("begin durable restore evidence: %w", err)
	}

	var epoch Epoch
	lastTime := started
	deadline := started.Add(30 * time.Minute)
	for _, stage := range OrderedStages() {
		stageTime, err := o.readTime(lastTime)
		if err != nil || stageTime.After(deadline) {
			_ = o.isolation.Disable(ctx)
			o.failEvidence(ctx, &report, stage, "authoritative-time-or-rto", lastTime)
			if err != nil {
				return report, err
			}
			return report, fmt.Errorf("restore RTO exceeded before stage %d", stage)
		}
		lastTime = stageTime
		starting := StageRecord{DrillID: request.DrillID, Actor: request.Actor, Workload: request.Workload, Reason: request.Reason, Ticket: request.Ticket, Traceparent: request.Traceparent, Stage: stage, Outcome: "starting", Epoch: epoch, At: stageTime}
		if err := o.auditor.RecordRestoreStage(ctx, starting); err != nil {
			_ = o.isolation.Disable(ctx)
			o.failEvidence(ctx, &report, stage, "protected-audit-start", stageTime)
			return report, fmt.Errorf("audit restore stage %d before execution: %w", stage, err)
		}
		if err := o.evidence.RecordRestoreStage(ctx, starting); err != nil {
			_ = o.isolation.Disable(ctx)
			o.failEvidence(ctx, &report, stage, "durable-evidence-start", stageTime)
			return report, fmt.Errorf("record durable restore stage %d before execution: %w", stage, err)
		}
		if err := o.executeStage(ctx, stage, request, &epoch); err != nil {
			failed := starting
			failed.Outcome = "failed"
			failed.Epoch = epoch
			if failedAt, timeErr := o.readTime(lastTime); timeErr == nil {
				failed.At = failedAt
			}
			report.Stages = append(report.Stages, failed)
			auditErr := o.auditor.RecordRestoreStage(ctx, failed)
			evidenceErr := o.evidence.RecordRestoreStage(ctx, failed)
			isolationErr := o.isolation.Disable(ctx)
			o.failEvidence(ctx, &report, stage, "stage-failed", failed.At)
			if auditErr != nil || evidenceErr != nil || isolationErr != nil {
				return report, fmt.Errorf("restore stage %d failed (%v); failure audit=%v evidence=%v isolation=%v", stage, err, auditErr, evidenceErr, isolationErr)
			}
			return report, fmt.Errorf("restore stage %d %s: %w", stage, stage, err)
		}
		completed := starting
		completed.Outcome = "completed"
		completed.Epoch = epoch
		completed.At, err = o.readTime(lastTime)
		if err != nil || completed.At.After(deadline) {
			completed.Outcome = "failed"
			report.Stages = append(report.Stages, completed)
			_ = o.auditor.RecordRestoreStage(ctx, completed)
			_ = o.evidence.RecordRestoreStage(ctx, completed)
			_ = o.isolation.Disable(ctx)
			o.failEvidence(ctx, &report, stage, "authoritative-time-or-rto", lastTime)
			if err != nil {
				return report, err
			}
			return report, fmt.Errorf("restore RTO exceeded during stage %d", stage)
		}
		lastTime = completed.At
		if err := o.auditor.RecordRestoreStage(ctx, completed); err != nil {
			_ = o.isolation.Disable(ctx)
			o.failEvidence(ctx, &report, stage, "protected-audit-complete", completed.At)
			return report, fmt.Errorf("audit restore stage %d completion: %w", stage, err)
		}
		if err := o.evidence.RecordRestoreStage(ctx, completed); err != nil {
			_ = o.isolation.Disable(ctx)
			o.failEvidence(ctx, &report, stage, "durable-evidence-complete", completed.At)
			return report, fmt.Errorf("record durable restore stage %d completion: %w", stage, err)
		}
		report.Stages = append(report.Stages, completed)
	}
	report.Epoch = epoch
	report.CompletedAt = lastTime
	report.RTO = report.CompletedAt.Sub(started)
	if report.RTO > 30*time.Minute {
		return report, fmt.Errorf("restore RTO %s exceeds thirty minutes", report.RTO)
	}
	candidate := report
	candidate.Completed = true
	// Only an approved Gate-F product and production-like drill may set this
	// retained evidence field. The product-neutral harness always leaves false.
	candidate.ProductionProof = false
	if err := o.evidence.CompleteRestore(ctx, candidate); err != nil {
		_ = o.isolation.Disable(ctx)
		o.failEvidence(ctx, &report, VerifyRecovery, "durable-evidence-finalize", report.CompletedAt)
		return report, fmt.Errorf("complete durable restore evidence: %w", err)
	}
	report = candidate
	return report, nil
}

func (o *Orchestrator) failEvidence(ctx context.Context, report *RestoreReport, stage Stage, code string, at time.Time) {
	report.FailedStage = stage
	report.FailureCode = code
	report.CompletedAt = at
	if !report.StartedAt.IsZero() && !at.Before(report.StartedAt) {
		report.RTO = at.Sub(report.StartedAt)
	}
	_ = o.evidence.FailRestore(ctx, *report)
}

func (o *Orchestrator) readTime(previous time.Time) (time.Time, error) {
	current := o.clock.Now().UTC()
	if current.IsZero() || current.Before(previous) {
		return time.Time{}, problem.New(problem.CodeAuthorityStale, "")
	}
	return current, nil
}

func ValidateRestoreRequest(request RestoreRequest) error {
	values := []string{request.DrillID, request.Actor, request.Workload, request.Ticket}
	for _, value := range values {
		if !validRestoreID(value) {
			return problem.New(problem.CodeRequestInvalid, "")
		}
	}
	if len(request.Reason) < 1 || len(request.Reason) > 1024 || request.RestorePoint.IsZero() || !validTraceparent(request.Traceparent) {
		return problem.New(problem.CodeRequestInvalid, "")
	}
	for _, character := range request.Reason {
		if character < 0x20 || character > 0x7e {
			return problem.New(problem.CodeRequestInvalid, "")
		}
	}
	return nil
}

func ValidateStageRecord(record StageRecord) error {
	request := RestoreRequest{DrillID: record.DrillID, Actor: record.Actor, Workload: record.Workload, Reason: record.Reason, Ticket: record.Ticket, Traceparent: record.Traceparent, RestorePoint: record.At}
	if ValidateRestoreRequest(request) != nil || record.Stage < DisableProcessing || record.Stage > VerifyRecovery || (record.Outcome != "starting" && record.Outcome != "completed" && record.Outcome != "failed") || record.At.IsZero() {
		return problem.New(problem.CodeRequestInvalid, "")
	}
	return nil
}

func ValidateRestoreReport(report RestoreReport, failed bool) error {
	if !validRestoreID(report.DrillID) || report.StartedAt.IsZero() || report.CompletedAt.IsZero() || report.CompletedAt.Before(report.StartedAt) || report.RPO < 0 || report.RTO < 0 || report.RPO > 5*time.Minute || report.RTO > 30*time.Minute {
		return problem.New(problem.CodeRequestInvalid, "")
	}
	if failed {
		if report.Completed || report.FailedStage < DisableProcessing || report.FailedStage > VerifyRecovery || !validRestoreID(report.FailureCode) {
			return problem.New(problem.CodeRequestInvalid, "")
		}
	} else if !report.Completed || report.Epoch == 0 || report.FailedStage != 0 || report.FailureCode != "" {
		return problem.New(problem.CodeRequestInvalid, "")
	}
	return nil
}

func validRestoreID(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for index, character := range value {
		if (character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || (index > 0 && (character == '.' || character == '_' || character == ':' || character == '-')) {
			continue
		}
		return false
	}
	return true
}

func (o *Orchestrator) executeStage(ctx context.Context, stage Stage, request RestoreRequest, epoch *Epoch) error {
	switch stage {
	case DisableProcessing:
		return o.isolation.Disable(ctx)
	case RestoreDatabase:
		return o.database.RestoreIsolated(ctx, request.RestorePoint)
	case RotateExternalEpoch:
		current, err := o.register.Current(ctx)
		if err != nil {
			return err
		}
		next, err := o.register.Increment(ctx, current, IncrementEvidence{Actor: request.Actor, Workload: request.Workload, Reason: request.Reason, Ticket: request.Ticket, Traceparent: request.Traceparent, At: o.clock.Now().UTC()})
		if err != nil {
			return err
		}
		*epoch = next
		return nil
	case FenceRecoveredScheduler:
		return o.scheduler.Rotate(ctx, *epoch)
	case EnableDualResultFence:
		return o.scheduler.EnableDualResultFence(ctx, *epoch)
	case ReconcileAcknowledgements:
		return o.reconciler.Reconcile(ctx, AcknowledgedFacts)
	case ReconcileCurrentAuthority:
		return o.reconciler.Reconcile(ctx, CurrentAuthority)
	case ReconcilePagix:
		return o.reconciler.Reconcile(ctx, PagixEffects)
	case ReconcileUsage:
		return o.reconciler.Reconcile(ctx, UsageReservations)
	case ReconcileArtifacts:
		return o.reconciler.Reconcile(ctx, ArtifactsGrants)
	case RebuildDeliveries:
		return o.reconciler.Reconcile(ctx, Deliveries)
	case ResumeInSafeOrder:
		if err := o.runtime.ReauthorizeNonterminal(ctx); err != nil {
			return err
		}
		if err := o.runtime.ResumeWorkflows(ctx); err != nil {
			return err
		}
		if err := o.runtime.EnableDispatch(ctx); err != nil {
			return err
		}
		return o.runtime.EnableIngress(ctx)
	case VerifyRecovery:
		if err := o.verifier.VerifyProtectedAudit(ctx); err != nil {
			return err
		}
		for _, probe := range RequiredProbes() {
			if err := o.verifier.Probe(ctx, probe); err != nil {
				return fmt.Errorf("probe %s: %w", probe, err)
			}
		}
		return nil
	default:
		return fmt.Errorf("unknown restore stage %d", stage)
	}
}
