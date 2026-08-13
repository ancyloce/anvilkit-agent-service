package recovery

import (
	"context"
	"fmt"
	"time"
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
type RestoreClock interface{ Now() time.Time }

type StageRecord struct {
	DrillID, Actor, Reason, Ticket, Traceparent string
	Stage                                       Stage
	Outcome                                     string
	Epoch                                       Epoch
	At                                          time.Time
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
	clock      RestoreClock
}

func NewOrchestrator(register Register, isolation Isolation, database DatabaseRestorer, scheduler SchedulerRecovery, reconciler Reconciler, runtime RuntimeRecovery, verifier RecoveryVerifier, auditor RestoreAuditor, clock RestoreClock) (*Orchestrator, error) {
	if register == nil || isolation == nil || database == nil || scheduler == nil || reconciler == nil || runtime == nil || verifier == nil || auditor == nil || clock == nil {
		return nil, fmt.Errorf("all restore dependencies are required")
	}
	return &Orchestrator{register, isolation, database, scheduler, reconciler, runtime, verifier, auditor, clock}, nil
}

func (o *Orchestrator) Execute(ctx context.Context, request RestoreRequest) (RestoreReport, error) {
	started := o.clock.Now().UTC()
	if request.DrillID == "" || request.Actor == "" || request.Workload == "" || request.Reason == "" || request.Ticket == "" || request.Traceparent == "" || request.RestorePoint.IsZero() || request.RestorePoint.After(started) {
		return RestoreReport{}, fmt.Errorf("restore request evidence is incomplete")
	}
	report := RestoreReport{DrillID: request.DrillID, StartedAt: started, RPO: started.Sub(request.RestorePoint)}
	if report.RPO > 5*time.Minute {
		return report, fmt.Errorf("restore point RPO %s exceeds five minutes", report.RPO)
	}

	var epoch Epoch
	for _, stage := range OrderedStages() {
		starting := StageRecord{DrillID: request.DrillID, Actor: request.Actor, Reason: request.Reason, Ticket: request.Ticket, Traceparent: request.Traceparent, Stage: stage, Outcome: "starting", Epoch: epoch, At: o.clock.Now().UTC()}
		if err := o.auditor.RecordRestoreStage(ctx, starting); err != nil {
			return report, fmt.Errorf("audit restore stage %d before execution: %w", stage, err)
		}
		if err := o.executeStage(ctx, stage, request, &epoch); err != nil {
			return report, fmt.Errorf("restore stage %d %s: %w", stage, stage, err)
		}
		completed := starting
		completed.Outcome = "completed"
		completed.Epoch = epoch
		completed.At = o.clock.Now().UTC()
		if err := o.auditor.RecordRestoreStage(ctx, completed); err != nil {
			return report, fmt.Errorf("audit restore stage %d completion: %w", stage, err)
		}
		report.Stages = append(report.Stages, completed)
	}
	report.Epoch = epoch
	report.CompletedAt = o.clock.Now().UTC()
	report.RTO = report.CompletedAt.Sub(started)
	if report.RTO > 30*time.Minute {
		return report, fmt.Errorf("restore RTO %s exceeds thirty minutes", report.RTO)
	}
	report.Completed = true
	// Only an approved Gate-F product and production-like drill may set this
	// retained evidence field. The product-neutral harness always leaves false.
	report.ProductionProof = false
	return report, nil
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
