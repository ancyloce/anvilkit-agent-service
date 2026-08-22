package telemetry

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"

	"github.com/ancyloce/anvilkit-agent-service/internal/events"
	"github.com/ancyloce/anvilkit-agent-service/internal/events/spool"
)

// Fields is a governed telemetry projection. Sensitive bodies and URLs have no
// representation here; callers may supply only bounded identities and counters.
type Fields struct {
	Service, Version, Environment                                    string
	RequestID, CorrelationID                                         string
	WorkspaceID, ProjectID                                           string
	RunID, RootRunID, ParentRunID, WorkflowID                        string
	State, Stage, TaskID                                             string
	RecoveryEpoch, ExecutionGeneration, LeaseEpoch                   int64
	PhysicalAttemptID                                                string
	Provider, RequestedModel, ReportedModel, Capability, Build       string
	PromptDigest, ToolID, ContextDigest, PolicyVersion, EvaluationID string
	ArtifactID, ArtifactDigest                                       string
	SecurityGeneration, EventSequence                                int64
	Outcome, RawValidity, RepairValidity, AcceptedValidity           string
	Admission, Queue, DwellDeadline, ErrorCode, Retryability         string
	CostUnits, DurationMilliseconds                                  int64
}

func (f Fields) attributes(redactor *Redactor) ([]attribute.KeyValue, error) {
	values := []struct{ key, value string }{
		{"service.name", f.Service}, {"service.version", f.Version}, {"deployment.environment", f.Environment},
		{"request.id", f.RequestID}, {"correlation.id", f.CorrelationID}, {"workspace.id", f.WorkspaceID}, {"project.id", f.ProjectID},
		{"run.id", f.RunID}, {"root_run.id", f.RootRunID}, {"parent_run.id", f.ParentRunID}, {"workflow.id", f.WorkflowID},
		{"run.state", f.State}, {"workflow.stage", f.Stage}, {"task.id", f.TaskID}, {"physical_attempt.id", f.PhysicalAttemptID},
		{"provider.id", f.Provider}, {"model.requested", f.RequestedModel}, {"model.reported", f.ReportedModel}, {"capability.id", f.Capability}, {"build.id", f.Build},
		{"prompt.digest", f.PromptDigest}, {"tool.id", f.ToolID}, {"context.digest", f.ContextDigest}, {"policy.version", f.PolicyVersion}, {"evaluation.id", f.EvaluationID},
		{"artifact.id", f.ArtifactID}, {"artifact.digest", f.ArtifactDigest}, {"outcome", f.Outcome}, {"validity.raw", f.RawValidity}, {"validity.repair", f.RepairValidity}, {"validity.accepted", f.AcceptedValidity},
		{"admission.outcome", f.Admission}, {"queue.name", f.Queue}, {"dwell.deadline", f.DwellDeadline}, {"error.code", f.ErrorCode}, {"error.retryability", f.Retryability},
	}
	attributes := make([]attribute.KeyValue, 0, len(values)+7)
	for _, item := range values {
		if item.value == "" {
			continue
		}
		if !utf8.ValidString(item.value) || len(item.value) > 256 {
			return nil, fmt.Errorf("telemetry field %s exceeds governed bound", item.key)
		}
		if redactor.ContainsSecret(item.value) {
			return nil, fmt.Errorf("telemetry field %s contains registered secret", item.key)
		}
		attributes = append(attributes, attribute.String(item.key, item.value))
	}
	integers := []struct {
		key   string
		value int64
	}{{"recovery.epoch", f.RecoveryEpoch}, {"execution.generation", f.ExecutionGeneration}, {"lease.epoch", f.LeaseEpoch}, {"artifact.security_generation", f.SecurityGeneration}, {"event.sequence", f.EventSequence}, {"cost.units", f.CostUnits}, {"duration.ms", f.DurationMilliseconds}}
	for _, item := range integers {
		if item.value != 0 {
			attributes = append(attributes, attribute.Int64(item.key, item.value))
		}
	}
	return attributes, nil
}

type Telemetry struct {
	provider        *sdktrace.TracerProvider
	metricProvider  *sdkmetric.MeterProvider
	tracer          trace.Tracer
	propagator      propagation.TraceContext
	redactor        *Redactor
	workCounter     metric.Int64Counter
	duration        metric.Int64Histogram
	eventVisibility metric.Float64Histogram
	cursorFailures  metric.Int64Counter
	spoolHeld       metric.Int64Gauge
	spoolUnreadable metric.Int64Gauge
	spoolOldest     metric.Float64Gauge
	spoolPlaced     metric.Int64Counter
	spoolDeferred   metric.Int64Counter
	spoolSetAside   metric.Int64Counter
	spoolUnsettable metric.Int64Counter
}

func New(serviceName string, exporter sdktrace.SpanExporter, redactor *Redactor) (*Telemetry, error) {
	return newTelemetry(serviceName, exporter, redactor, nil)
}

func newTelemetry(serviceName string, exporter sdktrace.SpanExporter, redactor *Redactor, reader sdkmetric.Reader) (*Telemetry, error) {
	if redactor == nil {
		redactor = NewRedactor(nil)
	}
	options := []sdktrace.TracerProviderOption{sdktrace.WithSampler(sdktrace.AlwaysSample()), sdktrace.WithResource(resource.NewSchemaless(attribute.String("service.name", serviceName)))}
	if exporter != nil {
		options = append(options, sdktrace.WithSpanProcessor(sdktrace.NewSimpleSpanProcessor(exporter)))
	}
	provider := sdktrace.NewTracerProvider(options...)
	var metricOptions []sdkmetric.Option
	if reader != nil {
		metricOptions = append(metricOptions, sdkmetric.WithReader(reader))
	}
	metricProvider := sdkmetric.NewMeterProvider(metricOptions...)
	meter := metricProvider.Meter("anvilkit-agent-service")
	workCounter, err := meter.Int64Counter("anvilkit.agent.work.total")
	if err != nil {
		return nil, fmt.Errorf("create governed work counter: %w", err)
	}
	duration, err := meter.Int64Histogram("anvilkit.agent.duration.milliseconds")
	if err != nil {
		return nil, fmt.Errorf("create governed duration histogram: %w", err)
	}
	eventVisibility, err := meter.Float64Histogram("agent_event_visibility_seconds", metric.WithUnit("s"))
	if err != nil {
		return nil, fmt.Errorf("create event visibility histogram: %w", err)
	}
	cursorFailures, err := meter.Int64Counter("agent_event_stream_cursor_record_failures_total")
	if err != nil {
		return nil, fmt.Errorf("create stream cursor record failure counter: %w", err)
	}
	spoolHeld, err := meter.Int64Gauge("agent_event_stream_cursor_spool_held_records")
	if err != nil {
		return nil, fmt.Errorf("create stream cursor spool backlog gauge: %w", err)
	}
	spoolUnreadable, err := meter.Int64Gauge("agent_event_stream_cursor_spool_unreadable_records")
	if err != nil {
		return nil, fmt.Errorf("create stream cursor spool unreadable-record gauge: %w", err)
	}
	spoolOldest, err := meter.Float64Gauge("agent_event_stream_cursor_spool_oldest_record_seconds", metric.WithUnit("s"))
	if err != nil {
		return nil, fmt.Errorf("create stream cursor spool oldest-record gauge: %w", err)
	}
	spoolPlaced, err := meter.Int64Counter("agent_event_stream_cursor_spool_placed_total")
	if err != nil {
		return nil, fmt.Errorf("create stream cursor spool placement counter: %w", err)
	}
	spoolDeferred, err := meter.Int64Counter("agent_event_stream_cursor_spool_deferred_total")
	if err != nil {
		return nil, fmt.Errorf("create stream cursor spool deferral counter: %w", err)
	}
	spoolUnsettable, err := meter.Int64Counter("agent_event_stream_cursor_spool_set_aside_failed_total")
	if err != nil {
		return nil, err
	}
	spoolSetAside, err := meter.Int64Counter("agent_event_stream_cursor_spool_unreadable_total")
	if err != nil {
		return nil, fmt.Errorf("create stream cursor spool unreadable-record counter: %w", err)
	}
	return &Telemetry{provider: provider, metricProvider: metricProvider, spoolHeld: spoolHeld, spoolUnreadable: spoolUnreadable, spoolOldest: spoolOldest, spoolPlaced: spoolPlaced, spoolDeferred: spoolDeferred, spoolSetAside: spoolSetAside, spoolUnsettable: spoolUnsettable, tracer: provider.Tracer("anvilkit-agent-service"), propagator: propagation.TraceContext{}, redactor: redactor, workCounter: workCounter, duration: duration, eventVisibility: eventVisibility, cursorFailures: cursorFailures}, nil
}

func (t *Telemetry) Start(ctx context.Context, name string, fields Fields) (context.Context, trace.Span) {
	attributes, err := fields.attributes(t.redactor)
	if err != nil {
		attributes = []attribute.KeyValue{attribute.String("telemetry.guard", "rejected")}
	}
	return t.tracer.Start(ctx, name, trace.WithAttributes(attributes...))
}
func (t *Telemetry) Inject(ctx context.Context, header http.Header) {
	t.propagator.Inject(ctx, propagation.HeaderCarrier(header))
}
func (t *Telemetry) Extract(ctx context.Context, header http.Header) context.Context {
	return t.propagator.Extract(ctx, propagation.HeaderCarrier(header))
}
func (t *Telemetry) Observe(ctx context.Context, fields Fields) error {
	attributes, err := fields.attributes(t.redactor)
	if err != nil {
		return err
	}
	options := metric.WithAttributes(attributes...)
	t.workCounter.Add(ctx, 1, options)
	if fields.DurationMilliseconds > 0 {
		t.duration.Record(ctx, fields.DurationMilliseconds, options)
	}
	return nil
}
func (t *Telemetry) ObserveEventVisibility(ctx context.Context, workspaceID, projectID, runID string, duration time.Duration) {
	if duration < 0 {
		duration = 0
	}
	t.eventVisibility.Record(ctx, duration.Seconds(), metric.WithAttributes(attribute.Bool("authorized", true), attribute.String("workspace.id", workspaceID), attribute.String("project.id", projectID), attribute.String("run.id", runID)))
}

// ObserveCursorRecordFailure reports one disconnect record the durable
// recorder could not persist. The record is the only account of what a
// disconnected client actually received, so losing one is an operational fact
// an operator can act on: the counter names the run and connection it belongs
// to, and the cursor it would have recorded, which is exactly what recovering
// it by hand needs. The failure itself carries no detail beyond its category
// — a database error string is not a field this projection admits.
func (t *Telemetry) ObserveCursorRecordFailure(ctx context.Context, scope events.Scope, runID, connectionID, lastEventID, reason string, _ error) {
	t.cursorFailures.Add(ctx, 1, metric.WithAttributes(
		attribute.String("workspace.id", scope.WorkspaceID),
		attribute.String("project.id", scope.ProjectID),
		attribute.String("run.id", runID),
		attribute.String("connection.id", connectionID),
		attribute.String("cursor.last_event_id", lastEventID),
		attribute.String("disconnect.reason", reason),
	))
}

func (t *Telemetry) Shutdown(ctx context.Context) error {
	if err := t.provider.Shutdown(ctx); err != nil {
		return fmt.Errorf("shutdown telemetry: %w", err)
	}
	if err := t.metricProvider.Shutdown(ctx); err != nil {
		return fmt.Errorf("shutdown metrics: %w", err)
	}
	return nil
}

func ProhibitedFieldNames() []string {
	return []string{"prompt", "response", "retrieval", "puckData", "canvas", "pageIR", "componentSource", "imageBytes", "signedURL", "continuation", "secret"}
}
func isProhibited(name string) bool {
	lowered := strings.ToLower(name)
	if strings.HasSuffix(lowered, "digest") {
		return false
	}
	for _, prohibited := range ProhibitedFieldNames() {
		if strings.Contains(lowered, strings.ToLower(prohibited)) {
			return true
		}
	}
	return false
}

// ObserveCursorSpool reports what one spool sweep found. The three gauges are
// the operational state — how many disconnect records the instance is holding,
// how long the oldest of them has waited, and how many it has had to set aside
// as unreadable — and the counters are the flow through it. Backlog size alone
// does not distinguish a store that is briefly unreachable from one that is
// not coming back; the oldest record's age does, and an unreadable record never
// resolves with time at all. A record the sweep could not even set aside is
// counted apart from the ones it did, because the two ask for different
// remedies.
func (t *Telemetry) ObserveCursorSpool(ctx context.Context, stats spool.Stats, report spool.DrainReport) {
	t.spoolHeld.Record(ctx, int64(stats.Held))
	t.spoolUnreadable.Record(ctx, int64(stats.Quarantined))
	t.spoolOldest.Record(ctx, stats.OldestAge.Seconds())
	if report.Placed > 0 {
		t.spoolPlaced.Add(ctx, int64(report.Placed))
	}
	if report.Deferred > 0 {
		t.spoolDeferred.Add(ctx, int64(report.Deferred))
	}
	if report.Quarantined > 0 {
		t.spoolSetAside.Add(ctx, int64(report.Quarantined))
	}
	// A record the sweep meant to set aside and could not is a different fault
	// from one it set aside, and it is the one that needs someone. It is
	// counted separately rather than folded into the set-aside total, because
	// a volume that has stopped accepting renames would otherwise be reported
	// as a volume quietly doing its job.
	if report.QuarantineFailed > 0 {
		t.spoolUnsettable.Add(ctx, int64(report.QuarantineFailed))
	}
}

var _ spool.SpoolObserver = (*Telemetry)(nil)
