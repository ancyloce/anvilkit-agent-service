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
	eventVisibility metric.Int64Histogram
}

func New(serviceName string, exporter sdktrace.SpanExporter, redactor *Redactor) (*Telemetry, error) {
	if redactor == nil {
		redactor = NewRedactor(nil)
	}
	options := []sdktrace.TracerProviderOption{sdktrace.WithSampler(sdktrace.AlwaysSample()), sdktrace.WithResource(resource.NewSchemaless(attribute.String("service.name", serviceName)))}
	if exporter != nil {
		options = append(options, sdktrace.WithSpanProcessor(sdktrace.NewSimpleSpanProcessor(exporter)))
	}
	provider := sdktrace.NewTracerProvider(options...)
	metricProvider := sdkmetric.NewMeterProvider()
	meter := metricProvider.Meter("anvilkit-agent-service")
	workCounter, err := meter.Int64Counter("anvilkit.agent.work.total")
	if err != nil {
		return nil, fmt.Errorf("create governed work counter: %w", err)
	}
	duration, err := meter.Int64Histogram("anvilkit.agent.duration.milliseconds")
	if err != nil {
		return nil, fmt.Errorf("create governed duration histogram: %w", err)
	}
	eventVisibility, err := meter.Int64Histogram("anvilkit.agent.event.authorized_visibility.milliseconds")
	if err != nil {
		return nil, fmt.Errorf("create event visibility histogram: %w", err)
	}
	return &Telemetry{provider: provider, metricProvider: metricProvider, tracer: provider.Tracer("anvilkit-agent-service"), propagator: propagation.TraceContext{}, redactor: redactor, workCounter: workCounter, duration: duration, eventVisibility: eventVisibility}, nil
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
	t.eventVisibility.Record(ctx, duration.Milliseconds(), metric.WithAttributes(attribute.String("workspace.id", workspaceID), attribute.String("project.id", projectID), attribute.String("run.id", runID)))
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
