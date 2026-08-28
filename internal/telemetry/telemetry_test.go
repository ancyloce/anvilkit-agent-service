package telemetry

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/ancyloce/anvilkit-agent-service/internal/agent/runner"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

func TestFieldsStructurallyExcludesProhibitedPayloads(t *testing.T) {
	typeOf := reflect.TypeOf(Fields{})
	for index := range typeOf.NumField() {
		if isProhibited(typeOf.Field(index).Name) {
			t.Fatalf("prohibited field is representable: %s", typeOf.Field(index).Name)
		}
	}
	redactor := NewRedactor([]string{"super-secret"})
	if _, err := (Fields{Outcome: "contains super-secret"}).attributes(redactor); err == nil {
		t.Fatal("registered secret accepted as attribute")
	}
}

func TestRedactorRemovesSecretsFromLogsAndErrors(t *testing.T) {
	buffer := &bytes.Buffer{}
	redactor := NewRedactor([]string{"super-secret"})
	logger := slog.New(NewHandler(slog.NewJSONHandler(buffer, nil), redactor))
	logger.Error("failed super-secret", "error", "token=super-secret")
	if strings.Contains(buffer.String(), "super-secret") {
		t.Fatalf("secret leaked: %s", buffer.String())
	}
}

func TestPinnedServiceBoundarySetMaintainsCompleteTraceContinuity(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	telemetry, err := New("agent-service", exporter, NewRedactor(nil))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := telemetry.Shutdown(context.Background()); err != nil {
			t.Errorf("shutdown telemetry: %v", err)
		}
	}()
	boundaries := []string{"studio-stand-in", "platform-agent-service", "fake-pagix", "contract-runtime", "fake-worker", "simulated-domain-confirmation"}
	const traces = 100
	for index := 0; index < traces; index++ {
		ctx := context.Background()
		spans := make([]trace.Span, 0, len(boundaries))
		for _, boundary := range boundaries {
			header := http.Header{}
			telemetry.Inject(ctx, header)
			ctx = telemetry.Extract(context.Background(), header)
			var span trace.Span
			ctx, span = telemetry.Start(ctx, boundary, Fields{WorkspaceID: "w", ProjectID: "p", RunID: "r"})
			spans = append(spans, span)
		}
		for index := len(spans) - 1; index >= 0; index-- {
			spans[index].End()
		}
	}
	spans := exporter.GetSpans()
	if len(spans) != traces*len(boundaries) {
		t.Fatalf("got %d spans", len(spans))
	}
	byTrace := map[string]map[string]bool{}
	for _, span := range spans {
		traceID := span.SpanContext.TraceID().String()
		if byTrace[traceID] == nil {
			byTrace[traceID] = map[string]bool{}
		}
		byTrace[traceID][span.Name] = true
	}
	continuous := 0
	for _, names := range byTrace {
		complete := true
		for _, boundary := range boundaries {
			complete = complete && names[boundary]
		}
		if complete {
			continuous++
		}
	}
	if len(byTrace) != traces || continuous != traces {
		t.Fatalf("trace continuity=%d/%d unique=%d", continuous, traces, len(byTrace))
	}
}

type failedExporter struct{}

func (failedExporter) ExportSpans(context.Context, []sdktrace.ReadOnlySpan) error {
	return errors.New("backend unavailable")
}
func (failedExporter) Shutdown(context.Context) error { return nil }

func TestTelemetryOutageDoesNotBlockWork(t *testing.T) {
	telemetry, err := New("agent-service", failedExporter{}, NewRedactor(nil))
	if err != nil {
		t.Fatal(err)
	}
	ctx, span := telemetry.Start(context.Background(), "work", Fields{Outcome: "accepted"})
	_ = ctx
	span.End()
	if err := telemetry.Observe(ctx, Fields{Outcome: "accepted", DurationMilliseconds: 4}); err != nil {
		t.Fatal(err)
	}
}

// The dispatch path's metrics carry only bounded labels: the runtime unit,
// closed outcome and stage vocabularies, and governed reason codes. No task,
// run, attempt, fence, token, or signature value is a label, and the metric
// names share one namespace.
func TestDispatchMetricsCarryOnlyBoundedLabels(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	telemetry, err := newTelemetry("agent-service", nil, NewRedactor(nil), reader)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	const unit = "runtime.platform.page-change-manager"
	telemetry.ObserveDispatchStarted(ctx, unit)
	telemetry.ObserveDispatch(ctx, unit, runner.DispatchAnswered, 250*time.Millisecond)
	telemetry.ObserveReplacement(ctx, unit, "DISPATCH_FAILED")
	telemetry.ObserveRejection(ctx, runner.RejectionSignature, "RESULT_SIGNATURE_UNVERIFIED")
	telemetry.ObserveResult(ctx, unit, runner.ResultCommitted, 300*time.Millisecond)
	telemetry.ObserveAttemptUsage(ctx, unit, "completed", "RUNTIME_COMPLETED", runner.AttemptUsage{ModelCalls: 2, ToolCalls: 1, InputTokens: 40, OutputTokens: 12, DurationMilliseconds: 300, CostMicros: 1200})

	var resource metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &resource); err != nil {
		t.Fatal(err)
	}
	allowedKeys := map[string]bool{"runtime_unit": true, "outcome": true, "reason": true, "stage": true, "status": true, "reason_code": true, "meter": true}
	seen := map[string]bool{}
	for _, scope := range resource.ScopeMetrics {
		for _, candidate := range scope.Metrics {
			if !strings.HasPrefix(candidate.Name, "anvilkit_agent_service_runtime_") {
				continue
			}
			seen[candidate.Name] = true
			var attributeSets []attribute.Set
			switch data := candidate.Data.(type) {
			case metricdata.Sum[int64]:
				for _, point := range data.DataPoints {
					attributeSets = append(attributeSets, point.Attributes)
				}
			case metricdata.Histogram[float64]:
				for _, point := range data.DataPoints {
					attributeSets = append(attributeSets, point.Attributes)
				}
			}
			for _, set := range attributeSets {
				for _, value := range set.ToSlice() {
					if !allowedKeys[string(value.Key)] {
						t.Fatalf("%s carries the unbounded label %s", candidate.Name, value.Key)
					}
				}
			}
		}
	}
	for _, name := range []string{metricDispatches, metricDispatchWait, metricAttemptsActive, metricSuperseded, metricRejections, metricResults, metricResultLatency, metricAttemptsSettled, metricAttemptUsage} {
		if !seen[name] {
			t.Fatalf("%s was not recorded", name)
		}
	}
}

func TestAuthorizedEventVisibilityUsesTheBindingSLOHistogram(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	telemetry, err := newTelemetry("agent-service", nil, NewRedactor(nil), reader)
	if err != nil {
		t.Fatal(err)
	}
	telemetry.ObserveEventVisibility(context.Background(), "workspace", "project", "run", 1500*time.Millisecond)
	var resource metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &resource); err != nil {
		t.Fatal(err)
	}
	for _, scope := range resource.ScopeMetrics {
		for _, candidate := range scope.Metrics {
			if candidate.Name != "agent_event_visibility_seconds" {
				continue
			}
			if candidate.Unit != "s" {
				t.Fatalf("visibility unit=%q", candidate.Unit)
			}
			histogram, ok := candidate.Data.(metricdata.Histogram[float64])
			if !ok || len(histogram.DataPoints) != 1 || histogram.DataPoints[0].Count != 1 || histogram.DataPoints[0].Sum != 1.5 {
				t.Fatalf("visibility histogram=%#v", candidate.Data)
			}
			attributes := histogram.DataPoints[0].Attributes.ToSlice()
			for _, value := range attributes {
				if string(value.Key) == "authorized" && value.Value.AsBool() {
					return
				}
			}
			t.Fatal("visibility histogram omitted authorized=true")
		}
	}
	t.Fatal("binding event visibility histogram was not recorded")
}
