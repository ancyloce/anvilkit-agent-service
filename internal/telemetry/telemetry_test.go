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

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
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

func TestSampleWorkflowProducesOneLinkedTraceAndPropagation(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	telemetry, err := New("agent-service", exporter, NewRedactor(nil))
	if err != nil {
		t.Fatal(err)
	}
	defer telemetry.Shutdown(context.Background())
	ctx, apiSpan := telemetry.Start(context.Background(), "api", Fields{WorkspaceID: "w", ProjectID: "p", RunID: "r"})
	header := http.Header{}
	telemetry.Inject(ctx, header)
	propagated := telemetry.Extract(context.Background(), header)
	workflowContext, workflowSpan := telemetry.Start(propagated, "workflow", Fields{WorkflowID: "r:v1", ExecutionGeneration: 1})
	adapterContext, adapterSpan := telemetry.Start(workflowContext, "adapter", Fields{Provider: "fake"})
	_, fakeSpan := telemetry.Start(adapterContext, "fake-dependency", Fields{Outcome: "accepted"})
	fakeSpan.End()
	adapterSpan.End()
	workflowSpan.End()
	apiSpan.End()
	spans := exporter.GetSpans()
	if len(spans) != 4 {
		t.Fatalf("got %d spans", len(spans))
	}
	traceID := spans[0].SpanContext.TraceID()
	for _, span := range spans {
		if span.SpanContext.TraceID() != traceID {
			t.Fatal("trace is not linked")
		}
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
