package modelgateway

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
)

// countingBudget authorizes a fixed number of physical attempts and records
// the usage it was told about before each one.
type countingBudget struct {
	fundedAttempts int
	observed       []Usage
	limits         AttemptLimits
}

func (b *countingBudget) Authorize(_ int, used Usage) (AttemptLimits, error) {
	b.observed = append(b.observed, used)
	if len(b.observed) > b.fundedAttempts {
		details := problem.New(problem.CodeBudgetDenied, "")
		details.Detail = "the pinned agent budget is exhausted"
		return AttemptLimits{}, details
	}
	return b.limits, nil
}

// meteringAdapter fails a fixed number of leading attempts while still
// reporting what those attempts consumed, and records the limits it was
// handed for each one.
type meteringAdapter struct {
	failures int
	calls    int
	handed   []AttemptLimits
	metered  AdapterResponse
}

func (a *meteringAdapter) Invoke(_ context.Context, request AdapterRequest) (AdapterResponse, error) {
	a.calls++
	a.handed = append(a.handed, AttemptLimits{MaximumInputTokens: request.MaximumInputTokens, MaximumOutputTokens: request.MaximumOutputTokens, MaximumTotalTokens: request.MaximumTotalTokens, MaximumCostMicros: request.MaximumCostMicros})
	response := AdapterResponse{InputTokens: a.metered.InputTokens, OutputTokens: a.metered.OutputTokens, CostMicros: a.metered.CostMicros}
	if a.calls <= a.failures {
		return response, RetryableError{Err: errors.New("transient provider failure")}
	}
	response.Output = []byte(`{"ok":true}`)
	return response, nil
}

func budgetInvokeRequest(selection Selection, budget AttemptBudget, attempts int) InvokeRequest {
	return InvokeRequest{
		RunID: "run", WorkspaceID: "workspace", ProjectID: "project",
		IdempotencyKey: "run:g1:turn-0000", Selection: selection,
		Context: []byte("minimal"), DataClasses: []DataClass{Internal},
		MaximumOutputBytes: 100, MaximumInputTokens: 100, MaximumOutputTokens: 100, MaximumTotalTokens: 200, MaximumCostMicros: 100,
		Timeout: time.Second, MaximumAttempts: attempts, RetryBudget: time.Minute, Budget: budget,
	}
}

// Every physical attempt — the first call and every transport retry — is
// authorized before it happens and accounted after it happens, and the
// authorized ceilings are handed to the adapter rather than merely checked
// against its answer.
func TestEveryPhysicalAttemptIsAuthorizedAccountedAndBounded(t *testing.T) {
	registry, _ := NewRegistry(providers())
	selection, _ := registry.Select("workspace", policy())
	provider := &meteringAdapter{failures: 2, metered: AdapterResponse{InputTokens: 3, OutputTokens: 2, CostMicros: 5}}
	gateway, _ := NewGateway(map[ProviderID]Adapter{"preferred": provider}, &recorder{}, clock{time.Unix(1, 0)}, sleeper{})
	budget := &countingBudget{fundedAttempts: 3, limits: AttemptLimits{MaximumInputTokens: 40, MaximumOutputTokens: 30, MaximumTotalTokens: 70, MaximumCostMicros: 20}}

	_, record, err := gateway.Invoke(context.Background(), budgetInvokeRequest(selection, budget, 3))
	if err != nil {
		t.Fatal(err)
	}
	if provider.calls != 3 || len(record.PhysicalAttempts) != 3 {
		t.Fatalf("physical attempts: adapter=%d recorded=%d", provider.calls, len(record.PhysicalAttempts))
	}
	if len(budget.observed) != 3 {
		t.Fatalf("budget consulted %d times, want once per physical attempt", len(budget.observed))
	}
	for index, want := range []Usage{
		{},
		{ModelCalls: 1, InputTokens: 3, OutputTokens: 2, CostMicros: 5},
		{ModelCalls: 2, InputTokens: 6, OutputTokens: 4, CostMicros: 10},
	} {
		if budget.observed[index] != want {
			t.Fatalf("usage before attempt %d = %+v, want %+v", index+1, budget.observed[index], want)
		}
	}
	if record.InputTokens != 9 || record.OutputTokens != 6 || record.CostMicros != 15 {
		t.Fatalf("recorded usage = %d/%d/%d, want every attempt counted", record.InputTokens, record.OutputTokens, record.CostMicros)
	}
	for index, handed := range provider.handed {
		if handed.MaximumInputTokens != 40 || handed.MaximumOutputTokens != 30 || handed.MaximumCostMicros != 20 {
			t.Fatalf("attempt %d was handed %+v, want the authorized ceilings", index+1, handed)
		}
	}
	identities := map[AttemptID]struct{}{}
	for _, attempt := range record.PhysicalAttempts {
		identities[attempt] = struct{}{}
	}
	if len(identities) != 3 {
		t.Fatalf("distinct physical attempt identities = %d, want 3", len(identities))
	}
}

// A retry the budget will not fund never reaches the provider, and what the
// earlier attempts consumed is still recorded.
func TestAnUnauthorizedRetryNeverReachesTheProvider(t *testing.T) {
	registry, _ := NewRegistry(providers())
	selection, _ := registry.Select("workspace", policy())
	provider := &meteringAdapter{failures: 3, metered: AdapterResponse{InputTokens: 3, OutputTokens: 2, CostMicros: 5}}
	gateway, _ := NewGateway(map[ProviderID]Adapter{"preferred": provider}, &recorder{}, clock{time.Unix(1, 0)}, sleeper{})
	budget := &countingBudget{fundedAttempts: 2, limits: AttemptLimits{MaximumInputTokens: 40, MaximumOutputTokens: 30, MaximumTotalTokens: 70, MaximumCostMicros: 20}}

	_, record, err := gateway.Invoke(context.Background(), budgetInvokeRequest(selection, budget, 3))
	var details problem.Details
	if !errors.As(err, &details) || details.Code != string(problem.CodeBudgetDenied) {
		t.Fatalf("exhausted budget err = %v", err)
	}
	if provider.calls != 2 || len(record.PhysicalAttempts) != 2 {
		t.Fatalf("physical attempts: adapter=%d recorded=%d, want exactly the funded two", provider.calls, len(record.PhysicalAttempts))
	}
	if record.InputTokens != 6 || record.OutputTokens != 4 || record.CostMicros != 10 {
		t.Fatalf("recorded usage = %d/%d/%d, want both funded attempts counted", record.InputTokens, record.OutputTokens, record.CostMicros)
	}
}

// An invocation with no attempt budget is refused before disclosure.
func TestAnInvocationWithoutAnAttemptBudgetIsRefused(t *testing.T) {
	registry, _ := NewRegistry(providers())
	selection, _ := registry.Select("workspace", policy())
	provider := &meteringAdapter{metered: AdapterResponse{InputTokens: 1, OutputTokens: 1, CostMicros: 1}}
	gateway, _ := NewGateway(map[ProviderID]Adapter{"preferred": provider}, &recorder{}, clock{time.Unix(1, 0)}, sleeper{})
	request := budgetInvokeRequest(selection, nil, 1)
	request.Budget = nil
	_, _, err := gateway.Invoke(context.Background(), request)
	var details problem.Details
	if !errors.As(err, &details) || details.Code != string(problem.CodeRequestInvalid) {
		t.Fatalf("missing attempt budget err = %v", err)
	}
	if provider.calls != 0 {
		t.Fatal("an unbudgeted invocation must not reach the provider")
	}
}

// refusingAttemptRecorder accepts the invocation but refuses to record any
// physical attempt, which is what a durable evidence store looks like when it
// is unavailable at exactly the wrong moment.
type refusingAttemptRecorder struct {
	completed []InvocationRecord
}

func (r *refusingAttemptRecorder) BeforeDisclosure(context.Context, InvocationRecord) error {
	return nil
}

func (r *refusingAttemptRecorder) BeforeAttempt(context.Context, InvocationRecord) error {
	return errors.New("attempt evidence store unavailable")
}

func (r *refusingAttemptRecorder) Complete(_ context.Context, value InvocationRecord) error {
	r.completed = append(r.completed, value)
	return nil
}

// A physical attempt becomes real only once the recorder has accepted it. If
// the recorder refuses, the provider must never be called and the attempt must
// consume nothing: no model call, no token, no cost, no retry slot, and no
// entry in the durable evidence.
func TestRecorderFailureConsumesNoAttemptAndNeverReachesTheProvider(t *testing.T) {
	registry, _ := NewRegistry(providers())
	selection, _ := registry.Select("workspace", policy())
	provider := &meteringAdapter{metered: AdapterResponse{InputTokens: 3, OutputTokens: 2, CostMicros: 5}}
	recorder := &refusingAttemptRecorder{}
	gateway, _ := NewGateway(map[ProviderID]Adapter{"preferred": provider}, recorder, clock{time.Unix(1, 0)}, sleeper{})
	budget := &countingBudget{fundedAttempts: 3, limits: AttemptLimits{MaximumInputTokens: 40, MaximumOutputTokens: 30, MaximumTotalTokens: 70, MaximumCostMicros: 20}}
	_, record, err := gateway.Invoke(context.Background(), budgetInvokeRequest(selection, budget, 3))
	if err == nil {
		t.Fatal("a refused attempt recording produced a successful invocation")
	}
	if provider.calls != 0 {
		t.Fatalf("provider calls = %d, want none: the attempt was never recorded", provider.calls)
	}
	if len(record.PhysicalAttempts) != 0 {
		t.Fatalf("physical attempts = %v, want none charged to the invocation", record.PhysicalAttempts)
	}
	if record.InputTokens != 0 || record.OutputTokens != 0 || record.CostMicros != 0 {
		t.Fatalf("record accounted %d/%d/%d, want nothing consumed", record.InputTokens, record.OutputTokens, record.CostMicros)
	}
	if len(budget.observed) != 1 {
		t.Fatalf("budget authorizations = %d, want exactly the one attempt that was never taken", len(budget.observed))
	}
	if len(recorder.completed) != 1 || len(recorder.completed[0].PhysicalAttempts) != 0 {
		t.Fatalf("completed evidence = %+v, want a closed invocation carrying no physical attempt", recorder.completed)
	}
}

// The pinned budget states an aggregate token limit as well as separate input
// and output limits. An invocation must not spend past the aggregate, and the
// ceiling handed to the adapter must reflect it.
func TestAggregateTokenCeilingBoundsTheAttemptAndItsAnswer(t *testing.T) {
	registry, _ := NewRegistry(providers())
	selection, _ := registry.Select("workspace", policy())
	provider := &meteringAdapter{metered: AdapterResponse{InputTokens: 30, OutputTokens: 25, CostMicros: 5}}
	gateway, _ := NewGateway(map[ProviderID]Adapter{"preferred": provider}, &recorder{}, clock{time.Unix(1, 0)}, sleeper{})
	// Input and output alone would authorize this call; the aggregate does not.
	budget := &countingBudget{fundedAttempts: 3, limits: AttemptLimits{MaximumInputTokens: 40, MaximumOutputTokens: 30, MaximumTotalTokens: 50, MaximumCostMicros: 20}}
	_, _, err := gateway.Invoke(context.Background(), budgetInvokeRequest(selection, budget, 1))
	var details problem.Details
	if !errors.As(err, &details) || details.Code != string(problem.CodeProviderLimitExceeded) {
		t.Fatalf("error = %v, want %s for an answer past the aggregate token limit", err, problem.CodeProviderLimitExceeded)
	}
	if len(provider.handed) != 1 || provider.handed[0].MaximumTotalTokens != 50 {
		t.Fatalf("handed limits = %+v, want the aggregate ceiling handed to the adapter", provider.handed)
	}
}
