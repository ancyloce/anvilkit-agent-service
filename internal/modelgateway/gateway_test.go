package modelgateway

import (
	"context"
	"errors"
	"fmt"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func providers() Snapshot {
	return Snapshot{Version: "v1", Providers: []Provider{{ID: "preferred", ModelVersion: "preferred-v1", Regions: []string{"us"}, DataClasses: []DataClass{Public, Internal}, Capabilities: []string{"plan"}, SafetyLevel: 3, MaximumCostMicros: 100, Priority: 1, Enabled: true}, {ID: "backup", ModelVersion: "backup-v1", Regions: []string{"eu"}, DataClasses: []DataClass{Public}, Capabilities: []string{"plan"}, Retention: true, Training: true, SafetyLevel: 1, MaximumCostMicros: 1000, Priority: 2, Enabled: true}}}
}
func policy() Policy {
	return Policy{Version: "p1", AllowedProviders: []ProviderID{"preferred", "backup"}, AllowedRegions: []string{"us"}, DataClasses: []DataClass{Internal}, Capability: "plan", MinimumSafety: 2, MaximumCostMicros: 200}
}
func TestEligibilityReasonsRefusalBeforeDisclosureAndHistoricalReplay(t *testing.T) {
	registry, err := NewRegistry(providers())
	if err != nil {
		t.Fatal(err)
	}
	selection, err := registry.Select("workspace", policy())
	if err != nil || selection.Provider.ID != "preferred" {
		t.Fatalf("selection=%#v err=%v", selection, err)
	}
	old := selection.SnapshotDigest
	updated := providers()
	updated.Version = "v2"
	updated.Providers[0].Enabled = false
	if err := registry.Update(updated); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Select("workspace", policy()); err == nil {
		t.Fatal("disabled provider fell back to ineligible provider")
	}
	replayed, err := registry.Replay(old, "workspace", policy())
	if err != nil || !reflect.DeepEqual(selection, replayed) {
		t.Fatalf("historical=%#v err=%v", replayed, err)
	}
	record := InvocationRecord{WorkspaceID: "workspace", RegistrySnapshotDigest: selection.SnapshotDigest, PolicyVersion: selection.PolicyVersion, PolicyDigest: selection.PolicyDigest, PolicySnapshot: selection.PolicySnapshot, Provider: selection.Provider.ID, ModelVersion: selection.Provider.ModelVersion, Region: selection.Region}
	replayed, err = registry.ReplayInvocation(record)
	if err != nil || !reflect.DeepEqual(selection, replayed) {
		t.Fatalf("invocation evidence replay=%#v err=%v", replayed, err)
	}
	forged := record
	forged.PolicySnapshot.MaximumCostMicros++
	if _, err := registry.ReplayInvocation(forged); err == nil {
		t.Fatal("mutable policy content replayed under an old digest")
	}
	removals := map[string]bool{}
	_, err = registry.Select("workspace", Policy{Version: "deny", AllowedProviders: []ProviderID{"backup"}, AllowedRegions: []string{"us"}, DataClasses: []DataClass{Restricted}, Capability: "missing", MinimumSafety: 5, MaximumCostMicros: 1})
	var details problem.Details
	if !errors.As(err, &details) || details.Code != string(problem.CodeNoEligibleProvider) {
		t.Fatalf("err=%v", err)
	}
	snapshot := registry.Current()
	decision, _ := selectSnapshot(snapshot, "workspace", Policy{Version: "deny", AllowedProviders: []ProviderID{"backup"}, AllowedRegions: []string{"us"}, DataClasses: []DataClass{Restricted}, Capability: "missing", MinimumSafety: 5, MaximumCostMicros: 1})
	for _, removed := range decision.Removed {
		for _, reason := range removed.Reasons {
			removals[reason] = true
		}
	}
	for _, reason := range []string{"platform-disabled", "provider-not-allowed", "residency", "data-class", "retention", "training", "safety", "cost", "capability"} {
		if !removals[reason] {
			t.Fatalf("missing reason %s: %v", reason, removals)
		}
	}
}
func TestWorkspaceDisablementTakesEffectForNewInvocation(t *testing.T) {
	snapshot := providers()
	snapshot.Providers[0].DisabledWorkspaces = []string{"blocked"}
	registry, _ := NewRegistry(snapshot)
	if _, err := registry.Select("blocked", policy()); err == nil {
		t.Fatal("workspace disablement ignored")
	}
	if selected, err := registry.Select("other", policy()); err != nil || selected.Provider.ID != "preferred" {
		t.Fatalf("selected=%#v err=%v", selected, err)
	}
}

func TestEligibilityRemovalReasonsIndependently(t *testing.T) {
	tests := []struct {
		name   string
		reason string
		mutate func(*Provider, *Policy)
	}{
		{"platform", "platform-disabled", func(provider *Provider, _ *Policy) { provider.Enabled = false }},
		{"workspace", "workspace-disabled", func(provider *Provider, _ *Policy) { provider.DisabledWorkspaces = []string{"workspace"} }},
		{"allowlist", "provider-not-allowed", func(_ *Provider, policy *Policy) { policy.AllowedProviders = []ProviderID{"other"} }},
		{"residency", "residency", func(_ *Provider, policy *Policy) { policy.AllowedRegions = []string{"eu"} }},
		{"data-class", "data-class", func(_ *Provider, policy *Policy) { policy.DataClasses = []DataClass{Restricted} }},
		{"retention", "retention", func(provider *Provider, _ *Policy) { provider.Retention = true }},
		{"training", "training", func(provider *Provider, _ *Policy) { provider.Training = true }},
		{"safety", "safety", func(_ *Provider, policy *Policy) { policy.MinimumSafety = 4 }},
		{"cost", "cost", func(provider *Provider, _ *Policy) { provider.MaximumCostMicros = 201 }},
		{"capability", "capability", func(_ *Provider, policy *Policy) { policy.Capability = "missing" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			provider := providers().Providers[0]
			policy := policy()
			test.mutate(&provider, &policy)
			registry, err := NewRegistry(Snapshot{Version: "v1", Providers: []Provider{provider}})
			if err != nil {
				t.Fatal(err)
			}
			selection, err := registry.Select("workspace", policy)
			if err == nil || len(selection.Removed) != 1 || !reflect.DeepEqual(selection.Removed[0].Reasons, []string{test.reason}) {
				t.Fatalf("selection=%#v err=%v", selection, err)
			}
		})
	}
}

func TestRegistryDigestCanonicalizesSetOrdering(t *testing.T) {
	first := providers()
	second := providers()
	second.Providers[0], second.Providers[1] = second.Providers[1], second.Providers[0]
	second.Providers[1].DataClasses[0], second.Providers[1].DataClasses[1] = second.Providers[1].DataClasses[1], second.Providers[1].DataClasses[0]
	left, _ := NewRegistry(first)
	right, _ := NewRegistry(second)
	if left.Current().Digest != right.Current().Digest {
		t.Fatalf("equivalent registry order changed digest: %s != %s", left.Current().Digest, right.Current().Digest)
	}
}

func TestRegistryAndPolicyRejectDuplicateOrUnboundedAuthority(t *testing.T) {
	invalid := providers()
	invalid.Providers[0].Regions = []string{"us", "us"}
	if _, err := NewRegistry(invalid); err == nil {
		t.Fatal("duplicate provider region accepted")
	}
	registry, _ := NewRegistry(providers())
	reusedVersion := providers()
	reusedVersion.Providers[0].Enabled = false
	if err := registry.Update(reusedVersion); err == nil {
		t.Fatal("registry version was reused for different content")
	}
	duplicatePolicy := policy()
	duplicatePolicy.DataClasses = []DataClass{Internal, Internal}
	if _, err := registry.Select("workspace", duplicatePolicy); err == nil {
		t.Fatal("duplicate policy data class accepted")
	}
	if _, err := registry.Select("workspace", policy()); err != nil {
		t.Fatal(err)
	}
	reusedPolicy := policy()
	reusedPolicy.MaximumCostMicros++
	if _, err := registry.Select("workspace", reusedPolicy); err == nil {
		t.Fatal("policy version was reused for different content")
	}
	tooMany := policy()
	tooMany.AllowedRegions = make([]string, 65)
	for index := range tooMany.AllowedRegions {
		tooMany.AllowedRegions[index] = fmt.Sprintf("region-%d", index)
	}
	if _, err := registry.Select("workspace", tooMany); err == nil {
		t.Fatal("unbounded policy regions accepted")
	}
}

type recorder struct {
	lock             sync.Mutex
	before, complete int
	records          []InvocationRecord
}

func (r *recorder) BeforeDisclosure(_ context.Context, value InvocationRecord) error {
	r.lock.Lock()
	defer r.lock.Unlock()
	r.before++
	r.records = append(r.records, value)
	return nil
}
func (r *recorder) BeforeAttempt(_ context.Context, value InvocationRecord) error {
	r.lock.Lock()
	defer r.lock.Unlock()
	r.records = append(r.records, value)
	return nil
}
func (r *recorder) Complete(_ context.Context, value InvocationRecord) error {
	r.lock.Lock()
	defer r.lock.Unlock()
	r.complete++
	r.records = append(r.records, value)
	return nil
}

type clock struct{ now time.Time }

func (c clock) Now() time.Time { return c.now }

type sleeper struct{}

func (sleeper) Sleep(context.Context, time.Duration) error { return nil }

type advancingClock struct {
	lock sync.Mutex
	now  time.Time
}

func (c *advancingClock) Now() time.Time {
	c.lock.Lock()
	defer c.lock.Unlock()
	return c.now
}

type advancingSleeper struct {
	clock  *advancingClock
	delays []time.Duration
}

func (s *advancingSleeper) Sleep(ctx context.Context, delay time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.delays = append(s.delays, delay)
	s.clock.lock.Lock()
	s.clock.now = s.clock.now.Add(delay)
	s.clock.lock.Unlock()
	return nil
}

type adapter struct {
	calls    int
	retry    int
	response AdapterResponse
}

func (a *adapter) Invoke(ctx context.Context, request AdapterRequest) (AdapterResponse, error) {
	a.calls++
	if request.InvocationID == "" || request.PhysicalAttemptID == "" || len(request.Context) == 0 {
		return AdapterResponse{}, errors.New("missing pre-disclosure identity")
	}
	if a.calls <= a.retry {
		return AdapterResponse{}, RetryableError{errors.New("retry")}
	}
	return a.response, nil
}

// requestLimitsBudget authorizes every physical attempt at the request's own
// ceilings. Budget policy is exercised in the planning and runner suites; here
// the port only has to be present and permissive.
type requestLimitsBudget struct {
	inputTokens, outputTokens, costMicros int64
}

func (b requestLimitsBudget) Authorize(int, Usage) (AttemptLimits, error) {
	return AttemptLimits{MaximumInputTokens: b.inputTokens, MaximumOutputTokens: b.outputTokens, MaximumTotalTokens: b.inputTokens + b.outputTokens, MaximumCostMicros: b.costMicros}, nil
}

func TestInvocationRecordsIdentityBeforeDisclosureAndEnforcesBounds(t *testing.T) {
	snapshot := providers()
	registry, _ := NewRegistry(snapshot)
	selection, _ := registry.Select("workspace", policy())
	recording := &recorder{}
	provider := &adapter{retry: 1, response: AdapterResponse{Output: []byte(`{"ok":true}`), InputTokens: 2, OutputTokens: 2, CostMicros: 3}}
	gateway, _ := NewGateway(map[ProviderID]Adapter{"preferred": provider}, recording, clock{time.Unix(1, 0)}, sleeper{})
	response, record, err := gateway.Invoke(context.Background(), InvokeRequest{RunID: "run", WorkspaceID: "workspace", ProjectID: "project", IdempotencyKey: "run:g1:turn-0000", Selection: selection, Context: []byte("minimal"), DataClasses: []DataClass{Internal}, MaximumOutputBytes: 100, MaximumInputTokens: 10, MaximumOutputTokens: 10, MaximumTotalTokens: 20, MaximumCostMicros: 10, Timeout: time.Second, MaximumAttempts: 2, RetryBudget: time.Second, Budget: requestLimitsBudget{inputTokens: 10, outputTokens: 10, costMicros: 10}})
	if err != nil || string(response.Output) != `{"ok":true}` || len(record.PhysicalAttempts) != 2 || record.RegistrySnapshotDigest != selection.SnapshotDigest || record.PolicyVersion != "p1" || record.PolicyDigest != selection.PolicyDigest || !reflect.DeepEqual(record.PolicySnapshot, selection.PolicySnapshot) || record.Provider != "preferred" || record.ModelVersion != "preferred-v1" || record.Region != "us" || recording.before != 1 {
		t.Fatalf("record=%#v response=%#v err=%v", record, response, err)
	}
	provider.response.Output = make([]byte, 101)
	_, _, err = gateway.Invoke(context.Background(), InvokeRequest{RunID: "run2", WorkspaceID: "workspace", ProjectID: "project", IdempotencyKey: "run2:g1:turn-0000", Selection: selection, Context: []byte("minimal"), DataClasses: []DataClass{Internal}, MaximumOutputBytes: 100, MaximumInputTokens: 10, MaximumOutputTokens: 10, MaximumTotalTokens: 20, MaximumCostMicros: 10, Timeout: time.Second, MaximumAttempts: 2, RetryBudget: time.Second, Budget: requestLimitsBudget{inputTokens: 10, outputTokens: 10, costMicros: 10}})
	var details problem.Details
	if !errors.As(err, &details) || details.Code != string(problem.CodeProviderLimitExceeded) {
		t.Fatalf("limit err=%v", err)
	}
}

func TestNoEligibleProviderRefusesBeforeAnyDisclosure(t *testing.T) {
	snapshot := providers()
	for index := range snapshot.Providers {
		snapshot.Providers[index].Enabled = false
	}
	registry, _ := NewRegistry(snapshot)
	recording := &recorder{}
	provider := &adapter{}
	gateway, _ := NewGateway(map[ProviderID]Adapter{"preferred": provider}, recording, clock{time.Unix(1, 0)}, sleeper{})
	_, _, err := gateway.InvokeEligible(context.Background(), registry, policy(), InvokeRequest{RunID: "run", WorkspaceID: "workspace", ProjectID: "project", IdempotencyKey: "run:g1:turn-0000", Context: []byte("must-not-leave"), MaximumOutputBytes: 100, MaximumInputTokens: 10, MaximumOutputTokens: 10, MaximumTotalTokens: 20, MaximumCostMicros: 10, Timeout: time.Second, MaximumAttempts: 1, Budget: requestLimitsBudget{inputTokens: 10, outputTokens: 10, costMicros: 10}})
	var details problem.Details
	if !errors.As(err, &details) || details.Code != string(problem.CodeNoEligibleProvider) || provider.calls != 0 || recording.before != 0 {
		t.Fatalf("err=%v calls=%d records=%d", err, provider.calls, recording.before)
	}
}

func TestAdapterTimeoutCancellationRetryJitterAndBudget(t *testing.T) {
	registry, _ := NewRegistry(providers())
	selection, _ := registry.Select("workspace", policy())
	recording := &recorder{}
	retrying := &adapter{retry: 2, response: AdapterResponse{Output: []byte(`{}`), InputTokens: 1, OutputTokens: 1, CostMicros: 1}}
	clock := &advancingClock{now: time.Unix(1, 0)}
	sleeper := &advancingSleeper{clock: clock}
	gateway, _ := NewGateway(map[ProviderID]Adapter{"preferred": retrying}, recording, clock, sleeper)
	base := InvokeRequest{RunID: "run", WorkspaceID: "workspace", ProjectID: "project", IdempotencyKey: "run:g1:turn-0000", Selection: selection, Context: []byte("minimal"), DataClasses: []DataClass{Internal}, MaximumOutputBytes: 10, MaximumInputTokens: 10, MaximumOutputTokens: 10, MaximumTotalTokens: 20, MaximumCostMicros: 10, Timeout: time.Second, MaximumAttempts: 3, RetryBudget: time.Second, Budget: requestLimitsBudget{inputTokens: 10, outputTokens: 10, costMicros: 10}}
	if _, record, err := gateway.Invoke(context.Background(), base); err != nil || len(record.PhysicalAttempts) != 3 || !reflect.DeepEqual(sleeper.delays, []time.Duration{retryJitter(InvocationIdentity(base.IdempotencyKey), 1), retryJitter(InvocationIdentity(base.IdempotencyKey), 2)}) {
		t.Fatalf("record=%#v delays=%v err=%v", record, sleeper.delays, err)
	}

	retrying.calls = 0
	clock.now = time.Unix(1, 0)
	sleeper.delays = nil
	base.RunID = "budget"
	base.RetryBudget = retryJitter(InvocationIdentity(base.IdempotencyKey), 1) / 2
	if _, record, err := gateway.Invoke(context.Background(), base); err == nil || len(record.PhysicalAttempts) != 1 || len(sleeper.delays) != 0 {
		t.Fatalf("retry budget escaped: record=%#v delays=%v err=%v", record, sleeper.delays, err)
	}

	clock.now = time.Unix(1, 0)
	sleeper.delays = nil
	slowFailure := AdapterFunc(func(context.Context, AdapterRequest) (AdapterResponse, error) {
		clock.lock.Lock()
		clock.now = clock.now.Add(2 * time.Second)
		clock.lock.Unlock()
		return AdapterResponse{}, RetryableError{errors.New("slow retryable failure")}
	})
	gateway, _ = NewGateway(map[ProviderID]Adapter{"preferred": slowFailure}, &recorder{}, clock, sleeper)
	base.RunID = "slow-budget"
	base.RetryBudget = time.Second
	if _, record, err := gateway.Invoke(context.Background(), base); err == nil || len(record.PhysicalAttempts) != 1 || len(sleeper.delays) != 0 {
		t.Fatalf("adapter duration escaped retry budget: record=%#v delays=%v err=%v", record, sleeper.delays, err)
	}

	blocking := AdapterFunc(func(ctx context.Context, _ AdapterRequest) (AdapterResponse, error) {
		<-ctx.Done()
		return AdapterResponse{}, ctx.Err()
	})
	gateway, _ = NewGateway(map[ProviderID]Adapter{"preferred": blocking}, &recorder{}, clock, sleeper)
	base.RunID = "timeout"
	base.MaximumAttempts = 1
	base.Timeout = time.Millisecond
	base.RetryBudget = 0
	started := time.Now()
	if _, _, err := gateway.Invoke(context.Background(), base); err == nil || time.Since(started) > time.Second {
		t.Fatalf("timeout not enforced: %v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	base.RunID = "canceled"
	if _, _, err := gateway.Invoke(canceled, base); err == nil {
		t.Fatal("caller cancellation ignored")
	}
}

type AdapterFunc func(context.Context, AdapterRequest) (AdapterResponse, error)

func (function AdapterFunc) Invoke(ctx context.Context, request AdapterRequest) (AdapterResponse, error) {
	return function(ctx, request)
}

func TestAdapterAccountingLimitsFailClosed(t *testing.T) {
	registry, _ := NewRegistry(providers())
	selection, _ := registry.Select("workspace", policy())
	responses := []AdapterResponse{
		{Output: make([]byte, 11)},
		{Output: []byte(`{}`), InputTokens: 11},
		{Output: []byte(`{}`), OutputTokens: 11},
		{Output: []byte(`{}`), CostMicros: 11},
		{Output: []byte(`{}`), InputTokens: -1},
		{Output: []byte(`{}`), Continuation: make([]byte, 16385)},
	}
	for index, response := range responses {
		t.Run(fmt.Sprintf("limit-%d", index), func(t *testing.T) {
			provider := &adapter{response: response}
			gateway, _ := NewGateway(map[ProviderID]Adapter{"preferred": provider}, &recorder{}, clock{time.Unix(1, 0)}, sleeper{})
			_, _, err := gateway.Invoke(context.Background(), InvokeRequest{RunID: fmt.Sprintf("run-%d", index), WorkspaceID: "workspace", ProjectID: "project", IdempotencyKey: fmt.Sprintf("run-%d:g1:turn-0000", index), Selection: selection, Context: []byte("minimal"), DataClasses: []DataClass{Internal}, MaximumOutputBytes: 10, MaximumInputTokens: 10, MaximumOutputTokens: 10, MaximumTotalTokens: 20, MaximumCostMicros: 10, Timeout: time.Second, MaximumAttempts: 1, Budget: requestLimitsBudget{inputTokens: 10, outputTokens: 10, costMicros: 10}})
			var details problem.Details
			if !errors.As(err, &details) || details.Code != string(problem.CodeProviderLimitExceeded) {
				t.Fatalf("response=%#v err=%v", response, err)
			}
		})
	}
}

// Every provider identity is derived from the caller's durable operation key,
// so recovery re-invoking the same durable step reproduces the same
// invocation, the same attempt identities, and the same provider-visible
// idempotency key instead of allocating fresh ones.
func TestProviderIdentitiesAreDerivedFromTheDurableOperationKey(t *testing.T) {
	registry, _ := NewRegistry(providers())
	selection, _ := registry.Select("workspace", policy())
	base := InvokeRequest{RunID: "run", WorkspaceID: "workspace", ProjectID: "project", IdempotencyKey: "run:g1:turn-0000:plan-attempt-00", Selection: selection, Context: []byte("minimal"), DataClasses: []DataClass{Internal}, MaximumOutputBytes: 100, MaximumInputTokens: 10, MaximumOutputTokens: 10, MaximumTotalTokens: 20, MaximumCostMicros: 10, Timeout: time.Second, MaximumAttempts: 2, RetryBudget: time.Second, Budget: requestLimitsBudget{inputTokens: 10, outputTokens: 10, costMicros: 10}}

	observed := []AdapterRequest{}
	capturing := AdapterFunc(func(_ context.Context, request AdapterRequest) (AdapterResponse, error) {
		observed = append(observed, request)
		return AdapterResponse{Output: []byte(`{"ok":true}`), InputTokens: 1, OutputTokens: 1, CostMicros: 1}, nil
	})
	gateway, _ := NewGateway(map[ProviderID]Adapter{"preferred": capturing}, &recorder{}, clock{time.Unix(1, 0)}, sleeper{})

	_, first, err := gateway.Invoke(context.Background(), base)
	if err != nil {
		t.Fatal(err)
	}
	_, second, err := gateway.Invoke(context.Background(), base)
	if err != nil {
		t.Fatal(err)
	}
	if first.InvocationID != second.InvocationID || first.InvocationID != InvocationIdentity(base.IdempotencyKey) {
		t.Fatalf("invocation identity is not derived from the operation key: %q vs %q", first.InvocationID, second.InvocationID)
	}
	if !reflect.DeepEqual(first.PhysicalAttempts, second.PhysicalAttempts) {
		t.Fatalf("attempt identities drifted: %v vs %v", first.PhysicalAttempts, second.PhysicalAttempts)
	}
	if len(observed) != 2 || observed[0].IdempotencyKey == "" || observed[0].IdempotencyKey != observed[1].IdempotencyKey {
		t.Fatalf("provider idempotency key drifted: %+v", observed)
	}
	if observed[0].IdempotencyKey != string(AttemptIdentity(first.InvocationID, 1)) {
		t.Fatalf("provider idempotency key %q is not the attempt identity", observed[0].IdempotencyKey)
	}

	// A different durable operation must produce a different identity.
	other := base
	other.IdempotencyKey = "run:g1:turn-0001:plan-attempt-00"
	_, third, err := gateway.Invoke(context.Background(), other)
	if err != nil {
		t.Fatal(err)
	}
	if third.InvocationID == first.InvocationID {
		t.Fatal("distinct durable operations shared a provider identity")
	}
}

// The operation key is mandatory: without it the gateway cannot produce a
// stable identity, so it must refuse before any disclosure.
func TestInvocationWithoutADurableOperationKeyFailsClosed(t *testing.T) {
	registry, _ := NewRegistry(providers())
	selection, _ := registry.Select("workspace", policy())
	provider := &adapter{response: AdapterResponse{Output: []byte(`{}`)}}
	recording := &recorder{}
	gateway, _ := NewGateway(map[ProviderID]Adapter{"preferred": provider}, recording, clock{time.Unix(1, 0)}, sleeper{})
	request := InvokeRequest{RunID: "run", WorkspaceID: "workspace", ProjectID: "project", Selection: selection, Context: []byte("minimal"), DataClasses: []DataClass{Internal}, MaximumOutputBytes: 100, MaximumInputTokens: 10, MaximumOutputTokens: 10, MaximumTotalTokens: 20, MaximumCostMicros: 10, Timeout: time.Second, MaximumAttempts: 1, Budget: requestLimitsBudget{inputTokens: 10, outputTokens: 10, costMicros: 10}}
	_, _, err := gateway.Invoke(context.Background(), request)
	var details problem.Details
	if !errors.As(err, &details) || details.Code != string(problem.CodeRequestInvalid) {
		t.Fatalf("missing operation key err = %v", err)
	}
	if provider.calls != 0 || recording.before != 0 {
		t.Fatalf("refused invocation disclosed context: calls=%d records=%d", provider.calls, recording.before)
	}
	request.IdempotencyKey = strings.Repeat("k", maximumIdempotencyKeyBytes+1)
	if _, _, err := gateway.Invoke(context.Background(), request); err == nil {
		t.Fatal("an unbounded operation key was accepted")
	}
}
