package execution_test

import (
	"context"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/ancyloce/anvilkit-agent-service/internal/agent"
	"github.com/ancyloce/anvilkit-agent-service/internal/execution"
	"github.com/ancyloce/anvilkit-agent-service/internal/modelgateway"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/tools"
	"github.com/ancyloce/anvilkit-agent-service/internal/workflow"
)

// driftingToolMaterial answers with the pinned argument schema digest the run
// froze but a tool definition whose signed fields have been altered. It is
// what a process running tool material that no longer matches the approved
// catalog looks like from the executor's side.
type driftingToolMaterial struct {
	inner  execution.ToolMaterial
	mutate func(tools.Definition) tools.Definition
}

func (m driftingToolMaterial) ComponentDigest(componentName string) (string, bool) {
	return m.inner.ComponentDigest(componentName)
}

func (m driftingToolMaterial) ToolDefinition(componentName string) (tools.Definition, bool) {
	definition, known := m.inner.ToolDefinition(componentName)
	if !known {
		return definition, known
	}
	return m.mutate(definition), true
}

// Execution is bound to the complete signed ToolDefinition, not only to the
// argument-schema digest. Any drift in the capability, side-effect class,
// risk, approval requirement, timeout, or retry policy stops the run before a
// provider is reached.
func TestSignedToolDefinitionDriftStopsTheRun(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(tools.Definition) tools.Definition
	}{
		{"capability", func(d tools.Definition) tools.Definition { d.Capability = "domain.apply"; return d }},
		{"side effect class", func(d tools.Definition) tools.Definition { d.SideEffectClass = "domain-effect"; return d }},
		{"risk class", func(d tools.Definition) tools.Definition { d.RiskClass = "high"; return d }},
		{"approval policy", func(d tools.Definition) tools.Definition {
			d.ApprovalPolicy.Digest = "sha256:" + hex.EncodeToString(make([]byte, 32))
			return d
		}},
		{"timeout policy", func(d tools.Definition) tools.Definition {
			d.TimeoutPolicy.TimeoutMilliseconds = 600000
			return d
		}},
		{"retry policy attempts", func(d tools.Definition) tools.Definition {
			d.RetryPolicy.MaximumAttempts = 8
			return d
		}},
		{"retry policy retryability", func(d tools.Definition) tools.Definition {
			d.RetryPolicy.Retryability = []string{"never"}
			return d
		}},
		{"accepted data classes", func(d tools.Definition) tools.Definition {
			d.AcceptedDataClasses = []string{"restricted"}
			return d
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			base := newHarness(t, [][]byte{finalPlan()})
			material := base.toolMaterial()
			h := newHarness(t, [][]byte{finalPlan()}, func(options *harnessOptions) {
				options.toolMaterial = driftingToolMaterial{inner: material, mutate: test.mutate}
			})
			input := h.seedRun("artifact-validation")
			outcome, err := h.engine.ExecuteRun(context.Background(), input)
			if err != nil {
				t.Fatal(err)
			}
			if outcome.Terminal != workflow.TerminalRefused || outcome.Problem == nil || outcome.Problem.Code != string(problem.CodeContractInvalid) {
				t.Fatalf("outcome = %+v, want a refusal on unapproved tool material", outcome)
			}
			if len(h.adapter.Requests()) != 0 {
				t.Fatal("a run against unapproved tool material must not reach a provider")
			}
		})
	}
}

// The running tool profile is built from the catalog's signed definitions, so
// the material the process dispatches and the material the catalog attests
// agree by construction and the per-run check passes.
func TestApprovedToolMaterialMatchesTheSignedCatalog(t *testing.T) {
	h := newHarness(t, [][]byte{finalPlan()})
	registry := h.registry
	for _, binding := range registry.ToolBindings() {
		definition, known := h.toolMaterial().ToolDefinition(binding.ToolID)
		if !known {
			t.Fatalf("%s is signed but not running", binding.ToolID)
		}
		if definition.Capability != binding.Capability || definition.SideEffectClass != binding.SideEffectClass || definition.RiskClass != binding.RiskClass {
			t.Fatalf("%s runs material the catalog did not sign: %+v", binding.ToolID, definition)
		}
		if definition.TimeoutPolicy.TimeoutMilliseconds != binding.TimeoutMilliseconds || definition.RetryPolicy.MaximumAttempts != binding.MaximumAttempts {
			t.Fatalf("%s runs a dispatch envelope the catalog did not sign: %+v", binding.ToolID, definition)
		}
	}
}

// unsignedModelPolicies serves a model policy whose digest is not the one the
// approved catalog carries, which is what an unattested or replaced policy
// looks like to selection.
type unsignedModelPolicies struct {
	inner  execution.ModelPolicySource
	mutate func(agent.ModelPolicy) agent.ModelPolicy
}

func (p unsignedModelPolicies) ModelPolicy(policyID, version string) (agent.ModelPolicy, bool) {
	policy, known := p.inner.ModelPolicy(policyID, version)
	if !known {
		return policy, known
	}
	return p.mutate(policy), true
}

// Provider selection uses the signed ModelPolicy and nothing else. A policy
// the approved catalog does not carry, or one whose digest no longer matches
// the reference the definition pinned, selects nothing.
func TestModelPolicyDriftStopsProviderSelection(t *testing.T) {
	registry := approvedRegistry(t)
	reference := agent.PolicyReference{PolicyID: "policy.model.default", Version: "v1"}
	signed, known := registry.ModelPolicy(reference.PolicyID, reference.Version)
	if !known {
		t.Fatal("the approved catalog carries no model policy")
	}
	reference.Digest = signed.Digest

	tests := []struct {
		name     string
		policies execution.ModelPolicySource
	}{
		{"policy is not in the approved catalog", missingPolicies{}},
		{"policy digest no longer matches the pinned reference", unsignedModelPolicies{inner: registry, mutate: func(policy agent.ModelPolicy) agent.ModelPolicy {
			policy.Digest = "sha256:" + hex.EncodeToString(make([]byte, 32))
			return policy
		}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ledger := execution.NewMemoryScriptLedger()
			adapter, err := execution.NewScriptedAdapter(ledger, finalPlan())
			if err != nil {
				t.Fatal(err)
			}
			stack, err := execution.NewControlledModelStack(adapter, systemClock{}, &execution.MemoryModelRecorder{}, test.policies)
			if err != nil {
				t.Fatal(err)
			}
			_, err = stack.Select(context.Background(), "workspace", reference)
			var details problem.Details
			if !errors.As(err, &details) || details.Code != string(problem.CodeContractInvalid) {
				t.Fatalf("selection error = %v, want %s", err, problem.CodeContractInvalid)
			}
		})
	}

	// The signed policy itself selects the controlled provider.
	ledger := execution.NewMemoryScriptLedger()
	adapter, err := execution.NewScriptedAdapter(ledger, finalPlan())
	if err != nil {
		t.Fatal(err)
	}
	stack, err := execution.NewControlledModelStack(adapter, systemClock{}, &execution.MemoryModelRecorder{}, registry)
	if err != nil {
		t.Fatal(err)
	}
	selection, err := stack.Select(context.Background(), "workspace", reference)
	if err != nil {
		t.Fatal(err)
	}
	if selection.Provider.ID != execution.ControlledProviderID {
		t.Fatalf("selected provider = %s", selection.Provider.ID)
	}
	if selection.PolicyVersion != signed.PolicyID+":"+signed.Version {
		t.Fatalf("selection policy version = %q, want the signed policy identity", selection.PolicyVersion)
	}
	if selection.PolicySnapshot.Capability != signed.Rules.Capability || selection.PolicySnapshot.MinimumSafety != signed.Rules.MinimumSafety {
		t.Fatalf("selection did not use the signed rules: %+v", selection.PolicySnapshot)
	}
	if selection.MaximumCostMicros != signed.Rules.MaximumCostMicros {
		t.Fatalf("selection cost ceiling = %d, want the signed ceiling %d", selection.MaximumCostMicros, signed.Rules.MaximumCostMicros)
	}
}

type missingPolicies struct{}

func (missingPolicies) ModelPolicy(string, string) (agent.ModelPolicy, bool) {
	return agent.ModelPolicy{}, false
}

// A provider operation settled by one adapter instance must be free for the
// next one. The ledger is the durable store both instances read, which is what
// a process or adapter restart looks like from the provider's side.
func TestProviderReplayAfterANewAdapterInstanceNeverCallsTheProviderAgain(t *testing.T) {
	ledger := execution.NewMemoryScriptLedger()
	first, err := execution.NewScriptedAdapter(ledger, finalPlan(), toolPlan())
	if err != nil {
		t.Fatal(err)
	}
	request := modelgateway.AdapterRequest{
		InvocationID:        "invocation.restart",
		IdempotencyKey:      "attempt.restart",
		Provider:            execution.ControlledProviderID,
		Context:             []byte("context"),
		MaximumOutputBytes:  65536,
		MaximumInputTokens:  1000,
		MaximumOutputTokens: 1000,
		MaximumTotalTokens:  2000,
		MaximumCostMicros:   1_000_000,
	}
	original, err := first.Invoke(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	billed, err := first.Billed(context.Background())
	if err != nil || billed != 1 {
		t.Fatalf("billed = %d err = %v, want the one operation", billed, err)
	}

	// A brand new adapter over the same durable ledger: a restarted process.
	restarted, err := execution.NewScriptedAdapter(ledger, finalPlan(), toolPlan())
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := restarted.Invoke(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if string(replayed.Output) != string(original.Output) {
		t.Fatal("the restarted adapter returned different bytes for a settled operation")
	}
	billed, err = restarted.Billed(context.Background())
	if err != nil || billed != 1 {
		t.Fatalf("billed after restart = %d err = %v, want no duplicate billing", billed, err)
	}

	// A genuinely new operation advances the script exactly once more, from
	// the durable position rather than from a fresh in-process counter.
	next := request
	next.IdempotencyKey = "attempt.restart.next"
	advanced, err := restarted.Invoke(context.Background(), next)
	if err != nil {
		t.Fatal(err)
	}
	if string(advanced.Output) == string(original.Output) {
		t.Fatal("a new operation did not advance the durable script position")
	}
	billed, err = restarted.Billed(context.Background())
	if err != nil || billed != 2 {
		t.Fatalf("billed = %d err = %v, want exactly two distinct operations", billed, err)
	}
}

// The controlled adapter has no process-local fallback: without its durable
// ledger it refuses to exist at all.
func TestControlledAdapterRefusesToRunWithoutADurableLedger(t *testing.T) {
	if _, err := execution.NewScriptedAdapter(nil, finalPlan()); err == nil {
		t.Fatal("an adapter was built with no durable provider ledger")
	}
}
