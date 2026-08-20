package main

import (
	"os/exec"
	"strings"
	"testing"
)

// The production binary must link every module the platform composition
// wires. A module that silently falls out of the import closure is a module
// the workflow can no longer reach, so this inventory fails the build the
// moment composition stops constructing one.
func TestProductionClosureCarriesEveryRequiredModule(t *testing.T) {
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Skip("the go tool is unavailable")
	}
	output, err := exec.Command(goBinary, "list", "-deps", ".").CombinedOutput()
	if err != nil {
		t.Fatalf("list production closure: %v\n%s", err, output)
	}
	closure := string(output)
	required := []string{
		"internal/agent/runner", // thin AgentRunner
		"internal/applyauth",    // apply-authorization issuance
		"internal/applyauth/postgres",
		"internal/artifacts", // immutable artifact lifecycle
		"internal/artifacts/postgres",
		"internal/authority", // one current-authority source
		"internal/budget",    // Platform budget controller
		"internal/budget/postgres",
		"internal/contextcompiler", // authorized context compilation
		"internal/contextcompiler/postgres",
		"internal/contractclient", // Contract Runtime boundary
		"internal/contractclient/postgres",
		"internal/execution", // the real executor pipeline
		"internal/execution/postgres",
		"internal/interrupts",   // durable input/approval waits
		"internal/journal",      // durable receipts
		"internal/modelgateway", // provider-neutral model gateway
		"internal/modelgateway/postgres",
		"internal/planning",  // attempt budgets
		"internal/recovery",  // non-rollback recovery epoch
		"internal/runs",      // run aggregate and transitions
		"internal/scheduler", // fenced task dispatch
		"internal/telemetry", // structured observability
		"internal/tools",     // Tool Guard
		"internal/tools/postgres",
		"internal/usage", // all-attempt usage accounting
		"internal/usage/postgres",
		"internal/workflow",      // AgentRunWorkflow
		"internal/workflow/dbos", // the durable engine adapter
	}
	var missing []string
	for _, module := range required {
		if !strings.Contains(closure, "anvilkit-agent-service/"+module+"\n") {
			missing = append(missing, module)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("the production closure no longer reaches: %s", strings.Join(missing, ", "))
	}
	// The in-memory proof engine is test scaffolding and must never ship.
	if strings.Contains(closure, "anvilkit-agent-service/internal/workflow/memory\n") {
		t.Fatal("the in-memory workflow engine leaked into the production closure")
	}
}
