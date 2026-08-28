package main

import (
	"testing"
	"time"
)

// TestCrossProcessNormalDelegationAndArtifact is the cross-process happy path: a
// page-change run whose Manager delegates to the Specialist across the process
// boundary, the Specialist produces a real PageCandidate through the controlled
// artifact interface, and the run commits — every reasoning turn executed in a
// separate process, dispatched over authenticated HTTP, its signed result
// verified and fence-committed.
//
// The assertions cover every dimension the exit criterion names: final state,
// the six-event public registry, internal evidence, per-attempt usage, exactly
// one committed artifact, and the attempt/fence records of the cross-process
// dispatch.
func TestCrossProcessNormalDelegationAndArtifact(t *testing.T) {
	top := newTopology(t, "delegate-page-specialist,compose-page")
	runPath := top.createRun("cross-normal-1", "make the hero section bolder")
	runID := runIDOf(runPath)

	// The run reaches the approval gate through the cross-process reasoning
	// path: Manager delegate turn, Specialist compose turn, Manager conclusion.
	etag := top.waitForStatus(runPath, "awaiting_approval")
	top.approve(runPath, etag)
	top.waitForStatus(runPath, "completed")

	// Physical attempts were created and committed across the boundary. The
	// manager's two turns (delegate, conclude) and the specialist's one turn
	// are three logical tasks, each with at least one attempt and a committed
	// result.
	if tasks := top.count(`SELECT count(*) FROM agent_workflow.runtime_tasks WHERE run_id=$1`, runID); tasks < 3 {
		t.Fatalf("runtime tasks = %d, want at least 3 (manager delegate, specialist, manager conclude)", tasks)
	}
	if committed := top.count(`SELECT count(*) FROM agent_workflow.runtime_attempts a JOIN agent_workflow.runtime_tasks t ON t.workspace_id=a.workspace_id AND t.project_id=a.project_id AND t.task_id=a.task_id WHERE t.run_id=$1 AND a.dispatch_status='succeeded'`, runID); committed < 3 {
		t.Fatalf("succeeded attempts = %d, want at least 3", committed)
	}
	if results := top.count(`SELECT count(*) FROM agent_workflow.runtime_results r JOIN agent_workflow.runtime_tasks t ON t.workspace_id=r.workspace_id AND t.project_id=r.project_id AND t.task_id=r.task_id WHERE t.run_id=$1`, runID); results < 3 {
		t.Fatalf("committed runtime results = %d, want at least 3", results)
	}

	// The Specialist wrote exactly one candidate through the controlled
	// artifact interface, recorded once and immutably.
	if submissions := top.count(`SELECT count(*) FROM agent_workflow.runtime_artifact_submissions WHERE run_id=$1`, runID); submissions != 1 {
		t.Fatalf("candidate submissions = %d, want exactly 1", submissions)
	}

	// The governed effect left exactly one committed artifact and its full
	// durable trail — the same guarantees the in-process slice proves, now
	// reached across the process boundary.
	for name, want := range map[string]int{
		"committed artifacts": 1,
		"authorizations":      1,
		"domain submissions":  1,
	} {
		var query string
		switch name {
		case "committed artifacts":
			query = `SELECT count(*) FROM agent_artifacts.metadata WHERE run_id=$1 AND state='committed'`
		case "authorizations":
			query = `SELECT count(*) FROM agent_control.apply_authorizations WHERE run_id=$1`
		case "domain submissions":
			query = `SELECT count(*) FROM agent_control.domain_operations WHERE run_id=$1 AND status='applied' AND authorization_consumed`
		}
		if got := top.count(query, runID); got != want {
			t.Fatalf("%s = %d, want %d", name, got, want)
		}
	}

	// Per-attempt usage was measured by the runtimes and recorded against the
	// run's budget: the model calls the two reasoning units actually made are
	// accounted at non-zero cost, not declared as zero by a unit that could
	// understate them.
	if observations := top.count(`SELECT count(*) FROM agent_control.budget_observations WHERE run_id=$1`, runID); observations < 2 {
		t.Fatalf("budget observations = %d, want at least 2 (a manager turn and a specialist turn)", observations)
	}
	if spend := top.count(`SELECT coalesce(sum(cost_micros),0)::int FROM agent_control.budget_observations WHERE run_id=$1`, runID); spend < 1 {
		t.Fatalf("measured model spend = %d micros, want the runtimes' metered cost, not zero", spend)
	}

	// The public stream stayed inside the six-event registry, and internal
	// evidence recorded the run's hidden facts — asserted with the same
	// six-outcome proof every scenario makes.
	top.assertScenario(completed(runPath, 0))
}

// TestCrossProcessCannotCompleteWithoutTheRuntimeProcesses proves the run
// cannot succeed through an in-process reasoning path: with the runtime units
// unreachable, dispatch fails and the run never completes. The same
// composition completes only when the separate processes answer.
func TestCrossProcessCannotCompleteWithoutTheRuntimeProcesses(t *testing.T) {
	top := newTopology(t, "delegate-page-specialist,compose-page")
	// Both runtime processes fail closed: nothing answers a dispatched task.
	top.manager.proxy.fail()
	top.specialist.proxy.fail()

	runPath := top.createRun("cross-noproc-1", "make the hero section bolder")
	runID := runIDOf(runPath)

	// The run makes no progress toward completion: the first turn cannot be
	// dispatched to any reasoning process, and there is no in-process fallback
	// that could reason in its place. It never reaches the approval gate.
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		status, _, _ := top.currentRun(runPath)
		if status == "completed" {
			t.Fatal("the run completed with no runtime process reachable — an in-process path succeeded")
		}
		if status == "awaiting_approval" {
			t.Fatal("the run reached the approval gate with no runtime process reachable")
		}
		time.Sleep(400 * time.Millisecond)
	}
	// No result was committed and no candidate was written: there was no
	// reasoning process to produce either. The run's terminal state is the
	// dispatch failure, with nothing charged, committed, or produced.
	if results := top.count(`SELECT count(*) FROM agent_workflow.runtime_results r JOIN agent_workflow.runtime_tasks t ON t.workspace_id=r.workspace_id AND t.project_id=r.project_id AND t.task_id=r.task_id WHERE t.run_id=$1`, runID); results != 0 {
		t.Fatalf("committed results with no reachable runtime = %d, want 0", results)
	}
	if submissions := top.count(`SELECT count(*) FROM agent_workflow.runtime_artifact_submissions WHERE run_id=$1`, runID); submissions != 0 {
		t.Fatalf("candidate submissions with no reachable runtime = %d, want 0", submissions)
	}
	if terminal := top.waitForTerminal(runPath); terminal != "failed" {
		t.Fatalf("a run with no reachable runtime settled %q, want failed", terminal)
	}
	top.assertScenario(scenario{
		run: runPath, final: "failed", artifacts: 0,
		events: []string{"run.created", "run.state-changed"},
		fence:  fence{tasks: 1, replaced: 1},
	})
}
