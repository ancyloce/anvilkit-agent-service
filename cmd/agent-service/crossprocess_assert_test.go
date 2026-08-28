package main

import (
	"encoding/json"
	"time"
)

// scenario is what one cross-process scenario must prove about a run once it
// settles: the six outcomes the recovery matrix's exit criterion names — final state, public
// Event, internal Evidence, usage, artifact, and fence. Every scenario asserts
// all six through assertScenario, so no recovery path is proven by its final
// status alone.
type scenario struct {
	run string
	// final is the run's expected terminal status.
	final string
	// artifacts is the exact number of committed artifacts the run may leave.
	artifacts int
	// events are the public event types that must have appeared. The
	// six-event registry is enforced whatever is listed.
	events []string
	// evidence is the minimum number of internal evidence records.
	evidence int
	// usage is the minimum number of budget observations; when positive, the
	// measured spend must also be non-zero — usage the runtimes metered, not
	// usage declared as free.
	usage int
	fence fence
}

// fence is what the durable dispatch record must say once a run settles.
type fence struct {
	// tasks is the minimum number of logical tasks the run created.
	tasks int
	// succeeded is the minimum number of attempts that committed.
	succeeded int
	// replaced is the minimum number of attempts that ended without
	// committing — superseded, failed, expired, or canceled.
	replaced int
	// dispositions are minimum counts of result evidence by disposition:
	// what the fence refused, and why.
	dispositions map[string]int
}

// attemptsOf joins attempts to the run that owns them.
const attemptsOf = `FROM agent_workflow.runtime_attempts a JOIN agent_workflow.runtime_tasks t ON t.workspace_id=a.workspace_id AND t.project_id=a.project_id AND t.task_id=a.task_id WHERE t.run_id=$1`

// resultsOf joins committed results to the run that owns them.
const resultsOf = `FROM agent_workflow.runtime_results r JOIN agent_workflow.runtime_tasks t ON t.workspace_id=r.workspace_id AND t.project_id=r.project_id AND t.task_id=r.task_id WHERE t.run_id=$1`

// assertScenario proves the six outcomes for one settled run.
func (top *topology) assertScenario(s scenario) {
	t := top.t
	t.Helper()
	runID := runIDOf(s.run)

	// 1. Final state: what the public run representation says.
	if status, _, payload := top.currentRun(s.run); status != s.final {
		t.Fatalf("final state = %q, want %q: %s", status, s.final, payload)
	}

	// 2. Public Event: inside the six-event registry, carrying what the
	// scenario requires.
	top.assertPublicEvents(runID, s.events)

	// 3. Internal Evidence: the run's hidden facts, and what the fence refused.
	if evidence := top.count(`SELECT count(*) FROM agent_evidence.records WHERE run_id=$1`, runID); evidence < s.evidence {
		t.Fatalf("internal evidence records = %d, want at least %d", evidence, s.evidence)
	}
	for disposition, want := range s.fence.dispositions {
		if got := top.countWith(`SELECT count(*) FROM agent_workflow.runtime_result_evidence WHERE run_id=$1 AND disposition=$2`, runID, disposition); got < want {
			t.Fatalf("result evidence with disposition %q = %d, want at least %d", disposition, got, want)
		}
	}

	// 4. Usage: what the runtimes metered, accounted against the run's budget.
	if observations := top.count(`SELECT count(*) FROM agent_control.budget_observations WHERE run_id=$1`, runID); observations < s.usage {
		t.Fatalf("budget observations = %d, want at least %d", observations, s.usage)
	}
	if s.usage > 0 {
		if spend := top.count(`SELECT coalesce(sum(cost_micros),0)::int FROM agent_control.budget_observations WHERE run_id=$1`, runID); spend < 1 {
			t.Fatalf("measured model spend = %d micros, want the runtimes' metered cost, not zero", spend)
		}
	}

	// 5. Artifact: exactly what the scenario allows to have been committed.
	if artifacts := top.count(`SELECT count(*) FROM agent_artifacts.metadata WHERE run_id=$1 AND state='committed'`, runID); artifacts != s.artifacts {
		t.Fatalf("committed artifacts = %d, want exactly %d", artifacts, s.artifacts)
	}

	// 6. Fence: the durable dispatch record. Whatever happened to the run, no
	// logical task committed twice, every committed result belongs to exactly
	// the one attempt it settled — succeeded, or closed by a failed result —
	// and no task has two live executions.
	if tasks := top.count(`SELECT count(*) FROM agent_workflow.runtime_tasks WHERE run_id=$1`, runID); tasks < s.fence.tasks {
		t.Fatalf("logical tasks = %d, want at least %d", tasks, s.fence.tasks)
	}
	if succeeded := top.count(`SELECT count(*) `+attemptsOf+` AND a.dispatch_status='succeeded'`, runID); succeeded < s.fence.succeeded {
		t.Fatalf("succeeded attempts = %d, want at least %d", succeeded, s.fence.succeeded)
	}
	if replaced := top.count(`SELECT count(*) `+attemptsOf+` AND a.dispatch_status IN ('superseded','failed','expired','canceled')`, runID); replaced < s.fence.replaced {
		t.Fatalf("replaced attempts = %d, want at least %d", replaced, s.fence.replaced)
	}
	if doubled := top.count(`SELECT count(*) FROM (SELECT a.task_id `+attemptsOf+` AND a.result_statement_digest IS NOT NULL GROUP BY a.task_id HAVING count(*)>1) doubled`, runID); doubled != 0 {
		t.Fatalf("%d logical tasks have more than one settled attempt", doubled)
	}
	if doubled := top.count(`SELECT count(*) FROM (SELECT r.task_id `+resultsOf+` GROUP BY r.task_id HAVING count(*)>1) doubled`, runID); doubled != 0 {
		t.Fatalf("%d logical tasks committed more than one result", doubled)
	}
	if orphaned := top.count(`SELECT count(*) `+resultsOf+` AND NOT EXISTS (SELECT 1 FROM agent_workflow.runtime_attempts a WHERE a.workspace_id=r.workspace_id AND a.project_id=r.project_id AND a.physical_attempt_id=r.physical_attempt_id AND a.result_statement_digest=r.result_statement_digest AND a.dispatch_status IN ('succeeded','failed'))`, runID); orphaned != 0 {
		t.Fatalf("%d committed results are not registered on the attempt they settled", orphaned)
	}
	if live := top.count(`SELECT count(*) FROM (SELECT a.task_id `+attemptsOf+` AND a.dispatch_status IN ('accepted','running') GROUP BY a.task_id HAVING count(*)>1) live`, runID); live != 0 {
		t.Fatalf("%d logical tasks have two live executions", live)
	}
	if settled, results := top.count(`SELECT count(*) `+attemptsOf+` AND a.result_statement_digest IS NOT NULL`, runID), top.count(`SELECT count(*) `+resultsOf, runID); settled != results {
		t.Fatalf("settled attempts = %d but committed results = %d; every commit registers exactly one result", settled, results)
	}
}

// assertPublicEvents proves every observed public event type is inside the
// six-event registry and the required types all appeared.
func (top *topology) assertPublicEvents(runID string, required []string) {
	t := top.t
	t.Helper()
	rows, err := top.observe.Query(top.ctx, `SELECT event_bytes FROM agent_events.agent_events WHERE run_id=$1 ORDER BY sequence`, runID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	registry := map[string]bool{
		"run.created": true, "run.state-changed": true, "run.input-requested": true,
		"run.approval-requested": true, "run.artifact-available": true, "run.problem-recorded": true,
	}
	observed := map[string]bool{}
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var event struct {
			EventType string `json:"eventType"`
		}
		if err := json.Unmarshal(raw, &event); err != nil {
			t.Fatal(err)
		}
		if !registry[event.EventType] {
			t.Fatalf("event type %q escaped the six-event public registry", event.EventType)
		}
		observed[event.EventType] = true
	}
	for _, want := range required {
		if !observed[want] {
			t.Fatalf("the public stream never carried %q", want)
		}
	}
}

// completedEvents are the public events every completed page-change run
// carries.
var completedEvents = []string{"run.created", "run.state-changed", "run.approval-requested", "run.artifact-available"}

// completed is the scenario every successfully recovered run must satisfy: a
// completed run with one artifact, evidence, metered usage, and three
// committed tasks (manager delegate, specialist, manager conclude). Scenarios
// add what their fault must have left behind.
func completed(runPath string, replaced int) scenario {
	return scenario{
		run: runPath, final: "completed", artifacts: 1, events: completedEvents,
		evidence: 1, usage: 2,
		fence: fence{tasks: 3, succeeded: 3, replaced: replaced},
	}
}

// countWith runs one scalar count query with arbitrary arguments.
func (top *topology) countWith(query string, arguments ...any) int {
	top.t.Helper()
	var value int
	if err := top.observe.QueryRow(top.ctx, query, arguments...).Scan(&value); err != nil {
		top.t.Fatalf("count query: %v", err)
	}
	return value
}

// attemptRow is one physical attempt as the durable record holds it.
type attemptRow struct {
	attemptID, taskID, unitID, status, keyID, failureReason string
	number, lease                                           int
	expiresAt                                               time.Time
}

// attempts reads every attempt of a run, oldest first.
func (top *topology) attempts(runID string) []attemptRow {
	top.t.Helper()
	rows, err := top.observe.Query(top.ctx, `SELECT a.physical_attempt_id, a.task_id, a.runtime_unit_id, a.dispatch_status, coalesce(a.signature_key_id,''), coalesce(a.failure_reason,''), a.attempt_number, a.lease_epoch, a.expires_at `+attemptsOf+` ORDER BY a.created_at, a.attempt_number`, runID)
	if err != nil {
		top.t.Fatal(err)
	}
	defer rows.Close()
	var attempts []attemptRow
	for rows.Next() {
		var row attemptRow
		if err := rows.Scan(&row.attemptID, &row.taskID, &row.unitID, &row.status, &row.keyID, &row.failureReason, &row.number, &row.lease, &row.expiresAt); err != nil {
			top.t.Fatal(err)
		}
		attempts = append(attempts, row)
	}
	return attempts
}

// attemptWhere returns the attempts of one unit in one status.
func (top *topology) attemptsWhere(runID, unitID, status string) []attemptRow {
	var matched []attemptRow
	for _, row := range top.attempts(runID) {
		if row.unitID == unitID && row.status == status {
			matched = append(matched, row)
		}
	}
	return matched
}

// waitForUnitDispatch waits until an attempt for the given unit has been
// dispatched for the run and returns it.
func (top *topology) waitForUnitDispatch(runID, unitID string) attemptRow {
	top.t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		for _, row := range top.attempts(runID) {
			if row.unitID == unitID && (row.status == "running" || row.status == "succeeded") {
				return row
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	top.t.Fatalf("no attempt for %s was dispatched for run %s in time", unitID, runID)
	return attemptRow{}
}
