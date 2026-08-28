package postgres_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ancyloce/anvilkit-agent-service/internal/agent"
	"github.com/ancyloce/anvilkit-agent-service/internal/dispatch"
	dispatchpg "github.com/ancyloce/anvilkit-agent-service/internal/dispatch/postgres"
	"github.com/ancyloce/anvilkit-agent-service/internal/persistence"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
)

// The dispatch record's invariants are held by the database, not by the code
// that writes it: one current attempt per task, a monotonic lease, one
// registered result, and a commit that is atomic with both. These proofs run
// against real SQL because that is the only place those guarantees exist.
func TestDurableDispatchRecordHoldsTheFence(t *testing.T) {
	baseURL := os.Getenv("POSTGRES_TEST_URL")
	if baseURL == "" {
		if os.Getenv("ANVILKIT_REQUIRE_POSTGRES_PROOFS") != "" {
			t.Fatal("POSTGRES_TEST_URL is not set but ANVILKIT_REQUIRE_POSTGRES_PROOFS requires these proofs; point POSTGRES_TEST_URL at a disposable PostgreSQL database")
		}
		t.Skip("POSTGRES_TEST_URL is not set")
	}
	ctx := context.Background()
	databaseURL, cleanup := isolatedDatabase(t, ctx, baseURL)
	defer cleanup()
	connection, err := pgx.Connect(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	if err := persistence.NewMigrator(connection).Apply(ctx); err != nil {
		t.Fatal(err)
	}
	if err := connection.Close(ctx); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	repository, err := dispatchpg.New(pool)
	if err != nil {
		t.Fatal(err)
	}
	clock := fixedClock{now: time.Unix(2000, 0).UTC()}
	coordinator, err := dispatch.New(dispatch.Config{Repository: repository, Tokens: dispatch.RandomTokens{}, Clock: clock, Lease: time.Minute})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("one current attempt survives concurrent opens", func(t *testing.T) {
		request := taskRequest("run.concurrent")
		var wait sync.WaitGroup
		results := make(chan error, 8)
		for range 8 {
			wait.Add(1)
			go func() {
				defer wait.Done()
				replacement := request
				replacement.Replacing = dispatch.ReasonReplaced
				_, err := coordinator.Open(ctx, replacement)
				results <- err
			}()
		}
		wait.Wait()
		close(results)
		opened := 0
		for err := range results {
			// A serialization failure is a legitimate outcome of eight writers
			// contending for one task: what must never happen is two attempts
			// being current at once.
			if err == nil {
				opened++
			}
		}
		if opened == 0 {
			t.Fatal("no attempt was opened at all")
		}
		var current int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM agent_workflow.runtime_attempts WHERE task_id=$1 AND dispatch_status IN ('accepted','running')`, request.TaskID).Scan(&current); err != nil {
			t.Fatal(err)
		}
		if current != 1 {
			t.Fatalf("current attempts = %d, want exactly 1", current)
		}
	})

	t.Run("commit is atomic with the result registration", func(t *testing.T) {
		execution, err := coordinator.Open(ctx, taskRequest("run.commit"))
		if err != nil {
			t.Fatal(err)
		}
		if err := coordinator.Dispatched(ctx, execution); err != nil {
			t.Fatal(err)
		}
		result, err := coordinator.Settle(ctx, settleOf(execution, statementOne, clock.now))
		if err != nil || !result.Disposition.Committed() {
			t.Fatalf("commit = %+v %v", result, err)
		}
		var status, attemptStatus, registered string
		if err := pool.QueryRow(ctx, `
			SELECT t.status, a.dispatch_status, r.result_statement_digest
			  FROM agent_workflow.runtime_tasks t
			  JOIN agent_workflow.runtime_attempts a ON a.task_id=t.task_id
			  JOIN agent_workflow.runtime_results r ON r.task_id=t.task_id
			 WHERE t.task_id=$1`, execution.Task.TaskID).Scan(&status, &attemptStatus, &registered); err != nil {
			t.Fatal(err)
		}
		if status != string(dispatch.Succeeded) || attemptStatus != string(dispatch.Succeeded) || registered != statementOne {
			t.Fatalf("task=%s attempt=%s registered=%s", status, attemptStatus, registered)
		}
		// The same statement again is idempotent, and a different one for the
		// settled task changes nothing.
		again, err := coordinator.Settle(ctx, settleOf(execution, statementOne, clock.now))
		if err != nil || again.Disposition != dispatch.DispositionDuplicate {
			t.Fatalf("redelivery = %+v %v", again, err)
		}
		different, err := coordinator.Settle(ctx, settleOf(execution, statementTwo, clock.now))
		if err != nil || different.Disposition != dispatch.DispositionTerminal {
			t.Fatalf("second result = %+v %v", different, err)
		}
		var evidence int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM agent_workflow.runtime_result_evidence WHERE task_id=$1`, execution.Task.TaskID).Scan(&evidence); err != nil {
			t.Fatal(err)
		}
		if evidence != 2 {
			t.Fatalf("evidence rows = %d, want the two results that changed nothing", evidence)
		}
	})

	t.Run("a superseded attempt cannot commit", func(t *testing.T) {
		request := taskRequest("run.superseded")
		first, err := coordinator.Open(ctx, request)
		if err != nil {
			t.Fatal(err)
		}
		replacement := request
		replacement.Replacing = dispatch.ReasonDispatchFailed
		second, err := coordinator.Open(ctx, replacement)
		if err != nil {
			t.Fatal(err)
		}
		late, err := coordinator.Settle(ctx, settleOf(first, statementOne, clock.now))
		if err != nil || late.Disposition != dispatch.DispositionSuperseded {
			t.Fatalf("superseded result = %+v %v", late, err)
		}
		current, err := coordinator.Settle(ctx, settleOf(second, statementTwo, clock.now))
		if err != nil || !current.Disposition.Committed() {
			t.Fatalf("current result = %+v %v", current, err)
		}
	})

	t.Run("cancellation revokes every open execution of a run", func(t *testing.T) {
		execution, err := coordinator.Open(ctx, taskRequest("run.cancelled"))
		if err != nil {
			t.Fatal(err)
		}
		if err := coordinator.Dispatched(ctx, execution); err != nil {
			t.Fatal(err)
		}
		open, err := coordinator.CancelRun(ctx, testScope(), "run.cancelled", dispatch.ReasonLeaseRevoked)
		if err != nil || open != 1 {
			t.Fatalf("cancellation revoked %d executions: %v", open, err)
		}
		result, err := coordinator.Settle(ctx, settleOf(execution, statementOne, clock.now))
		if err != nil || result.Disposition != dispatch.DispositionCanceled {
			t.Fatalf("result after cancellation = %+v %v", result, err)
		}
	})

	t.Run("the task identity may not be reused for different work", func(t *testing.T) {
		request := taskRequest("run.identity")
		if _, err := coordinator.Open(ctx, request); err != nil {
			t.Fatal(err)
		}
		different := request
		different.RequestDigest = "sha256:" + strings.Repeat("9", 64)
		_, err := coordinator.Open(ctx, different)
		var details problem.Details
		if err == nil || !asProblem(err, &details) || details.Code != string(problem.CodeIdempotencyKeyReused) {
			t.Fatalf("reused identity = %v", err)
		}
	})
}

const (
	statementOne = "sha256:11111111111111111111111111111111111111111111111111111111111111ab"
	statementTwo = "sha256:22222222222222222222222222222222222222222222222222222222222222ab"
)

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

func testScope() dispatch.Scope {
	return dispatch.Scope{WorkspaceID: "workspace", ProjectID: "project"}
}

func taskRequest(runID string) dispatch.Request {
	digest := func(fill string) string { return "sha256:" + strings.Repeat(fill, 64) }
	return dispatch.Request{
		Scope:               testScope(),
		TaskID:              dispatch.TaskID(runID + ":g1:turn-0000"),
		RunID:               runID,
		RootRunID:           runID,
		ExecutionGeneration: 1,
		DefinitionDigest:    digest("d"),
		Runtime: agent.RuntimeBinding{
			RuntimeUnitID:            "runtime.platform.manager",
			RuntimeManifestDigest:    digest("a"),
			RuntimeImageDigest:       digest("b"),
			InvocationProtocolDigest: digest("c"),
			RuntimeAudience:          "urn:anvilkit:audience:runtime-manager",
		},
		Capability:    "provider.invoke",
		RequestDigest: digest("e"),
	}
}

func settleOf(execution dispatch.Execution, statement string, at time.Time) dispatch.Settle {
	return dispatch.Settle{
		Scope: execution.Task.Scope,
		RunID: execution.Task.RunID,
		Predicate: dispatch.Predicate{
			RunID:                    execution.Task.RunID,
			TaskID:                   execution.Task.TaskID,
			ExecutionGeneration:      execution.Task.ExecutionGeneration,
			PhysicalAttemptID:        execution.Attempt.PhysicalAttemptID,
			AttemptNumber:            execution.Attempt.AttemptNumber,
			LeaseEpoch:               execution.Attempt.LeaseEpoch,
			FenceToken:               execution.FenceToken,
			RuntimeUnitID:            execution.Task.Runtime.RuntimeUnitID,
			RuntimeManifestDigest:    execution.Task.Runtime.RuntimeManifestDigest,
			RuntimeImageDigest:       execution.Task.Runtime.RuntimeImageDigest,
			InvocationProtocolDigest: execution.Task.Runtime.InvocationProtocolDigest,
		},
		Outcome: dispatch.Outcome{
			Status:                "completed",
			ReasonCode:            "RUNTIME_COMPLETED",
			ResultStatementDigest: statement,
			Statement:             []byte(`{"kind":"AgentRuntimeResult"}`),
			SignatureKeyID:        "urn:anvilkit:key:test-runtime-result",
			ObservedAt:            at,
		},
	}
}

func asProblem(err error, target *problem.Details) bool {
	details, ok := err.(problem.Details)
	if ok {
		*target = details
		return true
	}
	return false
}

func isolatedDatabase(t *testing.T, ctx context.Context, baseURL string) (string, func()) {
	t.Helper()
	admin, err := pgx.Connect(ctx, baseURL)
	if err != nil {
		t.Fatal(err)
	}
	random := make([]byte, 6)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	name := "agent_dispatch_" + hex.EncodeToString(random)
	if _, err := admin.Exec(ctx, fmt.Sprintf(`CREATE DATABASE %s TEMPLATE template0`, pgx.Identifier{name}.Sanitize())); err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(baseURL)
	if err != nil {
		t.Fatal(err)
	}
	parsed.Path = "/" + name
	return parsed.String(), func() {
		_, _ = admin.Exec(context.Background(), fmt.Sprintf(`DROP DATABASE IF EXISTS %s WITH (FORCE)`, pgx.Identifier{name}.Sanitize()))
		_ = admin.Close(context.Background())
	}
}
