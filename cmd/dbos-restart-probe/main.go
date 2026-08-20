// Command dbos-restart-probe is a two-process durable-checkpoint recovery probe.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/dbos-inc/dbos-transact-golang/dbos"
	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	mode := flag.String("mode", "start", "start, resume, or count")
	workflowID := flag.String("workflow-id", "restart-proof", "stable proof workflow ID")
	checkpoint := flag.Int("checkpoint", 1, "durable effect checkpoint to kill after")
	step := flag.Int("step", 0, "effect step to count")
	flag.Parse()
	if *checkpoint < 1 || *checkpoint > 3 {
		fmt.Fprintln(os.Stderr, "checkpoint must be between 1 and 3")
		os.Exit(2)
	}
	databaseURL := os.Getenv("DBOS_SYSTEM_DATABASE_URL")
	if databaseURL == "" {
		fmt.Fprintln(os.Stderr, "DBOS_SYSTEM_DATABASE_URL is required")
		os.Exit(2)
	}

	pool, err := pgxpool.New(context.Background(), databaseURL)
	if err != nil {
		panic(err)
	}
	defer pool.Close()
	if _, err = pool.Exec(context.Background(), `CREATE TABLE IF NOT EXISTS workflow_restart_external_effects (
		workflow_id text NOT NULL, step_index integer NOT NULL, executions integer NOT NULL,
		PRIMARY KEY (workflow_id, step_index)
	)`); err != nil {
		panic(err)
	}
	if *mode == "count" {
		if *step < 1 || *step > 3 {
			fmt.Fprintln(os.Stderr, "count mode requires step between 1 and 3")
			os.Exit(2)
		}
		var executions int
		if err = pool.QueryRow(context.Background(), `SELECT executions FROM workflow_restart_external_effects WHERE workflow_id=$1 AND step_index=$2`, *workflowID, *step).Scan(&executions); err != nil {
			os.Exit(1)
		}
		fmt.Println(executions)
		return
	}

	ctx, err := dbos.NewContext(context.Background(), dbos.Config{
		AppName: "anvilkit-agent-dbos-restart", ApplicationVersion: "dbos-restart-probe",
		SystemDBPool: pool, DatabaseSchema: "dbos_restart_probe", ExecutorID: "dbos-restart-executor",
		Logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
	})
	if err != nil {
		panic(err)
	}
	defer func() {
		if shutdownErr := dbos.Shutdown(ctx, 10*time.Second); shutdownErr != nil {
			fmt.Fprintf(os.Stderr, "shutdown DBOS context: %v\n", shutdownErr)
		}
	}()
	datasource, err := dbos.NewDataSource(ctx, pool, dbos.WithDataSourceName("restart-effects"))
	if err != nil {
		panic(err)
	}

	type restartInput struct {
		WorkflowID string `json:"workflowId"`
		Checkpoint int    `json:"checkpoint"`
	}
	workflow := func(workflowContext dbos.Context, input restartInput) (string, error) {
		for stepIndex := 1; stepIndex <= 3; stepIndex++ {
			_, transactionErr := dbos.RunAsTransaction(workflowContext, datasource,
				func(stepContext context.Context, transaction dbos.Tx) (int64, error) {
					result, executeErr := transaction.Exec(stepContext, `INSERT INTO workflow_restart_external_effects(workflow_id, step_index, executions)
						VALUES ($1, $2, 1) ON CONFLICT (workflow_id, step_index) DO UPDATE SET executions=workflow_restart_external_effects.executions+1`, input.WorkflowID, stepIndex)
					if executeErr != nil {
						return 0, executeErr
					}
					return result.RowsAffected()
				}, dbos.WithStepName(fmt.Sprintf("external-effect-%d", stepIndex)))
			if transactionErr != nil {
				return "", transactionErr
			}
			if stepIndex == input.Checkpoint {
				if _, recvErr := dbos.Recv[string](workflowContext, fmt.Sprintf("continue-%d", stepIndex), 5*time.Minute); recvErr != nil {
					return "", recvErr
				}
			}
		}
		return "resumed", nil
	}
	dbos.RegisterWorkflow(ctx, workflow, dbos.WithWorkflowName("WorkflowRestartMatrixWorkflow"))
	if err = dbos.Launch(ctx); err != nil {
		panic(err)
	}

	if *mode == "start" {
		handle, runErr := dbos.RunWorkflow(ctx, workflow, restartInput{WorkflowID: *workflowID, Checkpoint: *checkpoint}, dbos.WithWorkflowID(*workflowID))
		if runErr != nil {
			panic(runErr)
		}
		_, _ = handle.GetResult()
		return
	}
	if *mode != "resume" {
		fmt.Fprintln(os.Stderr, "mode must be start, resume, or count")
		os.Exit(2)
	}
	time.Sleep(500 * time.Millisecond)
	topic := fmt.Sprintf("continue-%d", *checkpoint)
	if err = dbos.Send(ctx, *workflowID, "resumed", topic, dbos.WithIdempotencyKey("workflow-resume-message-"+topic)); err != nil {
		panic(err)
	}
	handle, err := dbos.RetrieveWorkflow[string](ctx, *workflowID)
	if err != nil {
		panic(err)
	}
	value, err := handle.GetResult()
	if err != nil || value != "resumed" {
		panic(fmt.Sprintf("result=%q err=%v", value, err))
	}
	for stepIndex := 1; stepIndex <= 3; stepIndex++ {
		var executions int
		if err = pool.QueryRow(context.Background(), `SELECT executions FROM workflow_restart_external_effects WHERE workflow_id=$1 AND step_index=$2`, *workflowID, stepIndex).Scan(&executions); err != nil {
			panic(err)
		}
		if executions != 1 {
			panic(fmt.Sprintf("external effect %d executed %d times", stepIndex, executions))
		}
	}
	fmt.Printf("restart proof passed: checkpoint=%d result=%s externalEffects=3x1\n", *checkpoint, value)
}
