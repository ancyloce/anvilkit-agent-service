// Package dbos is the only package allowed to depend on the DBOS SDK.
package dbos

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	sdk "github.com/dbos-inc/dbos-transact-golang/dbos"

	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/workflow"
)

type Config struct {
	DatabaseURL, Schema, ExecutorID, ApplicationVersion string
	Logger                                              *slog.Logger
}

type Runtime struct {
	engine       sdk.DBOSContext
	executor     workflow.Executor
	workflowFunc func(sdk.DBOSContext, workflow.Request) (workflow.Result, error)
}

func New(parent context.Context, cfg Config, executor workflow.Executor) (*Runtime, error) {
	engine, err := sdk.NewDBOSContext(parent, sdk.Config{AppName: "anvilkit-agent-service", ApplicationVersion: cfg.ApplicationVersion, DatabaseURL: cfg.DatabaseURL, DatabaseSchema: cfg.Schema, ExecutorID: cfg.ExecutorID, Logger: cfg.Logger})
	if err != nil {
		return nil, fmt.Errorf("create durable runtime: %w", err)
	}
	runtime := &Runtime{engine: engine, executor: executor}
	durable := func(ctx sdk.DBOSContext, request workflow.Request) (workflow.Result, error) {
		return runtime.run(ctx, request), nil
	}
	runtime.workflowFunc = durable
	sdk.RegisterWorkflow(engine, durable, sdk.WithWorkflowName("AgentRunWorkflow"))
	return runtime, nil
}

func (r *Runtime) Start(context.Context) error {
	if err := sdk.Launch(r.engine); err != nil {
		return fmt.Errorf("launch durable runtime: %w", err)
	}
	return nil
}
func (r *Runtime) Stop(context.Context) error { sdk.Shutdown(r.engine, 20*time.Second); return nil }

func (r *Runtime) Execute(_ context.Context, request workflow.Request) (workflow.Result, error) {
	if err := workflow.Validate(request); err != nil {
		return workflow.Result{}, err
	}
	handle, err := sdk.RunWorkflow(r.engine, r.workflowFunc, request, sdk.WithWorkflowID(string(request.WorkflowID)))
	if err != nil {
		return workflow.Result{}, fmt.Errorf("start workflow: %w", err)
	}
	result, err := handle.GetResult()
	if err != nil {
		return workflow.Result{}, fmt.Errorf("await workflow: %w", err)
	}
	return result, nil
}
func (r *Runtime) StartWait(_ context.Context, request workflow.Request) error {
	if err := workflow.Validate(request); err != nil {
		return err
	}
	if len(request.Steps) != 1 || request.Steps[0].Kind != workflow.StepWait {
		return fmt.Errorf("start wait requires exactly one durable wait step")
	}
	if _, err := sdk.RunWorkflow(r.engine, r.workflowFunc, request, sdk.WithWorkflowID(string(request.WorkflowID))); err != nil {
		return fmt.Errorf("start durable wait: %w", err)
	}
	return nil
}

func (r *Runtime) Signal(_ context.Context, id workflow.ID, topic string, payload json.RawMessage, idempotencyKey string) error {
	if err := sdk.Send(r.engine, string(id), payload, topic, sdk.WithIdempotencyKey(idempotencyKey)); err != nil {
		return fmt.Errorf("signal workflow: %w", err)
	}
	return nil
}
func (r *Runtime) Cancel(_ context.Context, id workflow.ID) error {
	if err := sdk.CancelWorkflow(r.engine, string(id)); err != nil {
		return fmt.Errorf("cancel workflow: %w", err)
	}
	return nil
}

func (r *Runtime) run(ctx sdk.DBOSContext, request workflow.Request) workflow.Result {
	result := workflow.Result{WorkflowID: request.WorkflowID}
	for _, step := range request.Steps {
		stepResult := workflow.StepResult{Name: step.Name}
		switch step.Kind {
		case workflow.StepAction:
			value, err := sdk.RunAsStep(ctx, func(stepContext context.Context) (workflow.StepResult, error) {
				output, executeErr := r.executor.Execute(stepContext, request.WorkflowID, step)
				boundary := workflow.StepResult{Name: step.Name, Output: output}
				if executeErr != nil {
					details := problem.Internal("")
					details.Detail = "durable step failed"
					boundary.Problem = &details
					boundary.Output = nil
				}
				return boundary, nil
			}, sdk.WithStepName(step.Name))
			if err != nil {
				details := problem.Internal("")
				details.Detail = "workflow engine step failure"
				stepResult.Problem = &details
			} else {
				stepResult = value
			}
		case workflow.StepSleep:
			if _, err := sdk.Sleep(ctx, step.Duration); err != nil {
				details := problem.Internal("")
				details.Detail = "durable sleep failed"
				stepResult.Problem = &details
			}
		case workflow.StepWait:
			value, err := sdk.Recv[json.RawMessage](ctx, step.Topic, step.Duration)
			if err != nil {
				details := problem.Internal("")
				details.Detail = "durable wait failed"
				stepResult.Problem = &details
			} else {
				stepResult.Output = value
			}
		}
		result.Steps = append(result.Steps, stepResult)
		if stepResult.Problem != nil {
			break
		}
	}
	return result
}

var _ workflow.Runtime = (*Runtime)(nil)
