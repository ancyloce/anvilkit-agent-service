// Package dbos is the only package allowed to depend on the DBOS SDK. It
// adapts the repository-owned durable runtime port onto DBOS Go v1.1.0 and
// lets no DBOS context, handle, option, or error type cross the boundary.
package dbos

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	sdk "github.com/dbos-inc/dbos-transact-golang/dbos"

	"github.com/ancyloce/anvilkit-agent-service/internal/workflow"
)

type Config struct {
	DatabaseURL, Schema, ExecutorID, ApplicationVersion string
	Logger                                              *slog.Logger
}

// Runtime is the DBOS adapter for the canonical AgentRunWorkflow.
type Runtime struct {
	engine       sdk.Context
	ops          workflow.Operations
	workflowFunc sdk.Workflow[workflow.RunInput, workflow.RunOutcome]
}

func New(parent context.Context, cfg Config, ops workflow.Operations) (*Runtime, error) {
	if ops == nil {
		return nil, fmt.Errorf("durable runtime requires the workflow operations pipeline")
	}
	engine, err := sdk.NewContext(parent, sdk.Config{AppName: "anvilkit-agent-service", ApplicationVersion: cfg.ApplicationVersion, DatabaseURL: cfg.DatabaseURL, DatabaseSchema: cfg.Schema, ExecutorID: cfg.ExecutorID, Logger: cfg.Logger})
	if err != nil {
		return nil, fmt.Errorf("create durable runtime: %w", err)
	}
	runtime := &Runtime{engine: engine, ops: ops}
	durable := func(ctx sdk.Context, input workflow.RunInput) (workflow.RunOutcome, error) {
		return workflow.AgentRunWorkflow(&host{ctx: ctx}, runtime.ops, input)
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

func (r *Runtime) Stop(context.Context) error {
	if err := sdk.Shutdown(r.engine, 20*time.Second); err != nil {
		return fmt.Errorf("shutdown durable runtime: %w", err)
	}
	return nil
}

// StartRun ensures the durable workflow exists without awaiting its result.
// Starting the same run key again attaches to the existing execution.
func (r *Runtime) StartRun(_ context.Context, input workflow.RunInput) error {
	if err := input.Validate(); err != nil {
		return err
	}
	if _, err := sdk.RunWorkflow(r.engine, r.workflowFunc, input, sdk.WithWorkflowID(input.Key.WorkflowID())); err != nil {
		return fmt.Errorf("start agent run workflow: %w", err)
	}
	return nil
}

func (r *Runtime) ExecuteRun(_ context.Context, input workflow.RunInput) (workflow.RunOutcome, error) {
	if err := input.Validate(); err != nil {
		return workflow.RunOutcome{}, err
	}
	handle, err := sdk.RunWorkflow(r.engine, r.workflowFunc, input, sdk.WithWorkflowID(input.Key.WorkflowID()))
	if err != nil {
		return workflow.RunOutcome{}, fmt.Errorf("start agent run workflow: %w", err)
	}
	result, err := handle.GetResult()
	if err != nil {
		if errors.Is(err, sdk.ErrWorkflowCancelled) || errors.Is(err, sdk.ErrAwaitedWorkflowCancelled) {
			return workflow.RunOutcome{Key: input.Key, Terminal: workflow.TerminalCancelled}, nil
		}
		return workflow.RunOutcome{}, fmt.Errorf("await agent run workflow: %w", err)
	}
	return result, nil
}

func (r *Runtime) Signal(_ context.Context, key workflow.RunKey, topic string, payload json.RawMessage, idempotencyKey string) error {
	if err := sdk.Send(r.engine, key.WorkflowID(), payload, topic, sdk.WithIdempotencyKey(idempotencyKey)); err != nil {
		return fmt.Errorf("signal agent run workflow: %w", err)
	}
	return nil
}

func (r *Runtime) CancelRun(_ context.Context, key workflow.RunKey) error {
	if err := sdk.CancelWorkflow(r.engine, key.WorkflowID()); err != nil {
		return fmt.Errorf("cancel agent run workflow: %w", err)
	}
	return nil
}

// host maps the workflow Host primitives onto DBOS durable operations.
type host struct{ ctx sdk.Context }

func (h *host) WorkflowID() string {
	id, err := sdk.GetWorkflowID(h.ctx)
	if err != nil {
		return ""
	}
	return id
}

func (h *host) Step(name string, fn func(context.Context) ([]byte, error)) ([]byte, error) {
	return sdk.RunAsStep(h.ctx, func(stepContext context.Context) ([]byte, error) {
		return fn(stepContext)
	}, sdk.WithStepName(name))
}

func (h *host) AwaitSignal(topic string, timeout time.Duration) ([]byte, bool, error) {
	payload, err := sdk.Recv[json.RawMessage](h.ctx, topic, timeout)
	if err != nil {
		if errors.Is(err, sdk.ErrTimeout) {
			return nil, true, nil
		}
		return nil, false, err
	}
	return payload, false, nil
}

var _ workflow.Runtime = (*Runtime)(nil)
