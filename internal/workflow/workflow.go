// Package workflow defines the consumer-owned durable runtime port. Every type
// crossing this boundary is JSON serializable and contains no engine value.
package workflow

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
)

type ID string

type StepKind string

const (
	StepAction StepKind = "action"
	StepSleep  StepKind = "sleep"
	StepWait   StepKind = "wait"
)

type Step struct {
	Name     string          `json:"name"`
	Kind     StepKind        `json:"kind"`
	Input    json.RawMessage `json:"input,omitempty"`
	Duration time.Duration   `json:"duration,omitempty"`
	Topic    string          `json:"topic,omitempty"`
}

type Request struct {
	WorkflowID ID              `json:"workflowId"`
	Version    int             `json:"version"`
	Scope      Scope           `json:"scope"`
	Steps      []Step          `json:"steps"`
	State      json.RawMessage `json:"state,omitempty"`
}

type Scope struct {
	WorkspaceID string `json:"workspaceId"`
	ProjectID   string `json:"projectId"`
}

type StepResult struct {
	Name    string           `json:"name"`
	Output  json.RawMessage  `json:"output,omitempty"`
	Problem *problem.Details `json:"problem,omitempty"`
}

type Result struct {
	WorkflowID ID           `json:"workflowId"`
	Steps      []StepResult `json:"steps"`
}

type Executor interface {
	Execute(context.Context, ID, Step) (json.RawMessage, error)
}

type Runtime interface {
	Start(context.Context) error
	Execute(context.Context, Request) (Result, error)
	StartWait(context.Context, Request) error
	Signal(context.Context, ID, string, json.RawMessage, string) error
	Cancel(context.Context, ID) error
	Stop(context.Context) error
}

func Validate(request Request) error {
	if request.WorkflowID == "" {
		return fmt.Errorf("workflow request: ID is required")
	}
	if request.Version < 1 {
		return fmt.Errorf("workflow request: version must be positive")
	}
	if request.Scope.WorkspaceID == "" || request.Scope.ProjectID == "" {
		return fmt.Errorf("workflow request: workspace and project scope are required")
	}
	seen := make(map[string]struct{}, len(request.Steps))
	for _, step := range request.Steps {
		if step.Name == "" {
			return fmt.Errorf("workflow request: step name is required")
		}
		if _, exists := seen[step.Name]; exists {
			return fmt.Errorf("workflow request: duplicate step %s", step.Name)
		}
		seen[step.Name] = struct{}{}
		switch step.Kind {
		case StepAction:
		case StepSleep:
			if step.Duration < 0 {
				return fmt.Errorf("workflow request: sleep duration must not be negative")
			}
		case StepWait:
			if step.Topic == "" || step.Duration <= 0 {
				return fmt.Errorf("workflow request: wait needs topic and positive timeout")
			}
		default:
			return fmt.Errorf("workflow request: unsupported step kind %q", step.Kind)
		}
	}
	return nil
}
