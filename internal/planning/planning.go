// Package planning owns strict typed-plan validation, bounded repair, and
// separate raw/repaired/accepted accounting.
package planning

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/ancyloce/anvilkit-agent-service/internal/modelgateway"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"io"
	"sync"

	contractvalidator "github.com/ancyloce/anvilkit-agent-service/contracts/validator"
)

type DefinitionID string
type Step struct {
	Tool      string                     `json:"tool"`
	Arguments map[string]json.RawMessage `json:"arguments"`
}
type Plan struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Steps      []Step `json:"steps"`
}
type Finding struct{ Code, Stage, InstancePath, SchemaPath string }
type Attempt struct {
	Number     int
	Raw        []byte
	Valid      bool
	Findings   []Finding
	Invocation modelgateway.InvocationRecord
}
type Outcome string

const (
	Accepted Outcome = "accepted"
	Repaired Outcome = "repaired"
	Rejected Outcome = "rejected"
)

type Result struct {
	Plan         Plan
	Attempts     []Attempt
	Outcome      Outcome
	ProposedTool string
}
type Stats struct{ RawAttempts, RawValid, RepairAttempts, RepairValid, Accepted, Rejected int }
type Invoker interface {
	Invoke(context.Context, modelgateway.InvokeRequest) (modelgateway.AdapterResponse, modelgateway.InvocationRecord, error)
}
type Engine struct {
	invoker                      Invoker
	maximumSteps, maximumRepairs int
	lock                         sync.Mutex
	stats                        Stats
}

func New(invoker Invoker, maximumSteps, maximumRepairs int) (*Engine, error) {
	if invoker == nil || maximumSteps < 1 || maximumSteps > 128 || maximumRepairs < 0 || maximumRepairs > 3 {
		return nil, fmt.Errorf("planning bounds invalid")
	}
	return &Engine{invoker: invoker, maximumSteps: maximumSteps, maximumRepairs: maximumRepairs}, nil
}
func (e *Engine) Plan(ctx context.Context, request modelgateway.InvokeRequest) (Result, error) {
	result := Result{}
	scenario := request.Scenario
	originalContext := append([]byte(nil), request.Context...)
	for attempt := 0; attempt <= e.maximumRepairs; attempt++ {
		if attempt > 0 {
			request.Scenario = scenario + "-repair"
			request.Context = append(append([]byte(nil), originalContext...), []byte("\n[system repair] Return exactly one strict TypedPlan JSON object; do not add authority fields or prose.")...)
		}
		response, record, err := e.invoker.Invoke(ctx, request)
		if err != nil {
			return result, err
		}
		plan, findings := Decode(response.Output, e.maximumSteps)
		valid := len(findings) == 0
		if result.ProposedTool == "" {
			result.ProposedTool = proposedTool(response.Output)
		}
		result.Attempts = append(result.Attempts, Attempt{Number: attempt + 1, Raw: append([]byte(nil), response.Output...), Valid: valid, Findings: findings, Invocation: record})
		e.lock.Lock()
		if attempt == 0 {
			e.stats.RawAttempts++
			if valid {
				e.stats.RawValid++
			}
		} else {
			e.stats.RepairAttempts++
			if valid {
				e.stats.RepairValid++
			}
		}
		e.lock.Unlock()
		if valid {
			result.Plan = plan
			result.ProposedTool = plan.Steps[0].Tool
			if attempt == 0 {
				result.Outcome = Accepted
			} else {
				result.Outcome = Repaired
			}
			e.lock.Lock()
			e.stats.Accepted++
			e.lock.Unlock()
			return result, nil
		}
	}
	result.Outcome = Rejected
	e.lock.Lock()
	e.stats.Rejected++
	e.lock.Unlock()
	details := problem.New(problem.CodeContractInvalid, "")
	details.Detail = "typed plan failed bounded validation and repair"
	return result, details
}
func (e *Engine) Stats() Stats { e.lock.Lock(); defer e.lock.Unlock(); return e.stats }
func Decode(raw []byte, maximumSteps int) (Plan, []Finding) {
	if len(raw) == 0 || len(raw) > 4096 {
		return Plan{}, []Finding{{"PLAN_SIZE", "typed-plan-validation", "/", "/maximumSerializedBytes"}}
	}
	if _, err := contractvalidator.Admit(raw); err != nil {
		return Plan{}, []Finding{{"PLAN_PARSE", "provider-output-parse", "/", "/profile/strictAdmission"}}
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var plan Plan
	if err := decoder.Decode(&plan); err != nil {
		return Plan{}, []Finding{{"PLAN_PARSE", "provider-output-parse", "/", "/json"}}
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return Plan{}, []Finding{{"PLAN_TRAILING", "provider-output-parse", "/", "/json"}}
	}
	if plan.APIVersion != "anvilkit.io/contracts/v1" || plan.Kind != "TypedPlan" || len(plan.Steps) < 1 || len(plan.Steps) > maximumSteps {
		return Plan{}, []Finding{{"PLAN_SCHEMA", "typed-plan-validation", "/steps", "/properties/steps"}}
	}
	for index, step := range plan.Steps {
		if step.Tool == "" || len(step.Tool) > 128 || step.Arguments == nil {
			return Plan{}, []Finding{{"PLAN_STEP", "typed-plan-validation", fmt.Sprintf("/steps/%d", index), "/properties/steps/items"}}
		}
	}
	return plan, nil
}
func proposedTool(raw []byte) string {
	var value struct {
		Steps []struct {
			Tool  string   `json:"tool"`
			Tools []string `json:"tools"`
		} `json:"steps"`
	}
	_ = json.Unmarshal(raw, &value)
	if len(value.Steps) > 0 && len(value.Steps[0].Tools) == 0 {
		return value.Steps[0].Tool
	}
	return ""
}
