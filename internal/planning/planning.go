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
	Kind  string `json:"kind"`
	Steps []Step `json:"steps"`
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

// Usage, AttemptLimits, and AttemptBudget are the gateway's budget contract.
// Planning and the gateway share one budget port so a single implementation
// governs planning attempts and the physical provider attempts inside them.
type Usage = modelgateway.Usage
type AttemptLimits = modelgateway.AttemptLimits
type AttemptBudget = modelgateway.AttemptBudget

// invocationBudget presents one planning attempt's budget to the gateway.
// The gateway authorizes each physical attempt through it, reporting that
// attempt's consumption, and the wrapper adds the consumption of the earlier
// planning attempts before consulting the pinned budget.
type invocationBudget struct {
	base        AttemptBudget
	planAttempt int
	prior       Usage
}

func (b invocationBudget) Authorize(_ int, used Usage) (AttemptLimits, error) {
	return b.base.Authorize(b.planAttempt, Usage{
		ModelCalls:   b.prior.ModelCalls + used.ModelCalls,
		InputTokens:  b.prior.InputTokens + used.InputTokens,
		OutputTokens: b.prior.OutputTokens + used.OutputTokens,
		CostMicros:   b.prior.CostMicros + used.CostMicros,
	})
}

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

// Plan resolves one typed plan through the raw attempt and bounded repair.
// Every attempt is authorized by the budget first and carries its own
// deterministic idempotency identity derived from the caller's durable
// operation key.
func (e *Engine) Plan(ctx context.Context, request modelgateway.InvokeRequest, budget AttemptBudget) (Result, error) {
	result := Result{}
	if budget == nil {
		return result, fmt.Errorf("planning requires an attempt budget")
	}
	scenario := request.Scenario
	operationKey := request.IdempotencyKey
	originalContext := append([]byte(nil), request.Context...)
	used := Usage{}
	for attempt := 0; attempt <= e.maximumRepairs; attempt++ {
		// The budget governs the attempt, and it governs every physical
		// provider attempt inside it: the gateway re-authorizes through this
		// wrapper before each retry and reports what each one consumed.
		request.Budget = invocationBudget{base: budget, planAttempt: attempt, prior: used}
		request.IdempotencyKey = fmt.Sprintf("%s:plan-attempt-%02d", operationKey, attempt)
		if attempt > 0 {
			request.Scenario = scenario + "-repair"
			request.Context = append(append([]byte(nil), originalContext...), []byte("\n[system repair] Return exactly one strict TypedPlan JSON object; do not add authority fields or prose.")...)
		}
		response, record, err := e.invoker.Invoke(ctx, request)
		// A failed invocation may still have consumed provider budget, so it
		// is recorded and counted before the error propagates.
		used = addUsage(used, record)
		if err != nil {
			// An invocation that never reached a provider — an attempt the
			// budget refused to authorize, for instance — is not an attempt
			// made, and is not recorded as one.
			if len(record.PhysicalAttempts) != 0 {
				result.Attempts = append(result.Attempts, Attempt{Number: attempt + 1, Valid: false, Findings: []Finding{{"PLAN_INVOCATION", "provider-invocation", "/", "/provider"}}, Invocation: record})
			}
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

// addUsage folds one recorded invocation into the running attempt usage.
// Every physical provider attempt counts as one model call, so a planning
// attempt that took three transport retries is accounted as three.
func addUsage(u Usage, record modelgateway.InvocationRecord) Usage {
	return Usage{
		ModelCalls:   u.ModelCalls + int64(len(record.PhysicalAttempts)),
		InputTokens:  u.InputTokens + record.InputTokens,
		OutputTokens: u.OutputTokens + record.OutputTokens,
		CostMicros:   u.CostMicros + record.CostMicros,
	}
}
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
	if plan.Kind != "TypedPlan" || len(plan.Steps) < 1 || len(plan.Steps) > maximumSteps {
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
