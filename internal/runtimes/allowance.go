package runtimes

import (
	"fmt"
	"strconv"

	"github.com/ancyloce/anvilkit-agent-service/contracts/generated/schema"
	"github.com/ancyloce/anvilkit-agent-service/internal/modelgateway"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
)

// TaskAllowanceBudget is the attempt budget a dispatched task funds: the five
// allowance parameters this service computed when it dispatched the turn,
// bounded further by what the selected provider may cost.
//
// It is exported for the service side of the runtime boundary, which enforces
// the same allowance against a released unit's governed invocations that the
// in-process stand-in enforces against its own — one budget semantics, not two
// spellings of it.
func TaskAllowanceBudget(task schema.AgentTask, selection modelgateway.Selection) (modelgateway.AttemptBudget, error) {
	budget, err := taskBudgetOf(task, selection)
	if err != nil {
		return nil, err
	}
	return budget, nil
}

// taskBudget authorizes each provider attempt against the allowance the task
// carries and the ceiling the approved model policy sets, whichever binds
// first.
//
// Every attempt of a turn narrows it, repairs and transport retries included:
// enforcing an allowance only before the first call is how a repairing turn
// spends past what it was given. The allowance is not authority the runtime
// holds — Agent Service computed it, gated the dispatch on it, and accounts
// what was spent — it is what the runtime needs in order to stop.
type taskBudget struct {
	modelCalls, inputTokens, outputTokens, totalTokens, costMicros int64
	providerCostMicros                                             int64
}

// taskBudgetOf reads the allowance the task declares. A task that declares
// none funds nothing: a runtime that cannot see an allowance cannot enforce
// one, and spending against an unknown budget is the failure this refuses.
func taskBudgetOf(task schema.AgentTask, selection modelgateway.Selection) (taskBudget, error) {
	budget := taskBudget{providerCostMicros: selection.MaximumCostMicros}
	for _, field := range []struct {
		name  string
		value *int64
	}{
		{"allowanceModelCalls", &budget.modelCalls},
		{"allowanceInputTokens", &budget.inputTokens},
		{"allowanceOutputTokens", &budget.outputTokens},
		{"allowanceTotalTokens", &budget.totalTokens},
		{"allowanceCostMicros", &budget.costMicros},
	} {
		declared, present := task.Parameters[field.name]
		if !present {
			return taskBudget{}, fmt.Errorf("runtime allowance: the task declares no %s", field.name)
		}
		parsed, err := strconv.ParseInt(declared, 10, 64)
		if err != nil {
			return taskBudget{}, fmt.Errorf("runtime allowance: %s is not an allowance: %w", field.name, err)
		}
		*field.value = parsed
	}
	return budget, nil
}

func (b taskBudget) Authorize(_ int, used modelgateway.Usage) (modelgateway.AttemptLimits, error) {
	remainingCalls := b.modelCalls - used.ModelCalls
	remainingInput := b.inputTokens - used.InputTokens
	remainingOutput := b.outputTokens - used.OutputTokens
	// used covers every physical attempt already made inside this invocation
	// and, through the planning wrapper, every earlier repair attempt of the
	// turn, so the aggregate shrinks across repairs and retries exactly as it
	// does across turns.
	remainingTotal := b.totalTokens - (used.InputTokens + used.OutputTokens)
	remainingCost := b.costMicros - used.CostMicros
	if remainingCalls < 1 || remainingInput < 1 || remainingOutput < 1 || remainingTotal < 1 || remainingCost < 1 {
		details := problem.New(problem.CodeBudgetDenied, "")
		details.Detail = "the allowance this turn was dispatched with is exhausted"
		return modelgateway.AttemptLimits{}, details
	}
	cost := remainingCost
	if b.providerCostMicros > 0 && b.providerCostMicros < cost {
		cost = b.providerCostMicros
	}
	// No component ceiling may exceed what is left of the aggregate: an
	// attempt authorized for more input than the aggregate allows would spend
	// past the allowance in a single call.
	return modelgateway.AttemptLimits{
		MaximumInputTokens:  minimum64(remainingInput, remainingTotal),
		MaximumOutputTokens: minimum64(remainingOutput, remainingTotal),
		MaximumTotalTokens:  remainingTotal,
		MaximumCostMicros:   cost,
	}, nil
}

func minimum64(left, right int64) int64 {
	if left < right {
		return left
	}
	return right
}
