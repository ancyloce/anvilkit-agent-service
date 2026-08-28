package runtimeboundary

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/contracts/generated/schema"
	"github.com/ancyloce/anvilkit-agent-service/internal/agent"
	"github.com/ancyloce/anvilkit-agent-service/internal/canonical"
	"github.com/ancyloce/anvilkit-agent-service/internal/modelgateway"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/runtimes"
)

// budgetExhaustedReason is the governed runtime reason for an invocation the
// allowance cannot fund. It mirrors the vocabulary the runner already halts on.
const budgetExhaustedReason = "RUNTIME_BUDGET_EXHAUSTED"

// serveModelInvocation is the governed model path: one bounded invocation for
// one dispatched attempt, answered with the canonical governed result. The
// boundary decides nothing about the model's output; it meters, records, and
// attests what the governed gateway produced.
func (b *Boundary) serveModelInvocation(response http.ResponseWriter, httpRequest *http.Request) {
	call, ok := b.admit(response, httpRequest)
	if !ok {
		return
	}
	var request schema.ModelInvocationRequest
	if err := decodeStrict(call.body, &request); err != nil {
		b.refuse(response, http.StatusUnprocessableEntity, "CONTRACT_INVALID", "the request is not a canonical governed model invocation")
		return
	}
	if reason := bindsInvocation(request, call.task); reason != "" {
		b.refuse(response, http.StatusForbidden, "NOT_AUTHORIZED", reason)
		return
	}
	// The canonical request digest is recomputed, never trusted: it is the
	// identity a replayed invocation is answered under, and a digest the caller
	// chose could make two different invocations interchangeable.
	if reason := verifiesRequestDigest(request); reason != "" {
		b.refuse(response, http.StatusUnprocessableEntity, "CONTRACT_INVALID", reason)
		return
	}
	policy := agent.PolicyReference{
		PolicyID: string(request.ModelPolicy.PolicyId),
		Version:  request.ModelPolicy.Version,
		Digest:   string(request.ModelPolicy.Digest),
	}
	selection, err := b.cfg.Models.Select(httpRequest.Context(), call.credential.Binding.WorkspaceID, policy)
	if err != nil {
		b.refuse(response, http.StatusForbidden, "NOT_AUTHORIZED", "the pinned model policy did not resolve to a governed provider")
		return
	}
	// The allowance is read from the dispatched task's own parameters — the
	// budget this service computed and funded the turn with — never from the
	// request, which has no field to state one in.
	allowance, err := runtimes.TaskAllowanceBudget(call.task, selection)
	if err != nil {
		b.refuse(response, http.StatusForbidden, "NOT_AUTHORIZED", "the dispatched task carries no usable allowance")
		return
	}
	budget, err := allowance.Authorize(0, modelgateway.Usage{})
	if err != nil {
		b.answerJSON(response, http.StatusOK, invocationResult(request, modelgateway.InvocationRecord{}, schema.ModelInvocationResultOutcomeRefused, budgetExhaustedReason, nil, "", schema.ModelInvocationResultUsage{Cost: schema.SharedPrimitivesCost{Amount: schema.SharedPrimitivesDecimalString(decimalMicros(0)), Currency: "USD"}}))
		return
	}
	timeout := time.Duration(request.Limits.TimeoutMilliseconds) * time.Millisecond
	if timeout <= 0 {
		timeout = time.Minute
	}
	adapterResponse, record, err := b.cfg.Models.Invoke(httpRequest.Context(), modelgateway.InvokeRequest{
		RunID:       string(call.task.RunId),
		WorkspaceID: call.credential.Binding.WorkspaceID,
		ProjectID:   call.credential.Binding.ProjectID,
		// The idempotency identity is the attempt-and-operation identity the
		// canonical request carries: a network retry of the same invocation
		// replays the recorded outcome instead of billing a second one.
		IdempotencyKey: request.Idempotency.Key,
		Selection:      selection,
		// The compiled context is pinned by digest; the controlled provider
		// answers from its governed script and never reads a disclosure.
		Context:             []byte(request.ContextDigest),
		DataClasses:         selection.DataClasses,
		MaximumOutputBytes:  request.Limits.OutputBytes,
		MaximumInputTokens:  budget.MaximumInputTokens,
		MaximumOutputTokens: budget.MaximumOutputTokens,
		MaximumTotalTokens:  budget.MaximumTotalTokens,
		MaximumCostMicros:   budget.MaximumCostMicros,
		Timeout:             timeout,
		MaximumAttempts:     1,
		RetryBudget:         timeout,
		Budget:              allowance,
	})
	usage := usageOf(record)
	if err != nil {
		var details problem.Details
		if errors.As(err, &details) && details.Code == string(problem.CodeBudgetDenied) {
			// A refused invocation is the governed path working and saying no.
			// It is an answer, with the usage the refusal itself metered.
			b.answerJSON(response, http.StatusOK, invocationResult(request, record, schema.ModelInvocationResultOutcomeRefused, budgetExhaustedReason, nil, "", usage))
			return
		}
		b.refuse(response, http.StatusInternalServerError, "INTERNAL", "the governed model path could not serve this invocation")
		return
	}
	output := adapterResponse.Output
	// The controlled provider's scripted output is release material and cannot
	// know which run it serves; the boundary resolves its placeholder tokens
	// from the dispatched task. This is the test-profile provider behaving
	// like a model that read the disclosed context — a real provider's output
	// never carries the tokens, and the substitution is gated on the provider
	// identity so nothing here rewrites a governed model's answer.
	if string(selection.Provider.ID) == controlledProviderID {
		output = substitutePlaceholders(output, call.task, call.credential.Binding)
	}
	outputs, outputDigest, err := governedOutputs(output)
	if err != nil {
		b.refuse(response, http.StatusInternalServerError, "INTERNAL", "the governed output is not a bounded output document")
		return
	}
	b.answerJSON(response, http.StatusOK, invocationResult(request, record, schema.ModelInvocationResultOutcomeOk, completedReasonCode, outputs, outputDigest, usage))
}

// completedReasonCode is the governed reason a completed invocation reports,
// the same value the canonical fixture corpus records for an ok outcome.
const completedReasonCode = "GATEWAY_MODEL_COMPLETED"

// controlledProviderID mirrors execution.ControlledProviderID without
// importing the execution package here; the composition test proves the two
// spellings agree.
const controlledProviderID = "controlled-fake-provider"

// substitutePlaceholders resolves the controlled script's placeholder tokens
// from the dispatched task and the verified credential binding.
func substitutePlaceholders(output []byte, task schema.AgentTask, binding runtimes.Binding) []byte {
	parameters := map[string]string(task.Parameters)
	text := string(output)
	for token, value := range map[string]string{
		"{{workspaceId}}": binding.WorkspaceID,
		"{{projectId}}":   binding.ProjectID,
		"{{targetType}}":  parameters["target.type"],
		"{{targetId}}":    parameters["target.id"],
	} {
		text = strings.ReplaceAll(text, token, value)
	}
	return []byte(text)
}

// bindsInvocation holds the canonical request to the dispatched task. A
// request naming other work would attribute this invocation's tokens, and its
// output, to an attempt that never asked for it.
func bindsInvocation(request schema.ModelInvocationRequest, task schema.AgentTask) string {
	if request.TaskId != task.TaskId || request.RunId != task.RunId || request.RootRunId != task.RootRunId ||
		request.PhysicalAttemptId != task.PhysicalAttemptId ||
		request.AttemptNumber != task.AttemptNumber || request.ExecutionGeneration != task.ExecutionGeneration {
		return "the invocation does not belong to the dispatched attempt"
	}
	if request.Definition != task.Definition {
		return "the invocation names a definition the attempt was not dispatched under"
	}
	if request.ContractBomReference != task.ContractBomReference {
		return "the invocation names contract material the attempt was not dispatched under"
	}
	parameters := map[string]string(task.Parameters)
	if string(request.ContextDigest) != parameters["model.contextDigest"] {
		return "the invocation names a compiled context the attempt was not dispatched with"
	}
	if string(request.PromptDigest) != parameters["model.promptDigest"] {
		return "the invocation names a prompt the attempt was not dispatched with"
	}
	if string(request.ModelPolicy.PolicyId) != parameters["model.policyId"] ||
		request.ModelPolicy.Version != parameters["model.policyVersion"] ||
		string(request.ModelPolicy.Digest) != parameters["model.policyDigest"] {
		return "the invocation names a model policy the attempt was not dispatched under"
	}
	if request.Idempotency.Scope != idempotencyScope ||
		!strings.HasPrefix(request.Idempotency.Key, string(task.PhysicalAttemptId)+":") {
		return "the invocation idempotency identity does not belong to the dispatched attempt"
	}
	return ""
}

// verifiesRequestDigest recomputes the canonical request digest: RFC 8785
// canonical bytes of the request with its idempotency member removed — a
// document cannot contain the hash of itself. The construction is the one the
// runtime SDK defines; both sides must compute it identically.
func verifiesRequestDigest(request schema.ModelInvocationRequest) string {
	encoded, err := json.Marshal(request)
	if err != nil {
		return "the invocation could not be canonicalized"
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &document); err != nil {
		return "the invocation could not be canonicalized"
	}
	delete(document, "idempotency")
	withoutIdempotency, err := json.Marshal(document)
	if err != nil {
		return "the invocation could not be canonicalized"
	}
	digest, err := canonical.Digest(withoutIdempotency)
	if err != nil {
		return "the invocation could not be canonicalized"
	}
	if digest != string(request.Idempotency.CanonicalRequestDigest) {
		return "the canonical request digest does not cover this invocation"
	}
	return ""
}

// governedOutputs reads the provider's governed output document as the bounded
// output map the canonical result carries, and digests its canonical bytes —
// the same construction the runtime verifies before it reasons over a value.
//
// A value longer than one bound is split into the indexed continuation the
// runtime SDK reassembles (`key`, then `key.0`, `key.1`, …): the canonical
// output map bounds each value at 1024 characters, and a real page brief is
// longer than that. The runtime and the boundary agree on the chunked map
// because the digest is taken over exactly the map that is sent.
func governedOutputs(output []byte) (schema.SharedPrimitivesBoundedStringMap, string, error) {
	var raw map[string]string
	if err := decodeStrict(output, &raw); err != nil {
		return nil, "", fmt.Errorf("governed output: %w", err)
	}
	outputs := map[string]string{}
	for key, value := range raw {
		chunks := chunkValue(value)
		if len(chunks) == 1 {
			outputs[key] = chunks[0]
			continue
		}
		for index, chunk := range chunks {
			outputs[key+"."+strconv.Itoa(index)] = chunk
		}
	}
	if len(outputs) > 32 {
		return nil, "", fmt.Errorf("governed output: the chunked output exceeds the bounded map key count")
	}
	encoded, err := json.Marshal(outputs)
	if err != nil {
		return nil, "", fmt.Errorf("governed output: %w", err)
	}
	digest, err := canonical.Digest(encoded)
	if err != nil {
		return nil, "", fmt.Errorf("governed output: %w", err)
	}
	return schema.SharedPrimitivesBoundedStringMap(outputs), digest, nil
}

// maximumOutputValueRunes is the per-value bound the canonical bounded map
// enforces. A value at or under it travels as one member; anything over is
// split into the indexed continuation.
const maximumOutputValueRunes = 1024

// chunkValue splits one value into 1024-rune pieces on rune boundaries.
func chunkValue(value string) []string {
	runes := []rune(value)
	if len(runes) <= maximumOutputValueRunes {
		return []string{value}
	}
	chunks := make([]string, 0, (len(runes)+maximumOutputValueRunes-1)/maximumOutputValueRunes)
	for start := 0; start < len(runes); start += maximumOutputValueRunes {
		end := start + maximumOutputValueRunes
		if end > len(runes) {
			end = len(runes)
		}
		chunks = append(chunks, string(runes[start:end]))
	}
	return chunks
}

func invocationResult(
	request schema.ModelInvocationRequest,
	record modelgateway.InvocationRecord,
	outcome schema.ModelInvocationResultOutcome,
	reasonCode string,
	outputs schema.SharedPrimitivesBoundedStringMap,
	outputDigest string,
	usage schema.ModelInvocationResultUsage,
) schema.ModelInvocationResult {
	if outputs == nil {
		outputs = schema.SharedPrimitivesBoundedStringMap{}
	}
	if outputDigest == "" {
		// An empty output still has a canonical identity; digesting the empty
		// document keeps the member well-formed for refused outcomes.
		if encoded, err := json.Marshal(map[string]string{}); err == nil {
			if digest, err := canonical.Digest(encoded); err == nil {
				outputDigest = digest
			}
		}
	}
	invocationID := record.InvocationID
	if invocationID == "" {
		invocationID = string(modelgateway.InvocationIdentity(request.Idempotency.Key))
	}
	return schema.ModelInvocationResult{
		Kind:                "ModelInvocationResult",
		TaskId:              request.TaskId,
		PhysicalAttemptId:   request.PhysicalAttemptId,
		AttemptNumber:       request.AttemptNumber,
		ExecutionGeneration: request.ExecutionGeneration,
		InvocationId:        schema.SharedPrimitivesOpaqueId(invocationID),
		Outcome:             outcome,
		ReasonCode:          reasonCode,
		Output:              outputs,
		OutputDigest:        schema.SharedPrimitivesDigest(outputDigest),
		Usage:               usage,
		TraceContext:        request.TraceContext,
	}
}

// usageOf reports what the gateway metered for this invocation. A refused
// invocation still spent whatever was metered before the refusal.
func usageOf(record modelgateway.InvocationRecord) schema.ModelInvocationResultUsage {
	duration := 0
	if record.CompletedAt != nil {
		duration = int(record.CompletedAt.Sub(record.StartedAt) / time.Millisecond)
		if duration < 0 {
			duration = 0
		}
	}
	return schema.ModelInvocationResultUsage{
		InputTokens:          int(record.InputTokens),
		OutputTokens:         int(record.OutputTokens),
		DurationMilliseconds: duration,
		Cost: schema.SharedPrimitivesCost{
			Amount:   schema.SharedPrimitivesDecimalString(decimalMicros(record.CostMicros)),
			Currency: "USD",
		},
	}
}

// decimalMicros renders micros as the canonical decimal cost string.
func decimalMicros(micros int64) string {
	if micros < 0 {
		micros = 0
	}
	whole := micros / 1_000_000
	fraction := micros % 1_000_000
	if fraction == 0 {
		return strconv.FormatInt(whole, 10)
	}
	text := fmt.Sprintf("%d.%06d", whole, fraction)
	for text[len(text)-1] == '0' {
		text = text[:len(text)-1]
	}
	return text
}
