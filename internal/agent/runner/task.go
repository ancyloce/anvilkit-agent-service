package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/contracts/generated/schema"
	"github.com/ancyloce/anvilkit-agent-service/internal/agent"
	"github.com/ancyloce/anvilkit-agent-service/internal/canonical"
	"github.com/ancyloce/anvilkit-agent-service/internal/dispatch"
	"github.com/ancyloce/anvilkit-agent-service/internal/runtimes"
)

// taskIdempotencyScope names the identity space one turn's task is created in.
// It is fixed: a scope a caller could choose would let two different kinds of
// work share an idempotency key.
const taskIdempotencyScope = "agent-turn"

// createTask is the second stage of a turn: the durable record of what is to
// be executed, and the canonical AgentTask that carries it.
//
// The logical task is created once per durable operation and the physical
// attempt is opened under it, with its own attempt number, lease epoch, and
// fence. Both happen before anything is dispatched, so an execution that
// leaves this process is one the durable record already knows about — the
// alternative loses exactly the executions that need recovering.
func (r *Runner) createTask(ctx context.Context, request TurnRequest, compiled []byte, replacing string) (schema.AgentTask, dispatch.Execution, runtimes.Credential, error) {
	parameters, artifactInputs, err := turnParameters(request, contentDigest(compiled))
	if err != nil {
		return schema.AgentTask{}, dispatch.Execution{}, runtimes.Credential{}, err
	}
	requestDigest, err := logicalRequestDigest(request, parameters)
	if err != nil {
		return schema.AgentTask{}, dispatch.Execution{}, runtimes.Credential{}, err
	}
	execution, err := r.tasks.Open(ctx, dispatch.Request{
		Scope:               dispatch.Scope{WorkspaceID: request.Run.WorkspaceID, ProjectID: request.Run.ProjectID},
		TaskID:              dispatch.TaskID(request.OperationKey),
		RunID:               request.Run.RunID,
		RootRunID:           rootRunOf(request.Run),
		ExecutionGeneration: request.Run.ExecutionGeneration,
		DefinitionDigest:    request.Definition.DefinitionDigest,
		Runtime:             request.Runtime,
		Capability:          string(schema.AgentTaskCapabilityProviderInvoke),
		RequestDigest:       requestDigest,
		Replacing:           replacing,
	})
	if err != nil {
		return schema.AgentTask{}, dispatch.Execution{}, runtimes.Credential{}, fmt.Errorf("open a physical attempt for the turn: %w", err)
	}
	task := schema.AgentTask{
		Kind:                  "AgentTask",
		TaskId:                schema.SharedPrimitivesOpaqueId(execution.Task.TaskID),
		RunId:                 schema.SharedPrimitivesOpaqueId(execution.Task.RunID),
		RootRunId:             schema.SharedPrimitivesOpaqueId(execution.Task.RootRunID),
		PhysicalAttemptId:     schema.SharedPrimitivesOpaqueId(execution.Attempt.PhysicalAttemptID),
		AttemptNumber:         int(execution.Attempt.AttemptNumber),
		ExecutionGeneration:   int(execution.Task.ExecutionGeneration),
		LeaseEpoch:            int(execution.Attempt.LeaseEpoch),
		FenceToken:            execution.FenceToken,
		ExpiresAt:             schema.SharedPrimitivesTimestamp(execution.Attempt.ExpiresAt),
		Definition:            schema.SharedPrimitivesDefinitionReference{DefinitionId: schema.SharedPrimitivesOpaqueId(request.Definition.DefinitionID), DefinitionDigest: schema.SharedPrimitivesDigest(request.Definition.DefinitionDigest)},
		RuntimeBinding:        runtimeBinding(request.Runtime),
		AuthorizationAudience: request.Runtime.RuntimeAudience,
		Capability:            schema.AgentTaskCapabilityProviderInvoke,
		InputSchema:           schema.SharedPrimitivesSchemaReference{ComponentName: request.Definition.InputSchema.ComponentName, Digest: schema.SharedPrimitivesDigest(request.Definition.InputSchema.Digest)},
		// The compiled disclosure is pinned by digest rather than carried: the
		// canonical task's parameter map is bounded, and a context that had to
		// fit in it would be a context truncated by the wire rather than by
		// the guardrail policy. The disclosure travels the artifact path a
		// runtime reads under its task-scoped credential. What IS pinned as an
		// input is material the turn must verify against its own task — a
		// delegated candidate the next turn concludes on, or the references a
		// delegation's brief names.
		ArtifactInputs: artifactInputs,
		Parameters:     parameters,
		Resources:      schema.AgentTaskResources{ResourceClass: schema.AgentTaskResourcesResourceClassInteractiveCpu, Priority: interactivePriority},
		Limits: schema.SharedPrimitivesResourceLimits{
			TimeoutMilliseconds: int(r.limits.Timeout / time.Millisecond),
			MemoryBytes:         int(r.limits.MemoryBytes),
			CpuMillis:           int(r.limits.CPUMillis),
			GpuMillis:           0,
			OutputBytes:         r.limits.MaximumOutputBytes,
		},
		Idempotency:          schema.SharedPrimitivesIdempotency{Scope: taskIdempotencyScope, Key: request.OperationKey, CanonicalRequestDigest: schema.SharedPrimitivesDigest(requestDigest)},
		TraceContext:         schema.SharedPrimitivesTraceContext{Traceparent: request.Run.Traceparent},
		ContractBomReference: request.ContractBOM,
	}
	if r.disclosure != nil {
		if err := r.disclosure.Offer(ctx, task, compiled); err != nil {
			return schema.AgentTask{}, dispatch.Execution{}, runtimes.Credential{}, fmt.Errorf("offer the compiled context to the runtime: %w", err)
		}
	}
	credential, err := r.credentials.Issue(ctx, task, runtimes.Subject{WorkspaceID: request.Run.WorkspaceID, ProjectID: request.Run.ProjectID})
	if err != nil {
		return schema.AgentTask{}, dispatch.Execution{}, runtimes.Credential{}, fmt.Errorf("issue the task-scoped credential: %w", err)
	}
	return task, execution, credential, nil
}

// interactivePriority is where an agent turn sits in the runtime's admission
// order: a person is waiting for it, and it is not more important than
// anything else that a person is waiting for.
const interactivePriority = 500

func runtimeBinding(binding agent.RuntimeBinding) schema.AgentTaskRuntimeBinding {
	return schema.AgentTaskRuntimeBinding{
		RuntimeUnitId:            schema.SharedPrimitivesOpaqueId(binding.RuntimeUnitID),
		RuntimeManifestDigest:    schema.SharedPrimitivesDigest(binding.RuntimeManifestDigest),
		RuntimeImageDigest:       schema.SharedPrimitivesDigest(binding.RuntimeImageDigest),
		InvocationProtocolDigest: schema.SharedPrimitivesDigest(binding.InvocationProtocolDigest),
		RuntimeAudience:          binding.RuntimeAudience,
	}
}

// turnParameters is everything a runtime is told about the turn beyond its own
// identity: the turn basics, the allowance, the governed-model pins the
// released units resolve their invocations by, the delegation outcome a
// concluding turn validates, and — for a delegate turn — the supplied brief
// the delegation's validated input carries.
//
// The allowance is here rather than withheld because the governed result
// vocabulary has a runtime reason for exhausting a budget: a runtime is
// expected to stop rather than spend past what it was given. What travels is
// what is left for this turn, never the pinned budget itself — Agent Service
// remains the authority that computes it, gates the dispatch on it, and
// accounts what was actually spent.
//
// The map is bounded by contract at 32 members, so every key here is a
// decision: the context digest travels once, under the model.* vocabulary the
// released units read, and the delegate-turn depth is carried by the phase.
func turnParameters(request TurnRequest, contextDigest string) (schema.SharedPrimitivesBoundedStringMap, []schema.SharedPrimitivesArtifactReference, error) {
	parameters := schema.SharedPrimitivesBoundedStringMap{
		"phase":                 request.Phase,
		"turn":                  strconv.Itoa(request.Turn),
		"domain":                request.Run.Domain,
		"operation":             request.Run.Operation,
		"allowanceModelCalls":   strconv.FormatInt(request.Budget.RemainingModelCalls, 10),
		"allowanceInputTokens":  strconv.FormatInt(request.Budget.RemainingInputTokens, 10),
		"allowanceOutputTokens": strconv.FormatInt(request.Budget.RemainingOutputTokens, 10),
		"allowanceTotalTokens":  strconv.FormatInt(request.Budget.RemainingTotalTokens, 10),
		"allowanceCostMicros":   strconv.FormatInt(request.Budget.RemainingCostMicros, 10),
		// The governed-model pins: the compiled context and prompt this turn
		// was dispatched with, and the model policy the definition pins. A
		// released unit invokes the governed gateway with exactly these, and
		// the boundary refuses an invocation naming any others.
		"model.contextDigest": contextDigest,
		"model.promptDigest":  request.Definition.PromptDigest,
		"model.policyId":      request.Definition.ModelPolicy.PolicyID,
		"model.policyVersion": request.Definition.ModelPolicy.Version,
		"model.policyDigest":  request.Definition.ModelPolicy.Digest,
	}
	if request.ReviewReason != "" {
		parameters["reviewReason"] = truncate(request.ReviewReason, maximumParameterBytes)
	}
	artifactInputs := []schema.SharedPrimitivesArtifactReference{}
	if request.Delegation != nil {
		// The concluding turn validates the delegation outcome against what
		// the control plane pinned: the state, the delegate, and — for a
		// completed delegation — the candidate reference, pinned as one of the
		// task's own artifact inputs so the runtime can prove the reference it
		// is told about is the one it was dispatched with.
		parameters["delegation.state"] = request.Delegation.State
		parameters["delegation.delegate"] = request.Delegation.DelegateID
		if request.Delegation.ReasonCode != "" {
			parameters["delegation.reasonCode"] = request.Delegation.ReasonCode
		}
		if request.Delegation.Candidate.ArtifactId != "" {
			writeReference(parameters, "delegation.candidate", request.Delegation.Candidate)
			artifactInputs = append(artifactInputs, request.Delegation.Candidate)
		}
	}
	if request.Phase == PhaseDelegate {
		briefInputs, err := delegateBriefParameters(request, parameters)
		if err != nil {
			return nil, nil, err
		}
		artifactInputs = append(artifactInputs, briefInputs...)
	} else {
		// The run's target identity travels on non-delegate turns: the
		// governed provider proposes work about the target, and a proposal is
		// checked against the run's own identity when the control plane acts
		// on it. Delegate turns carry the same fact as the candidate pins.
		parameters["target.type"] = request.Run.TargetType
		parameters["target.id"] = request.Run.TargetID
	}
	if len(parameters) > maximumParameterMembers {
		return nil, nil, fmt.Errorf("the turn's supplied context exceeds the %d-member bound the canonical task carries", maximumParameterMembers)
	}
	return parameters, artifactInputs, nil
}

// maximumParameterMembers is the canonical bound on the task parameter map.
const maximumParameterMembers = 32

// delegateBrief is the validated delegation input: the canonical
// create-agent-run-request document the Manager proposed and the control plane
// validated against the specialist's pinned input schema.
type delegateBrief struct {
	Kind       string                                     `json:"kind"`
	Definition schema.SharedPrimitivesDefinitionReference `json:"definition"`
	Operation  string                                     `json:"operation"`
	Target     struct {
		TargetType  string `json:"targetType"`
		TargetID    string `json:"targetId"`
		WorkspaceID string `json:"workspaceId"`
		ProjectID   string `json:"projectId"`
	} `json:"target"`
	Input *struct {
		UserInput      string                                     `json:"userInput,omitempty"`
		ArtifactInputs []schema.SharedPrimitivesArtifactReference `json:"artifactInputs,omitempty"`
	} `json:"input,omitempty"`
	Labels map[string]string `json:"labels,omitempty"`
}

// delegateBriefParameters turns the delegation's validated input into the
// specialist's supplied context.
//
// What the Manager may supply and what the control plane must decide are kept
// apart here. The brief's userInput carries the page material — component
// schema, defaults, style and animation constraints, and the candidate pins —
// under the page.* and candidate.* vocabulary and no other: a brief member
// that named an allowance, a model pin, or a delegation key would be a
// delegation widening its own authority, and it is refused. The candidate's
// target pins are then overwritten from the run's own identity, because where
// a candidate lands is the control plane's fact, not the proposal's.
func delegateBriefParameters(request TurnRequest, parameters schema.SharedPrimitivesBoundedStringMap) ([]schema.SharedPrimitivesArtifactReference, error) {
	// The delegation input's shape is the specialist's pinned input schema,
	// already validated by delegation authorization. Only the canonical
	// create-run request carries a supplied brief; a specialist pinned to any
	// other input reads it from the compiled disclosure, and this composer
	// leaves it untouched.
	var probe struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(request.InputValue, &probe); err != nil || probe.Kind != "CreateAgentRunRequest" {
		return nil, nil
	}
	var brief delegateBrief
	decoder := json.NewDecoder(bytes.NewReader(request.InputValue))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&brief); err != nil {
		return nil, fmt.Errorf("the delegation input is not the canonical request the specialist was pinned to accept: %w", err)
	}
	if brief.Definition.DefinitionId != schema.SharedPrimitivesOpaqueId(request.Definition.DefinitionID) ||
		string(brief.Definition.DefinitionDigest) != request.Definition.DefinitionDigest {
		return nil, fmt.Errorf("the delegation input names a definition other than the resolved specialist")
	}
	if brief.Operation != request.Run.Operation {
		return nil, fmt.Errorf("the delegation input names an operation other than the run's")
	}
	if brief.Target.TargetType != request.Run.TargetType || brief.Target.TargetID != request.Run.TargetID ||
		brief.Target.WorkspaceID != request.Run.WorkspaceID || brief.Target.ProjectID != request.Run.ProjectID {
		return nil, fmt.Errorf("the delegation input names a target other than the run's")
	}
	supplied := map[string]string{}
	if brief.Input != nil && brief.Input.UserInput != "" {
		decoder := json.NewDecoder(strings.NewReader(brief.Input.UserInput))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&supplied); err != nil {
			return nil, fmt.Errorf("the delegation brief is not a bounded supplied-context document: %w", err)
		}
	}
	for key, value := range supplied {
		if !strings.HasPrefix(key, "page.") && !strings.HasPrefix(key, "candidate.") {
			return nil, fmt.Errorf("the delegation brief carries a member outside the supplied-context vocabulary")
		}
		if len(value) > maximumParameterBytes {
			return nil, fmt.Errorf("a delegation brief member exceeds the bounded value size")
		}
		parameters[key] = value
	}
	// The candidate's target is the run's target: the control plane's fact.
	parameters["candidate.target.type"] = request.Run.TargetType
	parameters["candidate.target.id"] = request.Run.TargetID
	parameters["candidate.target.workspaceId"] = request.Run.WorkspaceID
	parameters["candidate.target.projectId"] = request.Run.ProjectID
	inputs := []schema.SharedPrimitivesArtifactReference{}
	if brief.Input != nil {
		inputs = append(inputs, brief.Input.ArtifactInputs...)
	}
	return inputs, nil
}

// writeReference spells one artifact reference in the supplied-context
// vocabulary the runtime SDK reads references with.
func writeReference(parameters schema.SharedPrimitivesBoundedStringMap, prefix string, reference schema.SharedPrimitivesArtifactReference) {
	parameters[prefix+".artifactId"] = string(reference.ArtifactId)
	parameters[prefix+".digest"] = string(reference.Digest)
	parameters[prefix+".mediaType"] = reference.MediaType
	parameters[prefix+".sizeBytes"] = strconv.Itoa(reference.SizeBytes)
}

// maximumParameterBytes is the canonical bound on one parameter value.
const maximumParameterBytes = 1024

// logicalRequestDigest is the identity of the work, independent of which
// attempt carries it. Attempt identity, lease epoch, and fence are excluded on
// purpose: a replacement attempt of the same turn must digest identically, or
// every recovery would look like a reused idempotency key.
func logicalRequestDigest(request TurnRequest, parameters schema.SharedPrimitivesBoundedStringMap) (string, error) {
	document, err := json.Marshal(struct {
		Definition  string                                      `json:"definitionDigest"`
		Run         string                                      `json:"runId"`
		Generation  uint64                                      `json:"executionGeneration"`
		Operation   string                                      `json:"operationKey"`
		Capability  string                                      `json:"capability"`
		Runtime     schema.AgentTaskRuntimeBinding              `json:"runtimeBinding"`
		Parameters  schema.SharedPrimitivesBoundedStringMap     `json:"parameters"`
		ContractBOM schema.SharedPrimitivesContractBomReference `json:"contractBomReference"`
	}{
		Definition:  request.Definition.DefinitionDigest,
		Run:         request.Run.RunID,
		Generation:  request.Run.ExecutionGeneration,
		Operation:   request.OperationKey,
		Capability:  string(schema.AgentTaskCapabilityProviderInvoke),
		Runtime:     runtimeBinding(request.Runtime),
		Parameters:  parameters,
		ContractBOM: request.ContractBOM,
	})
	if err != nil {
		return "", fmt.Errorf("encode the logical task request: %w", err)
	}
	digest, err := canonical.Digest(document)
	if err != nil {
		return "", fmt.Errorf("digest the logical task request: %w", err)
	}
	return digest, nil
}

// rootRunOf falls back to the run's own identity. A root run is its own root,
// and a task that carried an empty lineage would be unattributable.
func rootRunOf(run RunView) string {
	if run.RootRunID != "" {
		return run.RootRunID
	}
	return run.RunID
}
