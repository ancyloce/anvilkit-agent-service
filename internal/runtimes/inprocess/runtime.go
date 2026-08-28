package inprocess

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/contracts/generated/schema"
	"github.com/ancyloce/anvilkit-agent-service/internal/agent"
	"github.com/ancyloce/anvilkit-agent-service/internal/eligibility"
	"github.com/ancyloce/anvilkit-agent-service/internal/modelgateway"
	"github.com/ancyloce/anvilkit-agent-service/internal/planning"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/runtimes"
)

// Selector resolves the policy-eligible provider selection for one turn.
type Selector interface {
	Select(ctx context.Context, workspaceID string, policy agent.PolicyReference) (modelgateway.Selection, error)
}

// Invoker performs one policy-eligible provider invocation through the
// governed Model Gateway.
type Invoker interface {
	Invoke(context.Context, modelgateway.InvokeRequest) (modelgateway.AdapterResponse, modelgateway.InvocationRecord, error)
}

// Definitions resolves the definition a task pins, so the stand-in runtime
// reasons under the same pinned policy a released unit would have been built
// with.
type Definitions interface {
	Resolve(definitionID, definitionDigest string) (agent.Definition, error)
}

// Runtime is an in-process stand-in for a runtime release.
//
// It exists so a deployment with no separate runtime process can still exercise
// the whole dispatch path — task creation, fencing, dispatch, a signed
// canonical result, and the fenced commit — against the same contract
// production uses. What it is not is a runtime: it runs inside this process,
// reaches this process's model path directly, and says so, which is why
// production refuses it whatever it is configured as.
//
// It also stands in for the two boundaries a real unit crosses on its own: the
// task-scoped context it would read from the control plane, and the artifact
// store it would write a candidate to. Both are in-process exchanges here, and
// both are digest-verified, so the control plane's side of those boundaries is
// exercised exactly as it will be when a released unit is on the other end.
type Runtime struct {
	definitions Definitions
	selector    Selector
	invoker     Invoker
	signer      ResultSigner
	credentials *runtimes.CredentialTrust
	now         func() time.Time
	repairs     int

	lock sync.Mutex
	// disclosures holds one attempt's compiled context, keyed by the physical
	// attempt it was compiled for. A stand-in that read any other attempt's
	// context would be reading disclosure it was never granted.
	disclosures map[string][]byte
	// candidates holds documents this runtime produced, keyed by content
	// digest, until the control plane reads them back.
	candidates map[string][]byte
}

// ResultSigner signs the canonical statement of one result.
type ResultSigner interface {
	Sign(statement []byte) (algorithm, keyID, signature string, err error)
}

// Config is the stand-in's dependency set.
type Config struct {
	Definitions Definitions
	Selector    Selector
	Invoker     Invoker
	Signer      ResultSigner
	// Credentials verifies the task-scoped credential a dispatch presents. It
	// is required: an in-process stand-in that read the claims it was handed
	// instead of verifying the token would be admitting work through a
	// different door from the one a released unit opens.
	Credentials *runtimes.CredentialTrust
	Now         func() time.Time
	// Repairs is the deployment's ceiling on typed-plan repair attempts. The
	// definition's own pinned repair policy decides how many a turn actually
	// makes; this only bounds it, so a definition cannot ask a deployment for
	// more repair than it allows.
	Repairs int
}

func New(cfg Config) (*Runtime, error) {
	if cfg.Definitions == nil || cfg.Selector == nil || cfg.Invoker == nil || cfg.Signer == nil || cfg.Credentials == nil || cfg.Now == nil {
		return nil, fmt.Errorf("controlled runtime: definitions, a provider selector, an invoker, a result signer, a credential verifier, and a clock are all required")
	}
	if cfg.Repairs < 0 || cfg.Repairs > 3 {
		return nil, fmt.Errorf("controlled runtime: bounded repair attempts must be between zero and three")
	}
	return &Runtime{
		definitions: cfg.Definitions,
		selector:    cfg.Selector,
		invoker:     cfg.Invoker,
		signer:      cfg.Signer,
		credentials: cfg.Credentials,
		now:         cfg.Now,
		repairs:     cfg.Repairs,
		disclosures: map[string][]byte{},
		candidates:  map[string][]byte{},
	}, nil
}

// Eligibility declares this implementation controlled. It is the whole reason
// production can refuse it without anyone having to recognise its name.
func (*Runtime) Eligibility() eligibility.Eligibility { return eligibility.ControlledOnly }

// Offer accepts the compiled context for one attempt. It is the in-process
// stand-in for the task-scoped context read a released unit performs against
// the control plane under its own credential.
func (c *Runtime) Offer(_ context.Context, task schema.AgentTask, compiled []byte) error {
	if len(compiled) == 0 {
		return fmt.Errorf("controlled runtime: a turn cannot be executed against an empty disclosure")
	}
	c.lock.Lock()
	defer c.lock.Unlock()
	c.disclosures[string(task.PhysicalAttemptId)] = append([]byte(nil), compiled...)
	return nil
}

// Content returns a document this runtime produced. The caller verifies the
// digest; this side returns bytes and nothing else, exactly as an artifact
// store would.
func (c *Runtime) Content(_ context.Context, reference schema.SharedPrimitivesArtifactReference) ([]byte, error) {
	c.lock.Lock()
	defer c.lock.Unlock()
	content, present := c.candidates[string(reference.Digest)]
	if !present {
		return nil, fmt.Errorf("controlled runtime: no document was produced for %s", reference.ArtifactId)
	}
	return append([]byte(nil), content...), nil
}

// Dispatch executes one physical attempt and returns a signed canonical
// result. The admission checks mirror what a released unit enforces at its own
// boundary, because a stand-in that admitted what a runtime would refuse would
// hide exactly the failures this path exists to surface.
func (c *Runtime) Dispatch(ctx context.Context, binding agent.RuntimeBinding, task schema.AgentTask, credential runtimes.Credential) (runtimes.DispatchReceipt, error) {
	dispatchedAt := c.now().UTC()
	verified, err := c.admit(binding, task, credential, dispatchedAt)
	if err != nil {
		return runtimes.DispatchReceipt{}, err
	}
	// Everything below acts inside the tenant the verified credential names,
	// never the one the caller passed alongside it. That is the difference
	// between authority a runtime was granted and authority it was told it had.
	subject := verified.Binding
	definition, resolveErr := c.definitions.Resolve(string(task.Definition.DefinitionId), string(task.Definition.DefinitionDigest))
	if resolveErr != nil {
		return c.answer(binding, task, failedStatus, "RUNTIME_INTERNAL_ERROR", schema.AgentRuntimeResultTurnDecision{}, planning.Result{}, dispatchedAt)
	}
	c.lock.Lock()
	compiled, present := c.disclosures[string(task.PhysicalAttemptId)]
	c.lock.Unlock()
	if !present {
		return c.answer(binding, task, failedStatus, "RUNTIME_INTERNAL_ERROR", schema.AgentRuntimeResultTurnDecision{}, planning.Result{}, dispatchedAt)
	}
	selection, err := c.selector.Select(ctx, subject.WorkspaceID, definition.ModelPolicy)
	if err != nil {
		return c.answer(binding, task, failedStatus, "RUNTIME_MODEL_UNAVAILABLE", schema.AgentRuntimeResultTurnDecision{}, planning.Result{}, dispatchedAt)
	}
	engine, err := planning.New(c.invoker, maximumPlanSteps, c.repairsFor(definition))
	if err != nil {
		return runtimes.DispatchReceipt{}, err
	}
	limits := task.Limits
	budget, err := runtimes.TaskAllowanceBudget(task, selection)
	if err != nil {
		return c.answer(binding, task, failedStatus, "RUNTIME_BUDGET_EXHAUSTED", schema.AgentRuntimeResultTurnDecision{}, planning.Result{}, dispatchedAt)
	}
	planned, planErr := engine.Plan(ctx, modelgateway.InvokeRequest{
		RunID:       string(task.RunId),
		WorkspaceID: subject.WorkspaceID,
		ProjectID:   subject.ProjectID,
		// The provider identity is the logical task's, not the attempt's: a
		// replacement execution of the same work must reproduce the same
		// provider call rather than buy a second one.
		IdempotencyKey:      task.Idempotency.Key,
		Selection:           selection,
		Context:             compiled,
		DataClasses:         []modelgateway.DataClass{"public", "internal"},
		MaximumOutputBytes:  limits.OutputBytes,
		MaximumInputTokens:  int64(limits.OutputBytes),
		MaximumOutputTokens: int64(limits.OutputBytes),
		MaximumTotalTokens:  int64(limits.OutputBytes) * 2,
		MaximumCostMicros:   selection.MaximumCostMicros,
		Timeout:             time.Duration(limits.TimeoutMilliseconds) * time.Millisecond,
		MaximumAttempts:     maximumTransportAttempts,
		RetryBudget:         time.Duration(limits.TimeoutMilliseconds) * time.Millisecond,
		Scenario:            "agent-turn",
		Budget:              budget,
	}, budget)
	if planErr != nil {
		status, reason := planOutcome(planErr)
		return c.answer(binding, task, status, reason, schema.AgentRuntimeResultTurnDecision{}, planned, dispatchedAt)
	}
	decision, reason := c.decide(planned.Plan)
	if reason != "" {
		return c.answer(binding, task, refusedStatus, reason, schema.AgentRuntimeResultTurnDecision{
			Decision:        schema.AgentRuntimeResultTurnDecisionDecisionRefuse,
			Payload:         schema.SharedPrimitivesBoundedStringMap{"reason": reason},
			ArtifactOutputs: []schema.SharedPrimitivesArtifactReference{},
		}, planned, dispatchedAt)
	}
	return c.answer(binding, task, completedStatus, "RUNTIME_COMPLETED", decision, planned, dispatchedAt)
}

// repairsFor is how many typed-plan repairs this turn may make: what the
// definition pins, bounded by what the deployment allows. A definition whose
// repair policy rejects repair gets none.
func (c *Runtime) repairsFor(definition agent.Definition) int {
	if definition.RepairPolicy.Mode == "reject" {
		return 0
	}
	repairs := definition.RepairPolicy.MaximumAttempts
	if repairs > c.repairs {
		repairs = c.repairs
	}
	if repairs < 0 {
		return 0
	}
	return repairs
}

// Cancel is not offered: this stand-in answers synchronously, so there is no
// execution left to stop by the time a cancellation could arrive.
func (c *Runtime) Cancel(_ context.Context, binding agent.RuntimeBinding, _ string) (runtimes.CancelReceipt, error) {
	return runtimes.CancelReceipt{}, runtimes.CancellationNotOfferedError{RuntimeUnitID: binding.RuntimeUnitID}
}

// CheckCompatibility reports the binding back unchanged. There is no released
// image to interrogate: this runtime is whatever release the task names, which
// is precisely why it may not be composed in production.
func (c *Runtime) CheckCompatibility(_ context.Context, binding agent.RuntimeBinding) (runtimes.CompatibilityResult, error) {
	return runtimes.CompatibilityResult{Compatible: true, Observed: binding, ObservedAt: c.now().UTC()}, nil
}

const (
	completedStatus          = "completed"
	refusedStatus            = "refused"
	failedStatus             = "failed"
	maximumPlanSteps         = 8
	maximumTransportAttempts = 3
)

// The reserved plan tool names map a typed plan onto the governed decision
// vocabulary. Any other agent.* name is invalid; any non-reserved name is a
// tool call proposal, which the control plane then holds to the definition's
// pinned tool profile.
const (
	planContinue  = "agent.continue"
	planNeedInput = "agent.need-input"
	planDelegate  = "agent.delegate"
	planFinal     = "agent.final"
	planRefuse    = "agent.refuse"
)

// decide maps the first validated plan step onto the canonical decision. It
// returns a governed refusal reason when the plan proposes something outside
// the vocabulary; the definition's own constraints are the control plane's to
// enforce, and are deliberately not re-implemented here.
func (c *Runtime) decide(plan planning.Plan) (schema.AgentRuntimeResultTurnDecision, string) {
	if len(plan.Steps) == 0 {
		return schema.AgentRuntimeResultTurnDecision{}, "RUNTIME_REFUSED_BY_GUARDRAIL"
	}
	first := plan.Steps[0]
	payload := schema.SharedPrimitivesBoundedStringMap{}
	outputs := []schema.SharedPrimitivesArtifactReference{}
	switch first.Tool {
	case planContinue:
		payload["note"] = stringArgument(first.Arguments, "note")
		return decisionOf(schema.AgentRuntimeResultTurnDecisionDecisionContinue, payload, outputs), ""
	case planNeedInput:
		payload["question"] = stringArgument(first.Arguments, "question")
		return decisionOf(schema.AgentRuntimeResultTurnDecisionDecisionNeedInput, payload, outputs), ""
	case planDelegate:
		payload["delegate"] = stringArgument(first.Arguments, "delegate")
		if input, present := first.Arguments["input"]; present {
			payload["input"] = string(input)
		}
		return decisionOf(schema.AgentRuntimeResultTurnDecisionDecisionDelegateAgent, payload, outputs), ""
	case planFinal:
		candidate, present := first.Arguments["candidate"]
		if !present {
			return schema.AgentRuntimeResultTurnDecision{}, "RUNTIME_REFUSED_BY_GUARDRAIL"
		}
		payload["summary"] = stringArgument(first.Arguments, "summary")
		// The candidate is written before it is named. A reference to a
		// document that was never stored is what makes a final decision
		// unverifiable, and it is the one thing a real unit's artifact write
		// establishes that a payload value never could.
		return decisionOf(schema.AgentRuntimeResultTurnDecisionDecisionFinal, payload, []schema.SharedPrimitivesArtifactReference{c.store(candidate)}), ""
	case planRefuse:
		payload["reason"] = stringArgument(first.Arguments, "reason")
		return decisionOf(schema.AgentRuntimeResultTurnDecisionDecisionRefuse, payload, outputs), ""
	default:
		if strings.HasPrefix(first.Tool, "agent.") {
			return schema.AgentRuntimeResultTurnDecision{}, "RUNTIME_REFUSED_BY_GUARDRAIL"
		}
		arguments, err := json.Marshal(first.Arguments)
		if err != nil {
			return schema.AgentRuntimeResultTurnDecision{}, "RUNTIME_INTERNAL_ERROR"
		}
		payload["tool"] = first.Tool
		payload["arguments"] = string(arguments)
		return decisionOf(schema.AgentRuntimeResultTurnDecisionDecisionToolCall, payload, outputs), ""
	}
}

func decisionOf(kind schema.AgentRuntimeResultTurnDecisionDecision, payload schema.SharedPrimitivesBoundedStringMap, outputs []schema.SharedPrimitivesArtifactReference) schema.AgentRuntimeResultTurnDecision {
	return schema.AgentRuntimeResultTurnDecision{Decision: kind, Payload: payload, ArtifactOutputs: outputs}
}

// store records a produced document and returns the immutable reference to it.
func (c *Runtime) store(content []byte) schema.SharedPrimitivesArtifactReference {
	sum := sha256.Sum256(content)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	c.lock.Lock()
	c.candidates[digest] = append([]byte(nil), content...)
	c.lock.Unlock()
	return schema.SharedPrimitivesArtifactReference{
		ArtifactId: schema.SharedPrimitivesOpaqueId("artifact." + hex.EncodeToString(sum[:16])),
		Digest:     schema.SharedPrimitivesDigest(digest),
		MediaType:  "application/json",
		SizeBytes:  len(content),
	}
}

// answer assembles and signs the canonical result. Every identity field is
// copied from the task rather than remembered, because the only attempt this
// runtime may answer for is the one it was handed.
func (c *Runtime) answer(binding agent.RuntimeBinding, task schema.AgentTask, status, reason string, decision schema.AgentRuntimeResultTurnDecision, planned planning.Result, dispatchedAt time.Time) (runtimes.DispatchReceipt, error) {
	if decision.Payload == nil {
		decision = decisionOf(schema.AgentRuntimeResultTurnDecisionDecisionRefuse,
			schema.SharedPrimitivesBoundedStringMap{"reason": reason},
			[]schema.SharedPrimitivesArtifactReference{})
	}
	observedAt := c.now().UTC()
	usage := usageOf(planned, observedAt.Sub(dispatchedAt))
	result := schema.AgentRuntimeResult{
		Kind:                "AgentRuntimeResult",
		TaskId:              task.TaskId,
		RunId:               task.RunId,
		RootRunId:           task.RootRunId,
		PhysicalAttemptId:   task.PhysicalAttemptId,
		AttemptNumber:       task.AttemptNumber,
		ExecutionGeneration: task.ExecutionGeneration,
		LeaseEpoch:          task.LeaseEpoch,
		FenceToken:          task.FenceToken,
		Selected: schema.AgentRuntimeResultSelected{
			RuntimeUnitId:            schema.SharedPrimitivesOpaqueId(binding.RuntimeUnitID),
			DefinitionDigest:         task.Definition.DefinitionDigest,
			RuntimeManifestDigest:    schema.SharedPrimitivesDigest(binding.RuntimeManifestDigest),
			InvocationProtocolDigest: schema.SharedPrimitivesDigest(binding.InvocationProtocolDigest),
			ImageDigest:              schema.SharedPrimitivesDigest(binding.RuntimeImageDigest),
		},
		Status:       schema.AgentRuntimeResultStatus{Status: schema.AgentRuntimeResultStatusStatus(status), ReasonCode: reason},
		TurnDecision: decision,
		Usage:        usage,
		Diagnostics:  []schema.AgentRuntimeResultDiagnosticsElem{},
		TraceContext: task.TraceContext,
	}
	statement, err := runtimes.StatementBytes(result)
	if err != nil {
		return runtimes.DispatchReceipt{}, err
	}
	algorithm, keyID, signature, err := c.signer.Sign(statement)
	if err != nil {
		return runtimes.DispatchReceipt{}, err
	}
	sum := sha256.Sum256(statement)
	result.Signature = schema.AgentRuntimeResultSignature{
		Algorithm:       schema.AgentRuntimeResultSignatureAlgorithm(algorithm),
		KeyId:           keyID,
		Signature:       signature,
		StatementDigest: schema.SharedPrimitivesDigest("sha256:" + hex.EncodeToString(sum[:])),
		// The provenance of a stand-in is the release it is standing in for.
		// It is the manifest digest and not an image attestation, because
		// there is no image: what produced this result is this process.
		ProvenanceReference: schema.SharedPrimitivesDigest(binding.RuntimeManifestDigest),
	}
	return runtimes.DispatchReceipt{Release: binding, Result: result, DispatchedAt: dispatchedAt, ObservedAt: observedAt}, nil
}

// admit is the boundary a released unit enforces on its own side. Every check
// here is one the canonical task states, so a task this stand-in accepts is
// one a real unit would also accept.
//
// The credential is verified, not read. The port carries the claims for the
// convenience of a caller that already holds them, but an admission that
// believed those claims would be proving nothing about the token — and it is
// the token, not the struct beside it, that a released unit is handed.
func (c *Runtime) admit(binding agent.RuntimeBinding, task schema.AgentTask, credential runtimes.Credential, now time.Time) (runtimes.VerifiedCredential, error) {
	switch {
	case credential.Value == "":
		return runtimes.VerifiedCredential{}, refusedDispatch("a task-scoped credential is required")
	case task.AuthorizationAudience != binding.RuntimeAudience:
		return runtimes.VerifiedCredential{}, refusedDispatch("the task must name the audience of the release executing it")
	case string(task.RuntimeBinding.RuntimeUnitId) != binding.RuntimeUnitID ||
		string(task.RuntimeBinding.RuntimeManifestDigest) != binding.RuntimeManifestDigest ||
		string(task.RuntimeBinding.RuntimeImageDigest) != binding.RuntimeImageDigest ||
		string(task.RuntimeBinding.InvocationProtocolDigest) != binding.InvocationProtocolDigest:
		return runtimes.VerifiedCredential{}, refusedDispatch("the task is bound to a different runtime release")
	case !now.Before(time.Time(task.ExpiresAt)):
		return runtimes.VerifiedCredential{}, refusedDispatch("the task expired before it was admitted")
	case task.FenceToken == "" || task.AttemptNumber < 1 || task.LeaseEpoch < 1:
		return runtimes.VerifiedCredential{}, refusedDispatch("the task carries no executable attempt identity")
	}
	// The audience a credential is admitted against is the release's own, never
	// the one the presented document asserts: a verifier that took the audience
	// from the token would accept every token for the audience it named itself.
	verified, err := c.credentials.Verify(credential.Value, binding.RuntimeAudience, now)
	if err != nil {
		return runtimes.VerifiedCredential{}, refusedDispatch("the task-scoped credential is not verifiable")
	}
	if mismatch := runtimes.BindsTask(verified, task, runtimes.OperationExecute); mismatch != "" {
		return runtimes.VerifiedCredential{}, refusedDispatch(mismatch)
	}
	return verified, nil
}

func refusedDispatch(detail string) error {
	details := problem.New(problem.CodeTaskDispatchDenied, "")
	details.Detail = detail
	return details
}

// planOutcome maps a planning failure onto the governed status and reason.
//
// The distinction matters to the control plane. A plan that never validated is
// a refusal — the turn has an answer, and repeating it would produce the same
// one — while an unavailable model or an internal fault is a failure, which the
// workflow may retry. A budget stop is reported as a failure with the budget
// reason, which the control plane turns into a halt rather than a retry.
func planOutcome(err error) (string, string) {
	var details problem.Details
	if !errors.As(err, &details) {
		return failedStatus, "RUNTIME_INTERNAL_ERROR"
	}
	switch problem.Code(details.Code) {
	case problem.CodeBudgetDenied:
		return failedStatus, "RUNTIME_BUDGET_EXHAUSTED"
	case problem.CodeNoEligibleProvider, problem.CodeProviderUnavailable:
		return failedStatus, "RUNTIME_MODEL_UNAVAILABLE"
	case problem.CodeContractInvalid, problem.CodeValidationUnavailable:
		return refusedStatus, "RUNTIME_REFUSED_BY_GUARDRAIL"
	default:
		return failedStatus, "RUNTIME_INTERNAL_ERROR"
	}
}

// usageOf accounts every physical provider attempt the turn caused, not one
// call per planning attempt: a planning attempt that took three transport
// retries billed three provider calls and is reported as three.
func usageOf(planned planning.Result, elapsed time.Duration) schema.AgentRuntimeResultUsage {
	usage := schema.AgentRuntimeResultUsage{Cost: schema.SharedPrimitivesCost{Amount: "0", Currency: "USD"}}
	var micros int64
	for _, attempt := range planned.Attempts {
		usage.ModelCalls += len(attempt.Invocation.PhysicalAttempts)
		usage.InputTokens += int(attempt.Invocation.InputTokens)
		usage.OutputTokens += int(attempt.Invocation.OutputTokens)
		micros += attempt.Invocation.CostMicros
	}
	usage.Cost.Amount = schema.SharedPrimitivesDecimalString(decimalOf(micros))
	if elapsed > 0 {
		usage.DurationMilliseconds = int(elapsed / time.Millisecond)
	}
	return usage
}

// decimalOf renders micros as the governed decimal string. The wire carries a
// decimal because currency is not an integer count of anything; the service
// accounts in micros because a decimal is not a safe accumulator.
func decimalOf(micros int64) string {
	if micros < 0 {
		micros = 0
	}
	whole := micros / 1_000_000
	fraction := micros % 1_000_000
	if fraction == 0 {
		return strconv.FormatInt(whole, 10)
	}
	rendered := fmt.Sprintf("%06d", fraction)
	return strconv.FormatInt(whole, 10) + "." + strings.TrimRight(rendered, "0")
}

func stringArgument(arguments map[string]json.RawMessage, key string) string {
	raw, present := arguments[key]
	if !present {
		return ""
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return ""
	}
	return value
}

// SeededSigner signs results with an Ed25519 key derived from the
// deployment's own signing material.
//
// A result nobody signed cannot be attributed to what produced it, so this
// stand-in signs like a release does. The key is derived rather than mounted
// because there is no release to mount one for.
type SeededSigner struct {
	key   ed25519.PrivateKey
	keyID string
}

// NewSeededSigner derives the signing key from the given material.
func NewSeededSigner(material, keyID string) (*SeededSigner, error) {
	if len(material) < 16 {
		return nil, fmt.Errorf("controlled result signer: signing material of at least 16 characters is required")
	}
	if !runtimes.ValidKeyIdentity(keyID) {
		return nil, fmt.Errorf("controlled result signer: a governed urn:anvilkit:key identity is required")
	}
	seed := sha256.Sum256([]byte("anvilkit/controlled-runtime-result\x00" + material))
	return &SeededSigner{key: ed25519.NewKeyFromSeed(seed[:]), keyID: keyID}, nil
}

// Sign produces the DSSE pre-authenticated signature over the statement, in
// the same encoding a released unit uses, so a verifier written against one
// works against the other.
func (s *SeededSigner) Sign(statement []byte) (string, string, string, error) {
	prefix := fmt.Sprintf("DSSEv1 %d %s %d ", len(runtimes.StatementPayloadType), runtimes.StatementPayloadType, len(statement))
	signature := ed25519.Sign(s.key, append([]byte(prefix), statement...))
	return "dsse-ed25519-v1", s.keyID, base64.RawURLEncoding.EncodeToString(signature), nil
}

// PublicKey exposes the verification key, so the trust store a verifier reads
// can be built from the same material this signer derived from.
func (s *SeededSigner) PublicKey() ed25519.PublicKey {
	return s.key.Public().(ed25519.PublicKey)
}
