// Package tools owns immutable bounded profiles and deterministic dispatch
// authorization. Model text and untrusted content are never authority inputs.
package tools

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"regexp"
	"sort"
	"strings"
	"time"
)

type ProfileID string
type PolicyReference struct {
	PolicyID string `json:"policyId"`
	Version  string `json:"version"`
	Digest   string `json:"digest"`
}
type SchemaReference struct {
	ComponentName string `json:"componentName"`
	Digest        string `json:"digest"`
}
type TimeoutPolicy struct {
	TimeoutMilliseconds int `json:"timeoutMilliseconds"`
}
type RetryPolicy struct {
	MaximumAttempts     int      `json:"maximumAttempts"`
	BackoffMilliseconds int      `json:"backoffMilliseconds"`
	Retryability        []string `json:"retryability"`
}
type Definition struct {
	Kind                string          `json:"kind"`
	Capability          string          `json:"capability"`
	InputSchema         SchemaReference `json:"inputSchema"`
	OutputSchema        SchemaReference `json:"outputSchema"`
	SideEffectClass     string          `json:"sideEffectClass"`
	RiskClass           string          `json:"riskClass"`
	ApprovalPolicy      PolicyReference `json:"approvalPolicy"`
	TimeoutPolicy       TimeoutPolicy   `json:"timeoutPolicy"`
	RetryPolicy         RetryPolicy     `json:"retryPolicy"`
	AcceptedDataClasses []string        `json:"acceptedDataClasses"`
	ToolID              string          `json:"toolId"`
}
type Profile struct {
	ID              ProfileID
	Version, Digest string
	Policy          PolicyReference
	Definitions     []Definition
}

func NewProfile(id ProfileID, version string, policy PolicyReference, definitions []Definition) (Profile, error) {
	if !opaque(string(id)) || !opaque(version) || !validPolicy(policy) || len(definitions) < 3 || len(definitions) > 7 {
		return Profile{}, fmt.Errorf("tool profile must contain 3-7 tools")
	}
	copyDefs := append([]Definition(nil), definitions...)
	sort.Slice(copyDefs, func(i, j int) bool { return copyDefs[i].ToolID < copyDefs[j].ToolID })
	seen := map[string]bool{}
	for _, definition := range copyDefs {
		if err := validateDefinition(definition); err != nil {
			return Profile{}, err
		}
		if seen[definition.ToolID] {
			return Profile{}, fmt.Errorf("duplicate tool %s", definition.ToolID)
		}
		seen[definition.ToolID] = true
	}
	raw, _ := json.Marshal(struct {
		ID          ProfileID
		Version     string
		Policy      PolicyReference
		Definitions []Definition
	}{id, version, policy, copyDefs})
	sum := sha256.Sum256(raw)
	return Profile{id, version, "sha256:" + hex.EncodeToString(sum[:]), policy, copyDefs}, nil
}
func validateDefinition(d Definition) error {
	if d.Kind != "ToolDefinition" || !opaque(d.ToolID) || !oneOf(d.Capability, "provider.invoke", "contract.validate", "artifact.scan", "fake.execute") || !validSchema(d.InputSchema) || !validSchema(d.OutputSchema) || !validPolicy(d.ApprovalPolicy) || !oneOf(d.SideEffectClass, "none", "read", "artifact-write", "domain-effect") || !oneOf(d.RiskClass, "low", "medium", "high", "critical") || d.TimeoutPolicy.TimeoutMilliseconds < 1 || d.TimeoutPolicy.TimeoutMilliseconds > 86400000 || d.RetryPolicy.MaximumAttempts < 1 || d.RetryPolicy.MaximumAttempts > 100 || d.RetryPolicy.BackoffMilliseconds < 0 || d.RetryPolicy.BackoffMilliseconds > 3600000 || d.RetryPolicy.Retryability == nil || len(d.RetryPolicy.Retryability) > 3 || len(d.AcceptedDataClasses) < 1 || len(d.AcceptedDataClasses) > 4 || !uniqueAllowed(d.AcceptedDataClasses, []string{"public", "internal", "confidential", "restricted"}) || !uniqueAllowed(d.RetryPolicy.Retryability, []string{"safe-immediate", "safe-after-backoff", "operator-action"}) {
		return fmt.Errorf("invalid ToolDefinition %s", d.ToolID)
	}
	return nil
}

type Intent struct {
	RunID, WorkspaceID, ProjectID, ActorID string
	AllowedTools                           []string
	AllowedEffects                         []string
	MaximumRisk                            string
	DataClasses                            []string
	ApprovalDecisionVersion                uint64
}
type CurrentAuthority struct {
	WorkspaceActive, ActorActive, PermissionActive, PolicyActive bool
	AllowedTools                                                 []string
	// AllowedCapabilities is the capability set the actor currently holds.
	// The signed ToolDefinition names the capability a dispatch exercises, so
	// a tool whose capability is not granted is denied even when the tool
	// identity itself is allowed.
	AllowedCapabilities     []string
	AllowedEffects          []string
	MaximumRisk             string
	DataClasses             []string
	ApprovalDecisionVersion uint64
}
type Proposal struct {
	ToolID        string
	Arguments     json.RawMessage
	UntrustedText string
}
type Decision struct {
	Allowed                      bool
	Code, Reason                 string
	ProfileDigest, PolicyVersion string
	RecordedAt                   time.Time
	// Dispatch carries the signed execution envelope of the allowed tool.
	// The caller executes inside it rather than deciding for itself how long
	// a tool may run or how often it may be attempted.
	Dispatch DispatchEnvelope
}

// DispatchEnvelope is the part of the signed ToolDefinition that governs the
// execution the guard just allowed.
type DispatchEnvelope struct {
	Capability          string
	SideEffectClass     string
	RiskClass           string
	TimeoutMilliseconds int
	MaximumAttempts     int
	BackoffMilliseconds int
	Retryability        []string
}

// RetryableImmediately reports whether the signed retry policy permits an
// immediate re-attempt of a failed dispatch.
func (e DispatchEnvelope) RetryableImmediately() bool {
	return contains(e.Retryability, "safe-immediate")
}

type Recorder interface {
	Record(context.Context, Intent, Proposal, Decision) error
}
type Clock interface{ Now() time.Time }
type ArgumentValidator interface {
	Validate(context.Context, SchemaReference, json.RawMessage) error
}
type Guard struct {
	profile   Profile
	recorder  Recorder
	clock     Clock
	validator ArgumentValidator
}

func NewGuard(profile Profile, recorder Recorder, clock Clock, validator ArgumentValidator) (*Guard, error) {
	if profile.Digest == "" || recorder == nil || clock == nil || validator == nil {
		return nil, fmt.Errorf("tool guard dependencies required")
	}
	canonical, err := NewProfile(profile.ID, profile.Version, profile.Policy, profile.Definitions)
	if err != nil || canonical.Digest != profile.Digest {
		return nil, fmt.Errorf("tool profile failed pinned digest validation")
	}
	return &Guard{profile: canonical, recorder: recorder, clock: clock, validator: validator}, nil
}
func (g *Guard) Evaluate(ctx context.Context, intent Intent, current CurrentAuthority, proposal Proposal) (Decision, error) {
	decision := Decision{ProfileDigest: g.profile.Digest, PolicyVersion: g.profile.Policy.Version, RecordedAt: g.clock.Now()}
	deny := func(code, reason string) (Decision, error) {
		decision.Code, decision.Reason = code, reason
		if err := g.recorder.Record(ctx, intent, proposal, decision); err != nil {
			return decision, err
		}
		details := problem.New(problem.CodeToolDispatchDenied, "")
		details.Detail = reason
		return decision, details
	}
	if intent.RunID == "" || intent.WorkspaceID == "" || intent.ProjectID == "" || intent.ActorID == "" {
		return deny("AUTHORITY_STALE", "original intent identity is incomplete")
	}
	if !validAuthority(intent.AllowedTools, intent.AllowedEffects, intent.MaximumRisk, intent.DataClasses) || !validAuthority(current.AllowedTools, current.AllowedEffects, current.MaximumRisk, current.DataClasses) {
		return deny("AUTHORITY_STALE", "original or current authority is malformed or unbounded")
	}
	if !current.WorkspaceActive || !current.ActorActive || !current.PermissionActive || !current.PolicyActive {
		return deny("AUTHORITY_STALE", "current authority is inactive")
	}
	definition, ok := g.definition(proposal.ToolID)
	if !ok || !contains(intent.AllowedTools, proposal.ToolID) || !contains(current.AllowedTools, proposal.ToolID) {
		return deny("TOOL_OUTSIDE_PROFILE", "tool is not in the pinned authorized profile")
	}
	if !contains(intent.AllowedEffects, definition.SideEffectClass) || !contains(current.AllowedEffects, definition.SideEffectClass) {
		return deny("SIDE_EFFECT_DENIED", "side effect class is not authorized")
	}
	if risk(definition.RiskClass) > risk(intent.MaximumRisk) || risk(definition.RiskClass) > risk(current.MaximumRisk) {
		return deny("RISK_DENIED", "risk exceeds current authority")
	}
	// The capability is part of the signed ToolDefinition, so it is authorized
	// like every other part of it: holding the tool identity is not holding
	// the capability the tool exercises.
	if definition.Capability == "" || !contains(current.AllowedCapabilities, definition.Capability) {
		return deny("CAPABILITY_DENIED", "the signed tool capability is not granted by current authority")
	}
	if !allContained(intent.DataClasses, definition.AcceptedDataClasses) || !allContained(intent.DataClasses, current.DataClasses) {
		return deny("DATA_CLASS_DENIED", "data class is not accepted")
	}
	if definition.SideEffectClass == "domain-effect" && (intent.ApprovalDecisionVersion == 0 || current.ApprovalDecisionVersion != intent.ApprovalDecisionVersion) {
		return deny("APPROVAL_REQUIRED", "current approval does not bind the proposal")
	}
	if err := g.validator.Validate(ctx, definition.InputSchema, proposal.Arguments); err != nil {
		return deny("ARGUMENT_SCHEMA_INVALID", "tool arguments violate the declared input schema")
	}
	if definition.TimeoutPolicy.TimeoutMilliseconds < 1 || definition.RetryPolicy.MaximumAttempts < 1 {
		return deny("DISPATCH_ENVELOPE_INVALID", "the signed tool timeout and retry policy do not bound a dispatch")
	}
	decision.Allowed = true
	decision.Code = "ALLOWED"
	decision.Dispatch = DispatchEnvelope{
		Capability:          definition.Capability,
		SideEffectClass:     definition.SideEffectClass,
		RiskClass:           definition.RiskClass,
		TimeoutMilliseconds: definition.TimeoutPolicy.TimeoutMilliseconds,
		MaximumAttempts:     definition.RetryPolicy.MaximumAttempts,
		BackoffMilliseconds: definition.RetryPolicy.BackoffMilliseconds,
		Retryability:        append([]string(nil), definition.RetryPolicy.Retryability...),
	}
	if err := g.recorder.Record(ctx, intent, proposal, decision); err != nil {
		return decision, err
	}
	return decision, nil
}
func (g *Guard) definition(id string) (Definition, bool) {
	for _, definition := range g.profile.Definitions {
		if definition.ToolID == id {
			return definition, true
		}
	}
	return Definition{}, false
}
func (g *Guard) Profile() Profile { return cloneProfile(g.profile) }
func cloneProfile(value Profile) Profile {
	raw, _ := json.Marshal(value)
	var result Profile
	_ = json.Unmarshal(raw, &result)
	result.ID, result.Version, result.Digest = value.ID, value.Version, value.Digest
	return result
}
func oneOf(value string, values ...string) bool { return contains(values, value) }
func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
func allContained(required, available []string) bool {
	for _, value := range required {
		if !contains(available, value) {
			return false
		}
	}
	return true
}
func risk(value string) int {
	switch strings.ToLower(value) {
	case "low":
		return 1
	case "medium":
		return 2
	case "high":
		return 3
	case "critical":
		return 4
	default:
		return 99
	}
}
func validSchema(value SchemaReference) bool {
	return regexp.MustCompile(`^anvilkit\.[a-z0-9][a-z0-9.-]*$`).MatchString(value.ComponentName) && !regexp.MustCompile(`\.v[0-9]+$`).MatchString(value.ComponentName) && validDigest(value.Digest)
}
func validPolicy(value PolicyReference) bool {
	return opaque(value.PolicyID) && opaque(value.Version) && validDigest(value.Digest)
}
func opaque(value string) bool {
	return regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`).MatchString(value)
}
func validDigest(value string) bool {
	return regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(value)
}
func uniqueAllowed(values, allowed []string) bool {
	seen := map[string]bool{}
	for _, value := range values {
		if seen[value] || !contains(allowed, value) {
			return false
		}
		seen[value] = true
	}
	return true
}

func validAuthority(toolIDs, effects []string, maximumRisk string, dataClasses []string) bool {
	if len(toolIDs) < 1 || len(toolIDs) > 7 || len(effects) < 1 || len(effects) > 4 || risk(maximumRisk) == 99 || len(dataClasses) < 1 || len(dataClasses) > 4 {
		return false
	}
	if !uniqueAllowed(effects, []string{"none", "read", "artifact-write", "domain-effect"}) || !uniqueAllowed(dataClasses, []string{"public", "internal", "confidential", "restricted"}) {
		return false
	}
	seen := map[string]bool{}
	for _, toolID := range toolIDs {
		if !opaque(toolID) || seen[toolID] {
			return false
		}
		seen[toolID] = true
	}
	return true
}
