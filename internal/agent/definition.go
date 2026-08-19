package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"github.com/ancyloce/anvilkit-agent-service/internal/canonical"
)

// Role is the frozen AgentDefinition role vocabulary.
type Role string

const (
	RoleManager    Role = "manager"
	RoleSpecialist Role = "specialist"
)

// SchemaReference mirrors the canonical shared primitive: a pinned schema
// component identity plus its content digest.
type SchemaReference struct {
	ComponentName string `json:"componentName"`
	Digest        string `json:"digest"`
}

// PolicyReference mirrors the canonical shared primitive.
type PolicyReference struct {
	PolicyID string `json:"policyId"`
	Version  string `json:"version"`
	Digest   string `json:"digest"`
}

type ToolProfile struct {
	Tools                []SchemaReference `json:"tools"`
	MaximumParallelTools int               `json:"maximumParallelTools"`
}

type RepairPolicy struct {
	MaximumAttempts int    `json:"maximumAttempts"`
	Mode            string `json:"mode"`
}

// Definition is the typed canonical AgentDefinition. It is immutable by
// (definitionId, definitionDigest); Raw preserves the exact pinned document.
type Definition struct {
	Kind                   string            `json:"kind"`
	Role                   Role              `json:"role"`
	Owner                  string            `json:"owner"`
	Domain                 string            `json:"domain"`
	PromptDigest           string            `json:"promptDigest"`
	InputSchema            SchemaReference   `json:"inputSchema"`
	OutputSchema           SchemaReference   `json:"outputSchema"`
	ToolProfile            ToolProfile       `json:"toolProfile"`
	ModelPolicy            PolicyReference   `json:"modelPolicy"`
	MemoryPolicy           PolicyReference   `json:"memoryPolicy"`
	GuardrailPolicy        PolicyReference   `json:"guardrailPolicy"`
	RepairPolicy           RepairPolicy      `json:"repairPolicy"`
	AllowedDelegates       []string          `json:"allowedDelegates"`
	MaximumDelegationDepth int               `json:"maximumDelegationDepth"`
	MaximumFanOut          int               `json:"maximumFanOut"`
	TurnLimit              int               `json:"turnLimit"`
	StopConditions         []string          `json:"stopConditions"`
	Evaluators             []SchemaReference `json:"evaluators"`
	DefinitionID           string            `json:"definitionId"`
	DefinitionDigest       string            `json:"definitionDigest"`

	Raw json.RawMessage `json:"-"`
}

// DefinitionReference is the pinned reference carried by an AgentRun.
type DefinitionReference struct {
	DefinitionID     string `json:"definitionId"`
	DefinitionDigest string `json:"definitionDigest"`
}

func ParseDefinitionReference(raw []byte) (DefinitionReference, error) {
	var reference DefinitionReference
	if err := strictDecode(raw, &reference); err != nil {
		return DefinitionReference{}, fmt.Errorf("definition reference: %w", err)
	}
	if !validComponentID(reference.DefinitionID) || !validDigest(reference.DefinitionDigest) {
		return DefinitionReference{}, fmt.Errorf("definition reference: bounded identity and digest are required")
	}
	return reference, nil
}

const maximumDefinitionBytes = 65536

// ParseDefinition strictly decodes one canonical AgentDefinition document and
// enforces every structural bound the canonical schema freezes.
func ParseDefinition(raw []byte) (Definition, error) {
	if len(raw) == 0 || len(raw) > maximumDefinitionBytes {
		return Definition{}, fmt.Errorf("agent definition: document exceeds the bounded contract")
	}
	var definition Definition
	if err := strictDecode(raw, &definition); err != nil {
		return Definition{}, fmt.Errorf("agent definition: %w", err)
	}
	definition.Raw = append(json.RawMessage(nil), raw...)
	if err := definition.validate(); err != nil {
		return Definition{}, err
	}
	return definition, nil
}

func (d Definition) validate() error {
	if d.Kind != "AgentDefinition" {
		return fmt.Errorf("agent definition: kind must be AgentDefinition")
	}
	if d.Role != RoleManager && d.Role != RoleSpecialist {
		return fmt.Errorf("agent definition: role must be manager or specialist")
	}
	if len(d.Owner) < 3 || len(d.Owner) > 128 {
		return fmt.Errorf("agent definition: accountable owner is required")
	}
	switch d.Domain {
	case "platform-agent", "pagix-page", "contract-runtime":
	default:
		return fmt.Errorf("agent definition: domain %q is outside the frozen vocabulary", d.Domain)
	}
	if !validDigest(d.PromptDigest) {
		return fmt.Errorf("agent definition: instruction digest is required")
	}
	for _, reference := range append([]SchemaReference{d.InputSchema, d.OutputSchema}, d.ToolProfile.Tools...) {
		if !validSchemaReference(reference) {
			return fmt.Errorf("agent definition: schema references require component name and digest")
		}
	}
	if len(d.ToolProfile.Tools) > 64 || d.ToolProfile.MaximumParallelTools < 1 || d.ToolProfile.MaximumParallelTools > 64 {
		return fmt.Errorf("agent definition: tool profile bounds are invalid")
	}
	for _, policy := range []PolicyReference{d.ModelPolicy, d.MemoryPolicy, d.GuardrailPolicy} {
		if !validPolicyReference(policy) {
			return fmt.Errorf("agent definition: policy references require identity, version, and digest")
		}
	}
	if d.RepairPolicy.MaximumAttempts < 0 || d.RepairPolicy.MaximumAttempts > 8 {
		return fmt.Errorf("agent definition: repair attempts are outside the frozen bound")
	}
	if d.RepairPolicy.Mode != "reject" && d.RepairPolicy.Mode != "bounded-repair" {
		return fmt.Errorf("agent definition: repair mode is outside the frozen vocabulary")
	}
	if len(d.AllowedDelegates) > 16 {
		return fmt.Errorf("agent definition: allowed delegates exceed the frozen bound")
	}
	seenDelegates := make(map[string]struct{}, len(d.AllowedDelegates))
	for _, delegate := range d.AllowedDelegates {
		if !validComponentID(delegate) {
			return fmt.Errorf("agent definition: delegate identity is invalid")
		}
		if _, duplicate := seenDelegates[delegate]; duplicate {
			return fmt.Errorf("agent definition: delegate identities must be unique")
		}
		seenDelegates[delegate] = struct{}{}
	}
	if d.MaximumDelegationDepth < 0 || d.MaximumDelegationDepth > 8 {
		return fmt.Errorf("agent definition: delegation depth is outside the frozen bound")
	}
	if d.MaximumFanOut < 0 || d.MaximumFanOut > 64 {
		return fmt.Errorf("agent definition: fan-out is outside the frozen bound")
	}
	if len(d.AllowedDelegates) > 0 && (d.MaximumDelegationDepth < 1 || d.MaximumFanOut < 1) {
		return fmt.Errorf("agent definition: delegates require positive depth and fan-out")
	}
	if d.TurnLimit < 1 || d.TurnLimit > 1024 {
		return fmt.Errorf("agent definition: turn limit is outside the frozen bound")
	}
	if len(d.StopConditions) < 1 || len(d.StopConditions) > 16 {
		return fmt.Errorf("agent definition: stop conditions are required and bounded")
	}
	seenStops := make(map[string]struct{}, len(d.StopConditions))
	for _, stop := range d.StopConditions {
		switch stop {
		case "completed", "refused", "budget-exhausted", "approval-required", "input-required", "policy-blocked":
		default:
			return fmt.Errorf("agent definition: stop condition %q is outside the frozen vocabulary", stop)
		}
		if _, duplicate := seenStops[stop]; duplicate {
			return fmt.Errorf("agent definition: stop conditions must be unique")
		}
		seenStops[stop] = struct{}{}
	}
	if len(d.Evaluators) > 32 {
		return fmt.Errorf("agent definition: evaluators exceed the frozen bound")
	}
	if !validComponentID(d.DefinitionID) {
		return fmt.Errorf("agent definition: definition identity is required")
	}
	if !validDigest(d.DefinitionDigest) {
		return fmt.Errorf("agent definition: definition digest is required")
	}
	return nil
}

// IdentityDigest recomputes the canonical digest over the frozen identity
// fields: every document field except kind and definitionDigest. A stored
// definitionDigest that does not match this value is rejected.
func (d Definition) IdentityDigest() (string, error) {
	var document map[string]json.RawMessage
	if err := json.Unmarshal(d.Raw, &document); err != nil {
		return "", fmt.Errorf("agent definition identity: %w", err)
	}
	delete(document, "kind")
	delete(document, "definitionDigest")
	identity, err := json.Marshal(document)
	if err != nil {
		return "", fmt.Errorf("agent definition identity: %w", err)
	}
	digest, err := canonical.Digest(identity)
	if err != nil {
		return "", fmt.Errorf("agent definition identity: %w", err)
	}
	return digest, nil
}

// AllowsDelegate reports whether the definition explicitly authorizes the
// delegate identity.
func (d Definition) AllowsDelegate(delegateID string) bool {
	for _, allowed := range d.AllowedDelegates {
		if allowed == delegateID {
			return true
		}
	}
	return false
}

// AllowsTool reports whether the tool component is in the pinned profile.
func (d Definition) AllowsTool(componentName string) bool {
	for _, tool := range d.ToolProfile.Tools {
		if tool.ComponentName == componentName {
			return true
		}
	}
	return false
}

func validSchemaReference(reference SchemaReference) bool {
	return len(reference.ComponentName) >= 8 && len(reference.ComponentName) <= 160 && validDigest(reference.Digest)
}

func validPolicyReference(reference PolicyReference) bool {
	return reference.PolicyID != "" && len(reference.PolicyID) <= 128 && reference.Version != "" && len(reference.Version) <= 64 && validDigest(reference.Digest)
}

func validDigest(value string) bool {
	if len(value) != 71 || value[:7] != "sha256:" {
		return false
	}
	for _, character := range value[7:] {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

func strictDecode(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("document must contain exactly one JSON value")
	}
	return nil
}
