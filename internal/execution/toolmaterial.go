package execution

import (
	"fmt"

	"github.com/ancyloce/anvilkit-agent-service/internal/agent"
	"github.com/ancyloce/anvilkit-agent-service/internal/tools"
)

// ToolMaterialSet is the Tool material the process is actually running: the
// digest-pinned argument schemas it compiled and the complete ToolDefinitions
// the running profile dispatches. A run's frozen tool profile is checked
// against both, because the argument-schema digest alone says nothing about
// the capability, side effects, risk, approval requirement, timeout, or retry
// policy the dispatch would carry.
type ToolMaterialSet struct {
	arguments   *PinnedToolArgumentValidator
	definitions map[string]tools.Definition
}

// NewToolMaterial binds the running tool profile to the compiled argument
// schemas. Every tool in the profile must have a pinned argument schema, and
// every definition must be complete: material that cannot be described is
// never treated as approved.
func NewToolMaterial(profile tools.Profile, arguments *PinnedToolArgumentValidator) (*ToolMaterialSet, error) {
	if arguments == nil {
		return nil, fmt.Errorf("tool material: the pinned argument validator is required")
	}
	if len(profile.Definitions) == 0 {
		return nil, fmt.Errorf("tool material: the running tool profile is empty")
	}
	set := &ToolMaterialSet{arguments: arguments, definitions: make(map[string]tools.Definition, len(profile.Definitions))}
	for _, definition := range profile.Definitions {
		if definition.ToolID == "" {
			return nil, fmt.Errorf("tool material: the running profile carries a tool without identity")
		}
		if _, known := arguments.ComponentDigest(definition.ToolID); !known {
			return nil, fmt.Errorf("tool material: %s has no pinned argument schema in this process", definition.ToolID)
		}
		set.definitions[definition.ToolID] = definition
	}
	return set, nil
}

// ComponentDigest returns the digest of the argument schema this process runs
// for one Tool component.
func (m *ToolMaterialSet) ComponentDigest(componentName string) (string, bool) {
	return m.arguments.ComponentDigest(componentName)
}

// ToolDefinition returns the complete definition this process would dispatch
// for one Tool component.
func (m *ToolMaterialSet) ToolDefinition(componentName string) (tools.Definition, bool) {
	definition, known := m.definitions[componentName]
	return definition, known
}

// matchesBinding reports whether one running definition is byte-for-byte the
// definition the approved catalog signed. Every field a dispatch decision
// depends on is compared; a difference in any of them is running material
// that the catalog never approved.
func matchesBinding(definition tools.Definition, binding agent.ToolBinding) bool {
	return definition.ToolID == binding.ToolID &&
		definition.Capability == binding.Capability &&
		definition.SideEffectClass == binding.SideEffectClass &&
		definition.RiskClass == binding.RiskClass &&
		definition.ApprovalPolicy.PolicyID == binding.ApprovalPolicy.PolicyID &&
		definition.ApprovalPolicy.Version == binding.ApprovalPolicy.Version &&
		definition.ApprovalPolicy.Digest == binding.ApprovalPolicy.Digest &&
		definition.TimeoutPolicy.TimeoutMilliseconds == binding.TimeoutMilliseconds &&
		definition.RetryPolicy.MaximumAttempts == binding.MaximumAttempts &&
		definition.RetryPolicy.BackoffMilliseconds == binding.BackoffMilliseconds &&
		equalStrings(definition.RetryPolicy.Retryability, binding.Retryability) &&
		equalStrings(definition.AcceptedDataClasses, binding.AcceptedDataClasses)
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

var _ ToolMaterial = (*ToolMaterialSet)(nil)
