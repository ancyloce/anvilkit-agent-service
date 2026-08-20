package agent

import (
	"encoding/json"
	"fmt"
)

// ModelPolicyRules is the attested provider-eligibility policy an
// AgentDefinition pins through its modelPolicy reference. It is the authority
// for which providers a run may disclose context to: residency, data classes,
// retention, training, safety floor, cost ceiling, and the required provider
// capability all come from the signed document, never from a value declared
// beside the selection code.
type ModelPolicyRules struct {
	ProviderClass      string   `json:"providerClass"`
	MaximumRiskClass   string   `json:"maximumRiskClass"`
	AllowedDataClasses []string `json:"allowedDataClasses"`
	// AllowedProviders restricts selection to named provider identities.
	// It is optional: an empty set states no identity restriction, and every
	// other axis of the policy still applies.
	AllowedProviders  []string `json:"allowedProviders,omitempty"`
	AllowedRegions    []string `json:"allowedRegions"`
	Capability        string   `json:"capability"`
	AllowRetention    bool     `json:"allowRetention"`
	AllowTraining     bool     `json:"allowTraining"`
	MinimumSafety     int      `json:"minimumSafety"`
	MaximumCostMicros int64    `json:"maximumCostMicros"`
}

// ModelPolicy is one approved signed model policy: its identity, the digest
// the catalog approves it at, and the rules it states.
type ModelPolicy struct {
	PolicyID string
	Version  string
	Digest   string
	Rules    ModelPolicyRules
}

// Clone returns an independent copy so approved policy material cannot be
// mutated through a returned value.
func (p ModelPolicy) Clone() ModelPolicy {
	p.Rules.AllowedDataClasses = append([]string(nil), p.Rules.AllowedDataClasses...)
	p.Rules.AllowedProviders = append([]string(nil), p.Rules.AllowedProviders...)
	p.Rules.AllowedRegions = append([]string(nil), p.Rules.AllowedRegions...)
	return p
}

// parseModelPolicyRules strictly decodes and bounds one model policy rule set.
// An unbounded or incomplete policy is refused rather than treated as
// permissive: a policy that states nothing must not select everything.
func parseModelPolicyRules(raw json.RawMessage) (ModelPolicyRules, error) {
	var rules ModelPolicyRules
	if len(raw) == 0 {
		return ModelPolicyRules{}, fmt.Errorf("model policy states no rules")
	}
	if err := strictDecode(raw, &rules); err != nil {
		return ModelPolicyRules{}, fmt.Errorf("model policy rules: %w", err)
	}
	switch rules.ProviderClass {
	case "general", "reasoning", "embedding":
	default:
		return ModelPolicyRules{}, fmt.Errorf("model policy provider class %q is outside the frozen vocabulary", rules.ProviderClass)
	}
	switch rules.MaximumRiskClass {
	case "low", "medium", "high":
	default:
		return ModelPolicyRules{}, fmt.Errorf("model policy risk class %q is outside the frozen vocabulary", rules.MaximumRiskClass)
	}
	if len(rules.AllowedDataClasses) < 1 || len(rules.AllowedDataClasses) > 4 {
		return ModelPolicyRules{}, fmt.Errorf("model policy declares no bounded data classes")
	}
	for _, value := range rules.AllowedDataClasses {
		switch value {
		case "public", "internal", "confidential", "restricted":
		default:
			return ModelPolicyRules{}, fmt.Errorf("model policy data class %q is outside the frozen vocabulary", value)
		}
	}
	if len(rules.AllowedProviders) > 128 {
		return ModelPolicyRules{}, fmt.Errorf("model policy provider allowance is unbounded")
	}
	if len(rules.AllowedRegions) < 1 || len(rules.AllowedRegions) > 64 {
		return ModelPolicyRules{}, fmt.Errorf("model policy declares no bounded residency")
	}
	if rules.Capability == "" || len(rules.Capability) > 128 {
		return ModelPolicyRules{}, fmt.Errorf("model policy declares no bounded provider capability")
	}
	if rules.MinimumSafety < 0 || rules.MinimumSafety > 100 {
		return ModelPolicyRules{}, fmt.Errorf("model policy safety floor is outside the frozen bound")
	}
	if rules.MaximumCostMicros < 0 {
		return ModelPolicyRules{}, fmt.Errorf("model policy cost ceiling must not be negative")
	}
	return rules, nil
}
