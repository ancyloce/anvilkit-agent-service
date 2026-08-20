package agent

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/ancyloce/anvilkit-agent-service/contracts/validator"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
)

// Source supplies the approved definition catalog and the documents it names.
// Implementations are approved definition stores, never discovery: the
// catalog is the list of what exists, and no document outside it is readable.
type Source interface {
	Catalog(context.Context) ([]byte, error)
	Document(ctx context.Context, name string) ([]byte, error)
}

// SchemaValidator validates one document against one pinned schema identity.
// The contracts validator adapter satisfies this interface.
type SchemaValidator interface {
	Validate(schemaURI string, raw []byte) []validator.Finding
}

// DefinitionSchemaURI derives the pinned schema identity for the canonical
// AgentDefinition schema bytes.
func DefinitionSchemaURI(schemaBytes []byte) string {
	digest := sha256.Sum256(schemaBytes)
	return "anvilkit://schema/agent-definition?digest=sha256:" + hex.EncodeToString(digest[:])
}

// RegistryConfig wires the approved source, mandatory schema validation, and
// the verified contract identity the catalog must be bound to.
type RegistryConfig struct {
	Source              Source
	Validator           SchemaValidator
	DefinitionSchemaURI string
	Approval            Approval
}

// Registry resolves Manager and Specialist definitions by canonical identity
// and frozen digest. Construction fails closed: a definition that is not in
// the approved catalog, whose bytes do not match the catalog, or whose
// referenced Tool, model, memory, Guardrail, or schema material does not
// match the material the catalog approves, produces no registry at all.
type Registry struct {
	definitions   map[string]Definition
	instructions  map[string]string
	policies      map[string]string
	toolSchemas   map[string]string
	toolBindings  map[string]ToolBinding
	modelPolicies map[string]ModelPolicy
	schemaDigests map[string]string
	catalogDigest string
}

const maximumDefinitions = 64

func NewRegistry(ctx context.Context, cfg RegistryConfig) (*Registry, error) {
	if cfg.Source == nil || cfg.Validator == nil || cfg.DefinitionSchemaURI == "" {
		return nil, fmt.Errorf("agent registry: source, schema validator, and pinned schema identity are required")
	}
	catalogBytes, err := cfg.Source.Catalog(ctx)
	if err != nil {
		return nil, fmt.Errorf("agent registry: load approved catalog: %w", err)
	}
	catalog, err := ParseCatalog(catalogBytes)
	if err != nil {
		return nil, fmt.Errorf("agent registry: %w", err)
	}
	if err := catalog.Authenticate(cfg.Approval); err != nil {
		return nil, fmt.Errorf("agent registry: %w", err)
	}
	if len(catalog.Definitions) > maximumDefinitions {
		return nil, fmt.Errorf("agent registry: definition set must contain between 1 and %d documents", maximumDefinitions)
	}

	registry := &Registry{
		definitions:   make(map[string]Definition, len(catalog.Definitions)),
		instructions:  make(map[string]string, len(catalog.Definitions)),
		policies:      make(map[string]string, len(catalog.Policies)),
		toolSchemas:   make(map[string]string, len(catalog.ToolSchemas)),
		toolBindings:  make(map[string]ToolBinding, len(catalog.ToolSchemas)),
		modelPolicies: make(map[string]ModelPolicy, len(catalog.Policies)),
		schemaDigests: cloneDigests(cfg.Approval.SchemaDigests),
		catalogDigest: DocumentDigest(catalogBytes),
	}

	// Policy material is authenticated before any definition may reference it.
	for _, entry := range catalog.Policies {
		raw, err := cfg.Source.Document(ctx, entry.Document)
		if err != nil {
			return nil, fmt.Errorf("agent registry: policy %s: %w", entry.PolicyID, err)
		}
		if !equalDigest(DocumentDigest(raw), entry.DocumentDigest) {
			return nil, fmt.Errorf("agent registry: policy %s does not match the approved catalog", entry.PolicyID)
		}
		var document struct {
			Kind     string          `json:"kind"`
			PolicyID string          `json:"policyId"`
			Version  string          `json:"version"`
			Rules    json.RawMessage `json:"rules"`
		}
		if err := decodeJSON(raw, &document); err != nil {
			return nil, fmt.Errorf("agent registry: decode policy %s: %w", entry.PolicyID, err)
		}
		if document.Kind != entry.Kind || document.PolicyID != entry.PolicyID || document.Version != entry.Version {
			return nil, fmt.Errorf("agent registry: policy %s does not carry the approved identity", entry.PolicyID)
		}
		// A model policy is not opaque material: it decides which providers a
		// run may disclose context to, so its rules are decoded and bounded
		// here and served to selection instead of being restated in code.
		if entry.Kind == "ModelPolicy" {
			rules, err := parseModelPolicyRules(document.Rules)
			if err != nil {
				return nil, fmt.Errorf("agent registry: policy %s: %w", entry.PolicyID, err)
			}
			registry.modelPolicies[policyKey(entry.PolicyID, entry.Version)] = ModelPolicy{PolicyID: entry.PolicyID, Version: entry.Version, Digest: entry.DocumentDigest, Rules: rules}
		}
		registry.policies[policyKey(entry.PolicyID, entry.Version)] = entry.DocumentDigest
	}

	// Tool material is approved here: the argument schema identity and the
	// complete ToolDefinition. The bytes and the definition the process is
	// actually running are checked against both at run time through the
	// ToolMaterial boundary.
	for _, entry := range catalog.ToolSchemas {
		registry.toolSchemas[entry.ComponentName] = entry.Digest
		registry.toolBindings[entry.ComponentName] = entry.Definition.clone()
	}

	for _, entry := range catalog.Definitions {
		raw, err := cfg.Source.Document(ctx, entry.Document)
		if err != nil {
			return nil, fmt.Errorf("agent registry: definition %s: %w", entry.DefinitionID, err)
		}
		if !equalDigest(DocumentDigest(raw), entry.DocumentDigest) {
			return nil, fmt.Errorf("agent registry: definition %s does not match the approved catalog", entry.DefinitionID)
		}
		if findings := cfg.Validator.Validate(cfg.DefinitionSchemaURI, raw); len(findings) != 0 {
			return nil, fmt.Errorf("agent registry: definition violates the pinned canonical schema: %v", findings)
		}
		definition, err := ParseDefinition(raw)
		if err != nil {
			return nil, fmt.Errorf("agent registry: %w", err)
		}
		if definition.DefinitionID != entry.DefinitionID {
			return nil, fmt.Errorf("agent registry: definition %s does not carry the approved identity", entry.DefinitionID)
		}
		identity, err := definition.IdentityDigest()
		if err != nil {
			return nil, fmt.Errorf("agent registry: %w", err)
		}
		if identity != definition.DefinitionDigest || !equalDigest(identity, entry.DefinitionDigest) {
			return nil, fmt.Errorf("agent registry: definition %s digest does not match its identity content", definition.DefinitionID)
		}
		if _, duplicate := registry.definitions[definition.DefinitionID]; duplicate {
			return nil, fmt.Errorf("agent registry: duplicate definition identity %s", definition.DefinitionID)
		}
		instruction, err := cfg.Source.Document(ctx, entry.Instruction)
		if err != nil {
			return nil, fmt.Errorf("agent registry: instruction for %s: %w", definition.DefinitionID, err)
		}
		if !equalDigest(DocumentDigest(instruction), entry.InstructionDigest) {
			return nil, fmt.Errorf("agent registry: instruction bytes for %s do not match the approved catalog", definition.DefinitionID)
		}
		if !equalDigest(DocumentDigest(instruction), definition.PromptDigest) {
			return nil, fmt.Errorf("agent registry: instruction bytes for %s do not match the pinned prompt digest", definition.DefinitionID)
		}
		if err := registry.verifyReferences(definition); err != nil {
			return nil, fmt.Errorf("agent registry: %w", err)
		}
		registry.definitions[definition.DefinitionID] = definition
		registry.instructions[definition.DefinitionID] = string(instruction)
	}
	for _, definition := range registry.definitions {
		for _, delegateID := range definition.AllowedDelegates {
			delegate, known := registry.definitions[delegateID]
			if !known {
				return nil, fmt.Errorf("agent registry: %s allows unknown delegate %s", definition.DefinitionID, delegateID)
			}
			if delegate.Role != RoleSpecialist {
				return nil, fmt.Errorf("agent registry: %s delegate %s must be a specialist", definition.DefinitionID, delegateID)
			}
			if len(delegate.AllowedDelegates) != 0 {
				return nil, fmt.Errorf("agent registry: specialist %s must not delegate further", delegateID)
			}
		}
	}
	return registry, nil
}

// verifyReferences proves that every schema, Tool, model, memory, and
// Guardrail reference a definition carries names material this registry
// authenticated against the approved boundary, with the exact digest the
// definition froze.
func (r *Registry) verifyReferences(definition Definition) error {
	for _, reference := range []SchemaReference{definition.InputSchema, definition.OutputSchema} {
		digest, known := r.schemaDigests[reference.ComponentName]
		if !known {
			return fmt.Errorf("definition %s references schema %s, which the canonical lock does not govern", definition.DefinitionID, reference.ComponentName)
		}
		if !equalDigest(digest, reference.Digest) {
			return fmt.Errorf("definition %s pins schema %s to a digest the canonical lock does not carry", definition.DefinitionID, reference.ComponentName)
		}
	}
	for _, reference := range definition.Evaluators {
		digest, known := r.schemaDigests[reference.ComponentName]
		if !known || !equalDigest(digest, reference.Digest) {
			return fmt.Errorf("definition %s pins evaluator %s to material the canonical lock does not carry", definition.DefinitionID, reference.ComponentName)
		}
	}
	for _, reference := range definition.ToolProfile.Tools {
		digest, known := r.toolSchemas[reference.ComponentName]
		if !known {
			return fmt.Errorf("definition %s references tool %s, which the approved catalog does not carry", definition.DefinitionID, reference.ComponentName)
		}
		if !equalDigest(digest, reference.Digest) {
			return fmt.Errorf("definition %s pins tool %s to a digest the approved catalog does not carry", definition.DefinitionID, reference.ComponentName)
		}
	}
	for label, reference := range map[string]PolicyReference{"model": definition.ModelPolicy, "memory": definition.MemoryPolicy, "guardrail": definition.GuardrailPolicy} {
		digest, known := r.policies[policyKey(reference.PolicyID, reference.Version)]
		if !known {
			return fmt.Errorf("definition %s references %s policy %s, which the approved catalog does not carry", definition.DefinitionID, label, reference.PolicyID)
		}
		if !equalDigest(digest, reference.Digest) {
			return fmt.Errorf("definition %s pins %s policy %s to a digest the approved catalog does not carry", definition.DefinitionID, label, reference.PolicyID)
		}
	}
	return nil
}

// Resolve returns the definition for an exact identity and digest. Unknown
// identities and digest mismatches fail closed with a typed problem.
func (r *Registry) Resolve(reference DefinitionReference) (Definition, error) {
	definition, known := r.definitions[reference.DefinitionID]
	if !known {
		details := problem.New(problem.CodeContractInvalid, "")
		details.Detail = "agent definition is not in the approved registry"
		return Definition{}, details
	}
	if definition.DefinitionDigest != reference.DefinitionDigest {
		details := problem.New(problem.CodeContractInvalid, "")
		details.Detail = "agent definition digest does not match the approved registry"
		return Definition{}, details
	}
	return definition, nil
}

// ResolveDelegate resolves an approved definition by identity alone. It is
// used only for delegation targets, whose digests are authoritative in the
// registry itself; unknown identities fail closed.
func (r *Registry) ResolveDelegate(definitionID string) (Definition, error) {
	definition, known := r.definitions[definitionID]
	if !known {
		details := problem.New(problem.CodeContractInvalid, "")
		details.Detail = "delegate definition is not in the approved registry"
		return Definition{}, details
	}
	return definition, nil
}

// Instruction returns the digest-verified instruction text for a resolved
// definition identity.
func (r *Registry) Instruction(definitionID string) (string, error) {
	instruction, known := r.instructions[definitionID]
	if !known {
		details := problem.New(problem.CodeContractInvalid, "")
		details.Detail = "agent instruction is not in the approved registry"
		return "", details
	}
	return instruction, nil
}

// Definitions lists the approved set ordered by identity.
func (r *Registry) Definitions() []Definition {
	ordered := make([]Definition, 0, len(r.definitions))
	for _, definition := range r.definitions {
		ordered = append(ordered, definition)
	}
	sort.Slice(ordered, func(left, right int) bool { return ordered[left].DefinitionID < ordered[right].DefinitionID })
	return ordered
}

// CatalogDigest is the digest of the approved catalog this registry was built
// from. It is the identity an external attestation signs.
func (r *Registry) CatalogDigest() string { return r.catalogDigest }

// ToolSchemaDigest returns the approved digest for one Tool argument schema
// component, so the running Tool material can be checked against the
// definition frozen on a run.
func (r *Registry) ToolSchemaDigest(componentName string) (string, bool) {
	digest, known := r.toolSchemas[componentName]
	return digest, known
}

// ToolBinding returns the complete approved ToolDefinition for one Tool
// component, so the definition the process dispatches can be checked against
// the definition the catalog attests rather than trusted because its argument
// schema digest happens to match.
func (r *Registry) ToolBinding(componentName string) (ToolBinding, bool) {
	binding, known := r.toolBindings[componentName]
	if !known {
		return ToolBinding{}, false
	}
	return binding.clone(), true
}

// ToolBindings lists the approved ToolDefinitions ordered by component
// identity. The running tool profile is built from this list, so the material
// in the process is the material the catalog approves by construction.
func (r *Registry) ToolBindings() []ToolBinding {
	ordered := make([]ToolBinding, 0, len(r.toolBindings))
	for _, binding := range r.toolBindings {
		ordered = append(ordered, binding.clone())
	}
	sort.Slice(ordered, func(left, right int) bool { return ordered[left].ToolID < ordered[right].ToolID })
	return ordered
}

// ModelPolicy returns the approved signed model policy for one identity. It
// is the only source of provider-eligibility rules the runtime reads: a
// selection made from anything else is a selection the catalog never attested.
func (r *Registry) ModelPolicy(policyID, version string) (ModelPolicy, bool) {
	policy, known := r.modelPolicies[policyKey(policyID, version)]
	if !known {
		return ModelPolicy{}, false
	}
	return policy.Clone(), true
}

// PolicyDigest returns the approved digest for one policy identity.
func (r *Registry) PolicyDigest(policyID, version string) (string, bool) {
	digest, known := r.policies[policyKey(policyID, version)]
	return digest, known
}

// SchemaDigest returns the canonical lock digest for one governed schema
// component.
func (r *Registry) SchemaDigest(componentName string) (string, bool) {
	digest, known := r.schemaDigests[componentName]
	return digest, known
}

// VerifyDefinitionReferences re-proves a resolved definition's references
// against the approved material. The executor calls it for every run so a
// definition can never be executed against material other than the material
// frozen with it.
func (r *Registry) VerifyDefinitionReferences(definition Definition) error {
	return r.verifyReferences(definition)
}

func policyKey(policyID, version string) string { return policyID + "\x00" + version }

func cloneDigests(value map[string]string) map[string]string {
	copied := make(map[string]string, len(value))
	for key, digest := range value {
		copied[key] = digest
	}
	return copied
}

//go:embed definitions/catalog.json
//go:embed definitions/definition.platform.manager.json
//go:embed definitions/definition.platform.manager.instruction.txt
//go:embed definitions/definition.platform.component-spec-specialist.json
//go:embed definitions/definition.platform.component-spec-specialist.instruction.txt
//go:embed definitions/policy.model.default.json
//go:embed definitions/policy.memory.none.json
//go:embed definitions/policy.guardrail.baseline.json
var embeddedDefinitions embed.FS

// EmbeddedCatalog is the first-party approved definition store shipped with
// the service. Every file it can serve is named explicitly in the embed
// directives above, so a missing file is a build failure rather than a
// silently smaller catalog at runtime.
type EmbeddedCatalog struct{}

const (
	ManagerDefinitionID    = "definition.platform.manager"
	SpecialistDefinitionID = "definition.platform.component-spec-specialist"
	catalogDocumentName    = "catalog.json"
)

func (EmbeddedCatalog) Catalog(context.Context) ([]byte, error) {
	raw, err := embeddedDefinitions.ReadFile("definitions/" + catalogDocumentName)
	if err != nil {
		return nil, fmt.Errorf("embedded definition store: %w", err)
	}
	return raw, nil
}

func (EmbeddedCatalog) Document(_ context.Context, name string) ([]byte, error) {
	if !validDocumentName(name) || name == catalogDocumentName {
		return nil, fmt.Errorf("embedded definition store: %q is not a readable document name", name)
	}
	raw, err := embeddedDefinitions.ReadFile("definitions/" + name)
	if err != nil {
		return nil, fmt.Errorf("embedded definition store: %w", err)
	}
	return raw, nil
}

var _ Source = EmbeddedCatalog{}
