package agent

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/ancyloce/anvilkit-agent-service/contracts/validator"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
)

// Source supplies pinned AgentDefinition documents and their instruction
// bytes. Implementations are approved definition stores, never discovery.
type Source interface {
	Definitions(context.Context) ([][]byte, error)
	Instruction(ctx context.Context, definitionID string) ([]byte, error)
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

// RegistryConfig wires the approved source and mandatory schema validation.
type RegistryConfig struct {
	Source              Source
	Validator           SchemaValidator
	DefinitionSchemaURI string
}

// Registry resolves Manager and Specialist definitions by canonical identity
// and frozen digest. Construction fails closed: an invalid, unverifiable, or
// inconsistent definition set produces no registry at all.
type Registry struct {
	definitions  map[string]Definition
	instructions map[string]string
}

const maximumDefinitions = 64

func NewRegistry(ctx context.Context, cfg RegistryConfig) (*Registry, error) {
	if cfg.Source == nil || cfg.Validator == nil || cfg.DefinitionSchemaURI == "" {
		return nil, fmt.Errorf("agent registry: source, schema validator, and pinned schema identity are required")
	}
	documents, err := cfg.Source.Definitions(ctx)
	if err != nil {
		return nil, fmt.Errorf("agent registry: load definitions: %w", err)
	}
	if len(documents) == 0 || len(documents) > maximumDefinitions {
		return nil, fmt.Errorf("agent registry: definition set must contain between 1 and %d documents", maximumDefinitions)
	}
	registry := &Registry{definitions: make(map[string]Definition, len(documents)), instructions: make(map[string]string, len(documents))}
	for _, raw := range documents {
		if findings := cfg.Validator.Validate(cfg.DefinitionSchemaURI, raw); len(findings) != 0 {
			return nil, fmt.Errorf("agent registry: definition violates the pinned canonical schema: %v", findings)
		}
		definition, err := ParseDefinition(raw)
		if err != nil {
			return nil, fmt.Errorf("agent registry: %w", err)
		}
		identity, err := definition.IdentityDigest()
		if err != nil {
			return nil, fmt.Errorf("agent registry: %w", err)
		}
		if identity != definition.DefinitionDigest {
			return nil, fmt.Errorf("agent registry: definition %s digest does not match its identity content", definition.DefinitionID)
		}
		if _, duplicate := registry.definitions[definition.DefinitionID]; duplicate {
			return nil, fmt.Errorf("agent registry: duplicate definition identity %s", definition.DefinitionID)
		}
		instruction, err := cfg.Source.Instruction(ctx, definition.DefinitionID)
		if err != nil {
			return nil, fmt.Errorf("agent registry: instruction for %s: %w", definition.DefinitionID, err)
		}
		instructionDigest := sha256.Sum256(instruction)
		if "sha256:"+hex.EncodeToString(instructionDigest[:]) != definition.PromptDigest {
			return nil, fmt.Errorf("agent registry: instruction bytes for %s do not match the pinned prompt digest", definition.DefinitionID)
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

//go:embed definitions
var embeddedDefinitions embed.FS

// EmbeddedCatalog is the first-party pinned definition source shipped with
// the service: one Manager and one Specialist.
type EmbeddedCatalog struct{}

const (
	ManagerDefinitionID    = "definition.platform.manager"
	SpecialistDefinitionID = "definition.platform.component-spec-specialist"
)

func (EmbeddedCatalog) Definitions(context.Context) ([][]byte, error) {
	var documents [][]byte
	for _, id := range []string{ManagerDefinitionID, SpecialistDefinitionID} {
		raw, err := embeddedDefinitions.ReadFile("definitions/" + id + ".json")
		if err != nil {
			return nil, fmt.Errorf("embedded definition catalog: %w", err)
		}
		documents = append(documents, raw)
	}
	return documents, nil
}

func (EmbeddedCatalog) Instruction(_ context.Context, definitionID string) ([]byte, error) {
	raw, err := embeddedDefinitions.ReadFile("definitions/" + definitionID + ".instruction.txt")
	if err != nil {
		return nil, fmt.Errorf("embedded definition catalog: %w", err)
	}
	return raw, nil
}
