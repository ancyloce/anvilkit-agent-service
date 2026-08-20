package execution

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"

	contractvalidator "github.com/ancyloce/anvilkit-agent-service/contracts/validator"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/tools"
)

//go:embed toolschemas
var toolArgumentSchemas embed.FS

const toolArgumentSchemaSuffix = ".schema.json"

// pinnedToolSchema is one compiled tool argument schema and the digest that
// pins its bytes.
type pinnedToolSchema struct {
	digest string
	schema *jsonschema.Schema
}

// PinnedToolArgumentValidator validates tool arguments against the tool's
// digest-pinned input schema. It is the Tool Guard's argument boundary:
// a proposal whose schema reference is unknown, whose digest does not match
// the pinned bytes, or whose arguments violate the schema fails closed.
// Syntactic JSON admission alone is never sufficient.
type PinnedToolArgumentValidator struct {
	schemas map[string]pinnedToolSchema
}

// NewPinnedToolArgumentValidator compiles the pinned tool argument schemas
// shipped with the service. Compilation resolves no network or file
// reference.
func NewPinnedToolArgumentValidator() (*PinnedToolArgumentValidator, error) {
	entries, err := toolArgumentSchemas.ReadDir("toolschemas")
	if err != nil {
		return nil, fmt.Errorf("pinned tool argument validator: %w", err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	compiler.UseLoader(deniedSchemaLoader{})
	type source struct {
		component, uri, digest string
	}
	sources := make([]source, 0, len(entries))
	for _, entry := range entries {
		component, isSchema := strings.CutSuffix(entry.Name(), toolArgumentSchemaSuffix)
		if entry.IsDir() || !isSchema {
			continue
		}
		raw, err := toolArgumentSchemas.ReadFile("toolschemas/" + entry.Name())
		if err != nil {
			return nil, fmt.Errorf("pinned tool argument validator: %w", err)
		}
		admitted, err := contractvalidator.Admit(raw)
		if err != nil {
			return nil, fmt.Errorf("pinned tool argument validator: %s is not strictly admissible: %w", entry.Name(), err)
		}
		document, ok := admitted.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("pinned tool argument validator: %s must be a schema object", entry.Name())
		}
		sum := sha256.Sum256(raw)
		digest := "sha256:" + hex.EncodeToString(sum[:])
		uri := "anvilkit://tool-arguments/" + component + "?digest=" + digest
		document["$id"] = uri
		if err := compiler.AddResource(uri, document); err != nil {
			return nil, fmt.Errorf("pinned tool argument validator: register %s: %w", component, err)
		}
		sources = append(sources, source{component: component, uri: uri, digest: digest})
	}
	if len(sources) == 0 {
		return nil, fmt.Errorf("pinned tool argument validator: no pinned tool argument schemas found")
	}
	validator := &PinnedToolArgumentValidator{schemas: make(map[string]pinnedToolSchema, len(sources))}
	for _, value := range sources {
		compiled, err := compiler.Compile(value.uri)
		if err != nil {
			return nil, fmt.Errorf("pinned tool argument validator: compile %s: %w", value.component, err)
		}
		validator.schemas[value.component] = pinnedToolSchema{digest: value.digest, schema: compiled}
	}
	return validator, nil
}

// Reference returns the pinned schema reference for one tool argument
// component. It is how the tool profile pins its input schemas.
func (v *PinnedToolArgumentValidator) Reference(componentName string) (tools.SchemaReference, error) {
	pinned, known := v.schemas[componentName]
	if !known {
		return tools.SchemaReference{}, fmt.Errorf("pinned tool argument validator: %s is not a pinned component", componentName)
	}
	return tools.SchemaReference{ComponentName: componentName, Digest: pinned.digest}, nil
}

// ComponentDigest returns the digest of the argument schema the service is
// actually running for one Tool component, keyed by the component identity
// an AgentDefinition tool profile uses. It satisfies the ToolMaterial port.
func (v *PinnedToolArgumentValidator) ComponentDigest(componentName string) (string, bool) {
	pinned, known := v.schemas[componentName+".arguments"]
	if !known {
		return "", false
	}
	return pinned.digest, true
}

// Validate satisfies the Tool Guard argument validator port.
func (v *PinnedToolArgumentValidator) Validate(_ context.Context, reference tools.SchemaReference, arguments json.RawMessage) error {
	pinned, known := v.schemas[reference.ComponentName]
	if !known {
		return argumentProblem("tool argument schema reference is not a pinned component")
	}
	if pinned.digest != reference.Digest {
		return argumentProblem("tool argument schema digest does not match the pinned schema bytes")
	}
	value, err := contractvalidator.Admit(arguments)
	if err != nil {
		return argumentProblem("tool arguments are not strictly admissible JSON")
	}
	if err := pinned.schema.Validate(value); err != nil {
		return argumentProblem("tool arguments violate the pinned input schema")
	}
	return nil
}

func argumentProblem(detail string) problem.Details {
	details := problem.New(problem.CodeContractInvalid, "")
	details.Detail = detail
	return details
}

// deniedSchemaLoader refuses every external schema reference.
type deniedSchemaLoader struct{}

func (deniedSchemaLoader) Load(url string) (any, error) {
	return nil, fmt.Errorf("tool argument schema resolution denied: %s", url)
}

var _ tools.ArgumentValidator = (*PinnedToolArgumentValidator)(nil)
