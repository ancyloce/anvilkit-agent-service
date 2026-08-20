package execution_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	contractvalidator "github.com/ancyloce/anvilkit-agent-service/contracts/validator"
	"github.com/ancyloce/anvilkit-agent-service/internal/agent"
	"github.com/ancyloce/anvilkit-agent-service/internal/contracts"
	"github.com/ancyloce/anvilkit-agent-service/internal/execution"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/tools"
)

// approvedRegistry builds the registry from the approved definition catalog
// shipped with the service, so tests measure the signed material rather than a
// locally declared copy of it.
func approvedRegistry(t *testing.T) *agent.Registry {
	t.Helper()
	validator, err := contractvalidator.New("../..")
	if err != nil {
		t.Fatal(err)
	}
	definitionSchema, err := os.ReadFile("../../contracts/agent/schemas/agent-definition.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := contracts.PinnedIdentity("../..")
	if err != nil {
		t.Fatal(err)
	}
	registry, err := agent.NewRegistry(context.Background(), agent.RegistryConfig{
		Source:              agent.EmbeddedCatalog{},
		Validator:           validator,
		DefinitionSchemaURI: agent.DefinitionSchemaURI(definitionSchema),
		Approval:            agent.Approval{ProfileDigest: identity.ProfileDigest, LockDigest: identity.LockDigest, SchemaDigests: identity.SchemaDigests},
	})
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

func pinnedToolArguments(t *testing.T) *execution.PinnedToolArgumentValidator {
	t.Helper()
	validator, err := execution.NewPinnedToolArgumentValidator()
	if err != nil {
		t.Fatal(err)
	}
	return validator
}

// The guard's argument boundary must enforce the pinned schema, not merely
// that the arguments parse as JSON.
func TestPinnedToolArgumentValidatorEnforcesTheSchema(t *testing.T) {
	validator := pinnedToolArguments(t)
	reference, err := validator.Reference("anvilkit.tool.context-echo.arguments")
	if err != nil {
		t.Fatal(err)
	}
	if err := validator.Validate(context.Background(), reference, json.RawMessage(`{"query":"page context"}`)); err != nil {
		t.Fatalf("valid arguments rejected: %v", err)
	}
	for _, testCase := range []struct {
		name      string
		arguments string
	}{
		{"missing-required-property", `{}`},
		{"wrong-type", `{"query":42}`},
		{"empty-string", `{"query":""}`},
		{"unknown-property", `{"query":"ok","extra":true}`},
		{"not-an-object", `"page context"`},
		{"duplicate-keys", `{"query":"a","query":"b"}`},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			err := validator.Validate(context.Background(), reference, json.RawMessage(testCase.arguments))
			var details problem.Details
			if !errors.As(err, &details) || details.Code != string(problem.CodeContractInvalid) {
				t.Fatalf("arguments %s were accepted: %v", testCase.arguments, err)
			}
		})
	}
}

// The reference is digest pinned: an unknown component or a digest that does
// not match the pinned schema bytes fails closed.
func TestPinnedToolArgumentValidatorFailsClosedOnUnpinnedReferences(t *testing.T) {
	validator := pinnedToolArguments(t)
	reference, err := validator.Reference("anvilkit.tool.artifact-scan.arguments")
	if err != nil {
		t.Fatal(err)
	}
	valid := json.RawMessage(`{"artifactDigest":"sha256:` + strings.Repeat("a", 64) + `"}`)
	if err := validator.Validate(context.Background(), reference, valid); err != nil {
		t.Fatalf("valid arguments rejected: %v", err)
	}
	tampered := reference
	tampered.Digest = "sha256:" + strings.Repeat("b", 64)
	if err := validator.Validate(context.Background(), tampered, valid); err == nil {
		t.Fatal("a mismatched schema digest was accepted")
	}
	unknown := tools.SchemaReference{ComponentName: "anvilkit.tool.unknown.arguments", Digest: reference.Digest}
	if err := validator.Validate(context.Background(), unknown, valid); err == nil {
		t.Fatal("an unpinned schema component was accepted")
	}
	if _, err := validator.Reference("anvilkit.tool.unknown.arguments"); err == nil {
		t.Fatal("an unpinned component produced a reference")
	}
}

// The approved tool profile must be built from the catalog's signed
// ToolDefinitions and must pin each tool's input schema to the digest of that
// tool's own argument schema.
func TestApprovedToolProfileCarriesTheSignedDefinitionsAndPerToolSchemas(t *testing.T) {
	validator := pinnedToolArguments(t)
	toolSchema, err := os.ReadFile("../../contracts/agent/schemas/tool-definition.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + hex.EncodeToString(sha256Of(toolSchema))
	registry := approvedRegistry(t)
	bindings := registry.ToolBindings()
	profile, err := execution.NewApprovedToolProfile(bindings, digest, registry.CatalogDigest(), validator)
	if err != nil {
		t.Fatal(err)
	}
	if len(profile.Definitions) != len(bindings) || len(bindings) != 3 {
		t.Fatalf("profile definitions = %d, bindings = %d", len(profile.Definitions), len(bindings))
	}
	signed := map[string]agent.ToolBinding{}
	for _, binding := range bindings {
		signed[binding.ToolID] = binding
	}
	seen := map[string]bool{}
	for _, definition := range profile.Definitions {
		reference, err := validator.Reference(definition.ToolID + ".arguments")
		if err != nil {
			t.Fatalf("%s has no pinned argument schema: %v", definition.ToolID, err)
		}
		if definition.InputSchema != reference {
			t.Fatalf("%s input schema = %+v, want %+v", definition.ToolID, definition.InputSchema, reference)
		}
		binding, approved := signed[definition.ToolID]
		if !approved {
			t.Fatalf("%s is not an approved tool", definition.ToolID)
		}
		if definition.Capability != binding.Capability || definition.SideEffectClass != binding.SideEffectClass || definition.RiskClass != binding.RiskClass {
			t.Fatalf("%s does not carry the signed capability, side effect, and risk: %+v", definition.ToolID, definition)
		}
		if definition.TimeoutPolicy.TimeoutMilliseconds != binding.TimeoutMilliseconds || definition.RetryPolicy.MaximumAttempts != binding.MaximumAttempts {
			t.Fatalf("%s does not carry the signed timeout and retry policy: %+v", definition.ToolID, definition)
		}
		if definition.ApprovalPolicy.Digest != binding.ApprovalPolicy.Digest {
			t.Fatalf("%s does not carry the signed approval policy: %+v", definition.ToolID, definition)
		}
		if seen[definition.InputSchema.Digest] {
			t.Fatalf("%s shares an argument schema digest with another tool", definition.ToolID)
		}
		seen[definition.InputSchema.Digest] = true
	}
	if _, err := execution.NewApprovedToolProfile(bindings, digest, registry.CatalogDigest(), nil); err == nil {
		t.Fatal("a profile without the pinned argument validator was accepted")
	}
	if _, err := execution.NewApprovedToolProfile(bindings, "not-a-digest", registry.CatalogDigest(), validator); err == nil {
		t.Fatal("a profile with an unpinned schema digest was accepted")
	}
}

func sha256Of(raw []byte) []byte {
	sum := sha256.Sum256(raw)
	return sum[:]
}
