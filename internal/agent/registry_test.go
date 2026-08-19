package agent

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	contractvalidator "github.com/ancyloce/anvilkit-agent-service/contracts/validator"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
)

func registryConfig(t *testing.T, source Source) RegistryConfig {
	t.Helper()
	adapter, err := contractvalidator.New("../..")
	if err != nil {
		t.Fatal(err)
	}
	schemaBytes, err := os.ReadFile("../../contracts/agent/schemas/agent-definition.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	return RegistryConfig{Source: source, Validator: adapter, DefinitionSchemaURI: DefinitionSchemaURI(schemaBytes)}
}

func newTestRegistry(t *testing.T) *Registry {
	t.Helper()
	registry, err := NewRegistry(context.Background(), registryConfig(t, EmbeddedCatalog{}))
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

type alteredSource struct {
	inner  Source
	mutate func([]byte) []byte
}

func (s alteredSource) Definitions(ctx context.Context) ([][]byte, error) {
	documents, err := s.inner.Definitions(ctx)
	if err != nil {
		return nil, err
	}
	out := make([][]byte, 0, len(documents))
	for _, document := range documents {
		out = append(out, s.mutate(document))
	}
	return out, nil
}

func (s alteredSource) Instruction(ctx context.Context, id string) ([]byte, error) {
	return s.inner.Instruction(ctx, id)
}

func TestRegistryResolvesManagerAndSpecialistByExactIdentity(t *testing.T) {
	registry := newTestRegistry(t)
	definitions := registry.Definitions()
	if len(definitions) != 2 {
		t.Fatalf("definitions = %d, want 2", len(definitions))
	}
	var manager, specialist Definition
	for _, definition := range definitions {
		switch definition.Role {
		case RoleManager:
			manager = definition
		case RoleSpecialist:
			specialist = definition
		}
	}
	if manager.DefinitionID != ManagerDefinitionID || specialist.DefinitionID != SpecialistDefinitionID {
		t.Fatalf("unexpected topology: %s / %s", manager.DefinitionID, specialist.DefinitionID)
	}
	resolved, err := registry.Resolve(DefinitionReference{DefinitionID: manager.DefinitionID, DefinitionDigest: manager.DefinitionDigest})
	if err != nil || resolved.Role != RoleManager {
		t.Fatalf("resolve manager: %v", err)
	}
	if !manager.AllowsDelegate(specialist.DefinitionID) {
		t.Fatal("manager must allow the specialist delegate")
	}
	if len(specialist.AllowedDelegates) != 0 || specialist.MaximumDelegationDepth != 0 {
		t.Fatal("specialist must not delegate further")
	}
	instruction, err := registry.Instruction(manager.DefinitionID)
	if err != nil || instruction == "" {
		t.Fatalf("manager instruction unavailable: %v", err)
	}
}

func TestRegistryFailsClosedOnUnknownIdentityAndDigestMismatch(t *testing.T) {
	registry := newTestRegistry(t)
	if _, err := registry.Resolve(DefinitionReference{DefinitionID: "definition.platform.unknown", DefinitionDigest: strings.Repeat("a", 64)}); err == nil {
		t.Fatal("unknown definition must fail closed")
	}
	manager := registry.Definitions()[1]
	if manager.Role != RoleManager {
		manager = registry.Definitions()[0]
	}
	var details problem.Details
	_, err := registry.Resolve(DefinitionReference{DefinitionID: manager.DefinitionID, DefinitionDigest: "sha256:" + strings.Repeat("0", 64)})
	if err == nil {
		t.Fatal("digest mismatch must fail closed")
	}
	if !problemAs(err, &details) || details.Code != string(problem.CodeContractInvalid) {
		t.Fatalf("digest mismatch problem = %v", err)
	}
	if _, err := registry.ResolveDelegate("definition.platform.unknown"); err == nil {
		t.Fatal("unknown delegate must fail closed")
	}
}

func TestRegistryRejectsTamperedDefinitionContent(t *testing.T) {
	tampered := alteredSource{inner: EmbeddedCatalog{}, mutate: func(raw []byte) []byte {
		return []byte(strings.Replace(string(raw), `"turnLimit": 16`, `"turnLimit": 17`, 1))
	}}
	if _, err := NewRegistry(context.Background(), registryConfig(t, tampered)); err == nil {
		t.Fatal("tampered identity content must fail registry construction")
	}
}

func TestRegistryRejectsInstructionDigestMismatch(t *testing.T) {
	tampered := instructionTamperSource{EmbeddedCatalog{}}
	if _, err := NewRegistry(context.Background(), registryConfig(t, tampered)); err == nil {
		t.Fatal("tampered instruction bytes must fail registry construction")
	}
}

type instructionTamperSource struct{ inner Source }

func (s instructionTamperSource) Definitions(ctx context.Context) ([][]byte, error) {
	return s.inner.Definitions(ctx)
}
func (s instructionTamperSource) Instruction(ctx context.Context, id string) ([]byte, error) {
	raw, err := s.inner.Instruction(ctx, id)
	if err != nil {
		return nil, err
	}
	return append(raw, byte(' ')), nil
}

func TestRegistryRequiresSchemaValidDefinitions(t *testing.T) {
	tampered := alteredSource{inner: EmbeddedCatalog{}, mutate: func(raw []byte) []byte {
		var document map[string]json.RawMessage
		if err := json.Unmarshal(raw, &document); err != nil {
			return raw
		}
		document["unknownField"] = json.RawMessage(`"x"`)
		out, _ := json.Marshal(document)
		return out
	}}
	if _, err := NewRegistry(context.Background(), registryConfig(t, tampered)); err == nil {
		t.Fatal("schema-invalid definition must fail registry construction")
	}
}

func problemAs(err error, target *problem.Details) bool {
	details, ok := err.(problem.Details)
	if ok {
		*target = details
		return true
	}
	return false
}

func TestTurnDecisionValidateEnforcesExactlyOnePayload(t *testing.T) {
	valid := map[DecisionKind]TurnDecision{
		DecisionContinue:  {Kind: DecisionContinue, Continue: &ContinueDecision{Note: "n"}},
		DecisionToolCall:  {Kind: DecisionToolCall, ToolCall: &ToolCallDecision{ToolID: "anvilkit.tool.context-echo", Arguments: json.RawMessage(`{}`)}},
		DecisionDelegate:  {Kind: DecisionDelegate, Delegate: &DelegateDecision{DelegateID: SpecialistDefinitionID, Input: json.RawMessage(`{}`)}},
		DecisionNeedInput: {Kind: DecisionNeedInput, NeedInput: &NeedInputDecision{Question: "q"}},
		DecisionFinal:     {Kind: DecisionFinal, Final: &FinalDecision{Candidate: json.RawMessage(`{}`)}},
		DecisionRefuse:    {Kind: DecisionRefuse, Refuse: &RefuseDecision{Reason: "r"}},
	}
	if len(valid) != len(DecisionKinds()) {
		t.Fatal("decision table must cover the frozen vocabulary")
	}
	for kind, decision := range valid {
		if err := decision.Validate(); err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
	}
	invalid := []TurnDecision{
		{},
		{Kind: DecisionContinue},
		{Kind: "unknown", Continue: &ContinueDecision{}},
		{Kind: DecisionFinal, Continue: &ContinueDecision{}},
		{Kind: DecisionContinue, Continue: &ContinueDecision{}, Final: &FinalDecision{Candidate: json.RawMessage(`{}`)}},
		{Kind: DecisionToolCall, ToolCall: &ToolCallDecision{ToolID: "", Arguments: json.RawMessage(`{}`)}},
		{Kind: DecisionToolCall, ToolCall: &ToolCallDecision{ToolID: "tool", Arguments: json.RawMessage(`{broken`)}},
		{Kind: DecisionDelegate, Delegate: &DelegateDecision{DelegateID: "", Input: json.RawMessage(`{}`)}},
		{Kind: DecisionNeedInput, NeedInput: &NeedInputDecision{Question: ""}},
		{Kind: DecisionNeedInput, NeedInput: &NeedInputDecision{Question: strings.Repeat("q", 4097)}},
		{Kind: DecisionFinal, Final: &FinalDecision{Candidate: nil}},
		{Kind: DecisionRefuse, Refuse: &RefuseDecision{Reason: ""}},
	}
	for index, decision := range invalid {
		if err := decision.Validate(); err == nil {
			t.Fatalf("invalid decision %d must fail validation", index)
		}
	}
}

func TestDefinitionIdentityDigestIsDeterministic(t *testing.T) {
	documents, err := EmbeddedCatalog{}.Definitions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range documents {
		definition, err := ParseDefinition(raw)
		if err != nil {
			t.Fatal(err)
		}
		first, err := definition.IdentityDigest()
		if err != nil {
			t.Fatal(err)
		}
		second, err := definition.IdentityDigest()
		if err != nil || first != second {
			t.Fatalf("identity digest is not deterministic: %s %s %v", first, second, err)
		}
		if first != definition.DefinitionDigest {
			t.Fatalf("pinned digest %s does not match identity %s", definition.DefinitionDigest, first)
		}
	}
}
