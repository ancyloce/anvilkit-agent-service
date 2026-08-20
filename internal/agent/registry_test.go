package agent

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	contractvalidator "github.com/ancyloce/anvilkit-agent-service/contracts/validator"
	"github.com/ancyloce/anvilkit-agent-service/internal/contracts"
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
	identity, err := contracts.PinnedIdentity("../..")
	if err != nil {
		t.Fatal(err)
	}
	return RegistryConfig{
		Source:              source,
		Validator:           adapter,
		DefinitionSchemaURI: DefinitionSchemaURI(schemaBytes),
		Approval:            Approval{ProfileDigest: identity.ProfileDigest, LockDigest: identity.LockDigest, SchemaDigests: identity.SchemaDigests},
	}
}

func newTestRegistry(t *testing.T) *Registry {
	t.Helper()
	registry, err := NewRegistry(context.Background(), registryConfig(t, EmbeddedCatalog{}))
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

// alteredSource serves the approved store with selected documents rewritten.
// rebind optionally repairs the catalog so a mutated document still matches
// its catalog digest, which is how a self-consistent forgery is modelled.
type alteredSource struct {
	inner    Source
	mutate   func(name string, raw []byte) []byte
	rebind   bool
	instruct func([]byte) []byte
}

func (s alteredSource) Catalog(ctx context.Context) ([]byte, error) {
	raw, err := s.inner.Catalog(ctx)
	if err != nil || !s.rebind {
		return raw, err
	}
	catalog, err := ParseCatalog(raw)
	if err != nil {
		return nil, err
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, err
	}
	entries := document["definitions"].([]any)
	for index, entry := range entries {
		value := entry.(map[string]any)
		name := value["document"].(string)
		original, err := s.inner.Document(ctx, name)
		if err != nil {
			return nil, err
		}
		value["documentDigest"] = DocumentDigest(s.mutate(name, original))
		entries[index] = value
	}
	if s.instruct != nil {
		for index, entry := range entries {
			value := entry.(map[string]any)
			name := value["instruction"].(string)
			original, err := s.inner.Document(ctx, name)
			if err != nil {
				return nil, err
			}
			value["instructionDigest"] = DocumentDigest(s.instruct(original))
			entries[index] = value
		}
	}
	document["definitions"] = entries
	_ = catalog
	return json.Marshal(document)
}

func (s alteredSource) Document(ctx context.Context, name string) ([]byte, error) {
	raw, err := s.inner.Document(ctx, name)
	if err != nil {
		return nil, err
	}
	if s.instruct != nil && strings.HasSuffix(name, ".instruction.txt") {
		return s.instruct(raw), nil
	}
	if s.mutate != nil {
		return s.mutate(name, raw), nil
	}
	return raw, nil
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
	mutate := func(name string, raw []byte) []byte {
		if !strings.HasSuffix(name, ".json") {
			return raw
		}
		return []byte(strings.Replace(string(raw), `"turnLimit": 16`, `"turnLimit": 17`, 1))
	}
	// Tampering alone is caught by the approved catalog binding.
	if _, err := NewRegistry(context.Background(), registryConfig(t, alteredSource{inner: EmbeddedCatalog{}, mutate: mutate})); err == nil {
		t.Fatal("tampered definition content must fail registry construction")
	}
	// Tampering that also rewrites the catalog digest is still caught,
	// because the frozen identity digest no longer matches the content.
	if _, err := NewRegistry(context.Background(), registryConfig(t, alteredSource{inner: EmbeddedCatalog{}, mutate: mutate, rebind: true})); err == nil {
		t.Fatal("self-consistent forged definition content must fail registry construction")
	}
}

func TestRegistryRejectsInstructionDigestMismatch(t *testing.T) {
	instruct := func(raw []byte) []byte { return append(append([]byte(nil), raw...), byte(' ')) }
	if _, err := NewRegistry(context.Background(), registryConfig(t, alteredSource{inner: EmbeddedCatalog{}, instruct: instruct})); err == nil {
		t.Fatal("tampered instruction bytes must fail registry construction")
	}
	// Rebinding the catalog to the tampered instruction still fails: the
	// definition's own pinned prompt digest no longer matches.
	identity := func(name string, raw []byte) []byte { return raw }
	if _, err := NewRegistry(context.Background(), registryConfig(t, alteredSource{inner: EmbeddedCatalog{}, mutate: identity, instruct: instruct, rebind: true})); err == nil {
		t.Fatal("self-consistent forged instruction bytes must fail registry construction")
	}
}

func TestRegistryRejectsACatalogBoundToADifferentApprovedBoundary(t *testing.T) {
	cfg := registryConfig(t, EmbeddedCatalog{})
	cfg.Approval.LockDigest = "sha256:" + strings.Repeat("0", 64)
	if _, err := NewRegistry(context.Background(), cfg); err == nil {
		t.Fatal("a catalog bound to a different canonical lock must fail registry construction")
	}
	cfg = registryConfig(t, EmbeddedCatalog{})
	cfg.Approval.ProfileDigest = "sha256:" + strings.Repeat("0", 64)
	if _, err := NewRegistry(context.Background(), cfg); err == nil {
		t.Fatal("a catalog bound to a different canonical profile must fail registry construction")
	}
	cfg = registryConfig(t, EmbeddedCatalog{})
	cfg.Approval.SchemaDigests = nil
	if _, err := NewRegistry(context.Background(), cfg); err == nil {
		t.Fatal("an unavailable approved contract identity must fail registry construction")
	}
}

func TestRegistryRejectsReferencedMaterialThatIsNotApproved(t *testing.T) {
	forged := "sha256:" + strings.Repeat("1", 64)
	for _, replaced := range []string{
		"sha256:c7a007e60d62331f77dbaa17cbc1c1945ce4fe061130c082adc658770eadd879",
		"sha256:819819ef4b7a473288ce0e0116410b5fb0491a754b38ea4cc424bf3266a6f57c",
		"sha256:80ca0c4751b2df4cbe5b68642ea75b183c212b8fa002823df174c5ddb7e32a80",
		"sha256:e653a85c2922d75464275bc15840a97dafd6f1de3d6faefec9c9ba65e933e710",
		"sha256:ae244db518fe7b181990406994ff42623cfebe97756e4b073fc9ea3df83b8fb0",
	} {
		mutate := func(name string, raw []byte) []byte {
			if !strings.HasPrefix(name, "definition.") || !strings.HasSuffix(name, ".json") {
				return raw
			}
			return []byte(strings.Replace(string(raw), replaced, forged, 1))
		}
		if _, err := NewRegistry(context.Background(), registryConfig(t, alteredSource{inner: EmbeddedCatalog{}, mutate: mutate, rebind: true})); err == nil {
			t.Fatalf("a definition pinning unapproved material (%s) must fail registry construction", replaced)
		}
	}
}

func TestRegistryRequiresSchemaValidDefinitions(t *testing.T) {
	tampered := alteredSource{inner: EmbeddedCatalog{}, rebind: true, mutate: func(name string, raw []byte) []byte {
		if !strings.HasPrefix(name, "definition.") || !strings.HasSuffix(name, ".json") {
			return raw
		}
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
	registry := newTestRegistry(t)
	for _, approved := range registry.Definitions() {
		raw := approved.Raw
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
