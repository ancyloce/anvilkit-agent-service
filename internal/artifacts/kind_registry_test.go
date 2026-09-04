package artifacts

import (
	"encoding/json"
	"os"
	"regexp"
	"sort"
	"testing"

	contractschema "github.com/ancyloce/anvilkit-agent-service/contracts/generated/schema"
)

// The artifact-kind registry is the authority for what an artifact may be
// (CAT-FR-003). check-agent-contracts.ts holds the canonical AgentArtifact
// schema enum to the registry; this test holds this service's Kind set and the
// database CHECK constraint to that pinned schema, so a kind added in one
// place and not the others fails here before it can merge (plan 0009 C4-04).

var everyKind = []Kind{
	CompiledContext, TargetSnapshot, AgentPlan, WorkerResult, ValidationReport,
	CatalogSnapshot, PageCandidate, PagePreviewTask, PagePreviewResult, ComponentDesign,
	ComponentIntent, ComponentIR,
}

func pinnedSchemaKinds(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile("../../contracts/agent/schemas/agent-artifact.schema.json")
	if err != nil {
		t.Fatalf("read pinned schema: %v", err)
	}
	var document struct {
		Properties struct {
			Kind struct {
				Enum []string `json:"enum"`
			} `json:"kind"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatalf("decode pinned schema: %v", err)
	}
	return document.Properties.Kind.Enum
}

func sorted(values []string) []string {
	out := append([]string(nil), values...)
	sort.Strings(out)
	return out
}

func TestKindSetMirrorsPinnedSchemaEnum(t *testing.T) {
	want := sorted(pinnedSchemaKinds(t))
	got := make([]string, 0, len(everyKind))
	for _, kind := range everyKind {
		if !ValidKind(kind) {
			t.Errorf("ValidKind(%q) = false for a declared kind", kind)
		}
		var decoded contractschema.AgentArtifactKind
		if err := json.Unmarshal([]byte(`"`+string(kind)+`"`), &decoded); err != nil {
			t.Errorf("generated binding rejects %q: %v", kind, err)
		}
		got = append(got, string(kind))
	}
	if g, w := sorted(got), want; !equal(g, w) {
		t.Fatalf("service kinds %v differ from the pinned schema enum %v", g, w)
	}
	if ValidKind("not-a-kind") {
		t.Fatal("ValidKind admits a value outside the vocabulary")
	}
}

func TestArtifactKindCheckConstraintMirrorsKindSet(t *testing.T) {
	raw, err := os.ReadFile("../persistence/migrations/0033_artifact_kind_registry_mirror.up.sql")
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	constraint := regexp.MustCompile(`kind IN \(([^)]*)\)`).FindStringSubmatch(string(raw))
	if constraint == nil {
		t.Fatal("migration declares no kind CHECK list")
	}
	var listed []string
	for _, match := range regexp.MustCompile(`'([a-z-]+)'`).FindAllStringSubmatch(constraint[1], -1) {
		listed = append(listed, match[1])
	}
	if g, w := sorted(listed), sorted(pinnedSchemaKinds(t)); !equal(g, w) {
		t.Fatalf("database CHECK list %v differs from the pinned schema enum %v", g, w)
	}
}

func equal(left, right []string) bool {
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
