package events

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/auth"
	"github.com/ancyloce/anvilkit-agent-service/internal/authority"
	"github.com/ancyloce/anvilkit-agent-service/internal/runs"
)

func validEvidence(id string) Evidence {
	return Evidence{
		WorkspaceID: "workspace.1",
		ProjectID:   "project.1",
		RunID:       "run.1",
		EvidenceID:  id,
		Type:        "commit.authorization-issued",
		OccurredAt:  time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC),
		Producer: EvidenceProducer{
			Component:         "agent-executor",
			DefinitionDigest:  "sha256:" + strings.Repeat("d", 64),
			PolicyDigest:      "sha256:" + strings.Repeat("a", 64),
			ContractBOMDigest: "sha256:" + strings.Repeat("c", 64),
		},
		Classification: "internal",
		Retention:      "audit",
		Traceparent:    "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01",
		Payload:        map[string]string{"authorizationId": "authorization.1"},
	}
}

// Evidence sequences are independent, per-run, and idempotent by evidence
// identity: a durable-operation replay converges on the recorded sequence.
func TestEvidenceSequencesAreIndependentAndIdempotent(t *testing.T) {
	store := NewMemoryEvidence()
	first, err := store.AppendEvidence(context.Background(), validEvidence("evidence.1"))
	if err != nil || first != 1 {
		t.Fatalf("first append sequence=%d err=%v", first, err)
	}
	second, err := store.AppendEvidence(context.Background(), validEvidence("evidence.2"))
	if err != nil || second != 2 {
		t.Fatalf("second append sequence=%d err=%v", second, err)
	}
	replayed, err := store.AppendEvidence(context.Background(), validEvidence("evidence.1"))
	if err != nil || replayed != 1 {
		t.Fatalf("replayed append sequence=%d err=%v, want the recorded 1", replayed, err)
	}
	other := validEvidence("evidence.other-run")
	other.RunID = "run.2"
	otherSequence, err := store.AppendEvidence(context.Background(), other)
	if err != nil || otherSequence != 1 {
		t.Fatalf("independent run sequence=%d err=%v", otherSequence, err)
	}
}

// verifiedRequest stands in for the service's request-authority verification.
// It returns only the tenant scope a caller proved; it cannot express a
// clearance, which is the point — clearance comes from current authority.
type verifiedRequest struct {
	scope runs.Scope
	err   error
}

func (v verifiedRequest) Authorize(context.Context, auth.Claims, auth.Operation) (runs.Scope, error) {
	return v.scope, v.err
}

// grantingAuthority is a current-authority source that admits the actor under
// a role and grants the named data classes, so a test states the authority in
// force rather than the answer it wants.
func grantingAuthority(role string, classes ...string) *authority.Static {
	return authority.NewStatic(authority.Current{
		Definition:       json.RawMessage(`{"definitionId":"definition.1"}`),
		ContractBOM:      json.RawMessage(`{"bomDigest":"sha256:1"}`),
		Policy:           json.RawMessage(`{"policyId":"policy.1"}`),
		Budget:           json.RawMessage(`{"kind":"AgentBudget"}`),
		WorkspaceActive:  true,
		ActorActive:      true,
		PermissionActive: true,
		PolicyActive:     true,
		ActorRole:        role,
		ActorGrants:      authority.ActorAuthority{DataClasses: classes},
	})
}

// mintAuthority resolves an evidence read authority the way production does.
// Every test that reads evidence goes through it, so no test can hold an
// authority the composition could not have issued.
func mintAuthority(t *testing.T, scope runs.Scope, purpose string, source *authority.Static) EvidenceAuthority {
	t.Helper()
	value, err := MintEvidenceAuthority(context.Background(), verifiedRequest{scope: scope}, source, auth.Claims{}, purpose)
	if err != nil {
		t.Fatalf("mint evidence authority: %v", err)
	}
	return value
}

// operatorScope is the tenant and actor the controlled evidence tests read as.
func operatorScope() runs.Scope {
	return runs.Scope{WorkspaceID: "workspace.1", ProjectID: "project.1", ActorID: "operator"}
}

// readAuthority is the fully cleared accessor the controlled store admits, so
// a test that needs a permitted read states one explicitly.
func readAuthority(t *testing.T) EvidenceAuthority {
	t.Helper()
	return mintAuthority(t, operatorScope(), "incident-debug", grantingAuthority("agent-operator", "public", "internal", "confidential", "restricted"))
}

// Evidence reads are access-audited: an anonymous or purposeless read is not
// a mode.
func TestEvidenceReadsRequireAccessorAndPurpose(t *testing.T) {
	store := NewMemoryEvidence()
	if _, err := store.AppendEvidence(context.Background(), validEvidence("evidence.1")); err != nil {
		t.Fatal(err)
	}
	anonymous := operatorScope()
	anonymous.ActorID = ""
	if _, err := MintEvidenceAuthority(context.Background(), verifiedRequest{scope: anonymous}, grantingAuthority("agent-operator", "restricted"), auth.Claims{}, "incident-debug"); err == nil {
		t.Fatal("an anonymous evidence read was allowed")
	}
	if _, err := MintEvidenceAuthority(context.Background(), verifiedRequest{scope: operatorScope()}, grantingAuthority("agent-operator", "restricted"), auth.Claims{}, ""); err == nil {
		t.Fatal("a purposeless evidence read was allowed")
	}
	records, err := store.ReadEvidence(context.Background(), readAuthority(t), "run.1", 10)
	if err != nil || len(records) != 1 {
		t.Fatalf("audited read records=%d err=%v", len(records), err)
	}
	if len(store.Reads) != 1 || store.Reads[0] != "operator:incident-debug" {
		t.Fatalf("access audit=%v", store.Reads)
	}
}

// An evidence read reaches exactly the tenant the accessor is authorized for,
// never a neighbouring one, and never a classification above the accessor's
// clearance. Both denials are silent by design: an unauthorized reader learns
// nothing about what exists.
func TestEvidenceReadsAreTenantScopedAndClearanceBound(t *testing.T) {
	store := NewMemoryEvidence()
	restricted := validEvidence("evidence.restricted")
	restricted.Classification = "restricted"
	for _, fact := range []Evidence{validEvidence("evidence.1"), restricted} {
		if _, err := store.AppendEvidence(context.Background(), fact); err != nil {
			t.Fatal(err)
		}
	}
	neighbourScope := operatorScope()
	neighbourScope.WorkspaceID = "workspace.2"
	neighbour := mintAuthority(t, neighbourScope, "incident-debug", grantingAuthority("agent-operator", "restricted"))
	if records, err := store.ReadEvidence(context.Background(), neighbour, "run.1", 10); err != nil || len(records) != 0 {
		t.Fatalf("a neighbouring workspace read records=%d err=%v, want none", len(records), err)
	}
	siblingScope := operatorScope()
	siblingScope.ProjectID = "project.2"
	sibling := mintAuthority(t, siblingScope, "incident-debug", grantingAuthority("agent-operator", "restricted"))
	if records, err := store.ReadEvidence(context.Background(), sibling, "run.1", 10); err != nil || len(records) != 0 {
		t.Fatalf("a sibling project read records=%d err=%v, want none", len(records), err)
	}
	limited := mintAuthority(t, operatorScope(), "incident-debug", grantingAuthority("agent-operator", "public", "internal"))
	records, err := store.ReadEvidence(context.Background(), limited, "run.1", 10)
	if err != nil || len(records) != 1 || records[0].EvidenceID != "evidence.1" {
		t.Fatalf("clearance-bound read records=%d err=%v, want only the internal fact", len(records), err)
	}
	if _, err := MintEvidenceAuthority(context.Background(), verifiedRequest{scope: operatorScope()}, grantingAuthority("agent-operator", "unbounded"), auth.Claims{}, "incident-debug"); err == nil {
		t.Fatal("an unregistered clearance was accepted")
	}
}

// Retention bounds disclosure: evidence past its governed window is no longer
// returned, while the record itself stays immutable so its integrity digest
// keeps attesting the document it was computed over.
func TestEvidencePastItsRetentionWindowIsNoLongerDisclosed(t *testing.T) {
	recorded := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	now := recorded
	store := NewMemoryEvidence(WithEvidenceClock(func() time.Time { return now }))
	operational := validEvidence("evidence.operational")
	operational.Retention = "operational"
	for _, fact := range []Evidence{operational, validEvidence("evidence.audit")} {
		if _, err := store.AppendEvidence(context.Background(), fact); err != nil {
			t.Fatal(err)
		}
	}
	operationalWindow, err := RetentionWindow("operational")
	if err != nil {
		t.Fatal(err)
	}
	now = recorded.Add(operationalWindow).Add(time.Second)
	records, err := store.ReadEvidence(context.Background(), readAuthority(t), "run.1", 10)
	if err != nil || len(records) != 1 || records[0].EvidenceID != "evidence.audit" {
		t.Fatalf("post-window read records=%d err=%v, want only the audit-retained fact", len(records), err)
	}
	auditWindow, err := RetentionWindow("audit")
	if err != nil {
		t.Fatal(err)
	}
	now = recorded.Add(auditWindow).Add(time.Second)
	if records, err := store.ReadEvidence(context.Background(), readAuthority(t), "run.1", 10); err != nil || len(records) != 0 {
		t.Fatalf("expired read records=%d err=%v, want none", len(records), err)
	}
}

// The evidence contract fails closed: unregistered namespaces,
// classifications, retention categories, and prohibited payload content never
// reach storage.
func TestEvidenceValidationFailsClosed(t *testing.T) {
	unregistered := validEvidence("evidence.bad-type")
	unregistered.Type = "run.state-changed"
	if err := ValidateEvidence(unregistered); err == nil {
		t.Fatal("a public event type was accepted as an evidence namespace")
	}
	classified := validEvidence("evidence.bad-class")
	classified.Classification = "open"
	if err := ValidateEvidence(classified); err == nil {
		t.Fatal("an unregistered classification was accepted")
	}
	retained := validEvidence("evidence.bad-retention")
	retained.Retention = "forever"
	if err := ValidateEvidence(retained); err == nil {
		t.Fatal("an unregistered retention category was accepted")
	}
	leaking := validEvidence("evidence.leak")
	leaking.Payload = map[string]string{"note": "the system prompt said"}
	if err := ValidateEvidence(leaking); err == nil {
		t.Fatal("prohibited payload content was accepted")
	}
}

// Rendered evidence and rendered public events are different kinds: one can
// never deserialize as the other.
func TestEvidenceAndPublicEventsAreDisjointShapes(t *testing.T) {
	rendered, err := RenderEvidence(validEvidence("evidence.1"), 1, time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateBytes(rendered, DefaultBounds()); err == nil {
		t.Fatal("rendered evidence validated as a public event")
	}
	if !strings.Contains(string(rendered), `"kind":"AgentEvidence"`) || !strings.Contains(string(rendered), `"evidenceSequence":1`) {
		t.Fatalf("rendered evidence lacks its kind or sequence: %s", rendered)
	}
}

// A public event type is refused as an evidence namespace by the registry
// check itself, not incidentally by the namespace pattern: the two lists stay
// independently enforced.
func TestPublicEventTypesAreRefusedAsEvidenceNamespaces(t *testing.T) {
	for _, public := range PublicEventTypes() {
		value := validEvidence("evidence.public-type")
		value.Type = public
		err := ValidateEvidence(value)
		if err == nil {
			t.Fatalf("%q was accepted as an evidence namespace", public)
		}
		if !strings.Contains(err.Error(), "public event type") {
			t.Fatalf("%q was refused for the wrong reason: %v", public, err)
		}
	}
}

// Evidence identities and correlation references must be identifiers the
// canonical contract accepts, so validation is a complete precondition of the
// contract rather than a looser sketch of it.
func TestEvidenceIdentitiesMustSatisfyTheCanonicalBounds(t *testing.T) {
	overlong := strings.Repeat("a", 129)
	cases := map[string]func(*Evidence){
		"overlong evidence identity": func(e *Evidence) { e.EvidenceID = overlong },
		"malformed run identity":     func(e *Evidence) { e.RunID = "run/1" },
		"overlong turn correlation":  func(e *Evidence) { e.TurnID = overlong },
		"malformed workflow":         func(e *Evidence) { e.WorkflowID = "workflow 1" },
		"malformed trace context":    func(e *Evidence) { e.Traceparent = "not-a-traceparent" },
		"missing policy digest":      func(e *Evidence) { e.Producer.PolicyDigest = "" },
	}
	for name, mutate := range cases {
		value := validEvidence("evidence.bounds")
		mutate(&value)
		if err := ValidateEvidence(value); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}

// Both stores bound a page identically, so a caller cannot get an unbounded
// read from one and a silently truncated page from the other.
func TestEvidencePagesAreBoundedIdentically(t *testing.T) {
	if BoundedEvidencePage(0) != MaximumEvidencePage || BoundedEvidencePage(-1) != MaximumEvidencePage {
		t.Fatal("a non-positive page request must resolve to the bounded maximum")
	}
	if BoundedEvidencePage(MaximumEvidencePage+1) != MaximumEvidencePage {
		t.Fatal("an oversized page request must resolve to the bounded maximum")
	}
	if BoundedEvidencePage(7) != 7 {
		t.Fatal("a bounded page request must be honoured")
	}
	store := NewMemoryEvidence()
	for index := 0; index < 5; index++ {
		if _, err := store.AppendEvidence(context.Background(), validEvidence("evidence."+strconv.Itoa(index))); err != nil {
			t.Fatal(err)
		}
	}
	full, err := store.ReadEvidence(context.Background(), readAuthority(t), "run.1", 0)
	if err != nil || len(full) != 5 {
		t.Fatalf("unbounded request records=%d err=%v", len(full), err)
	}
	page, err := store.ReadEvidence(context.Background(), readAuthority(t), "run.1", 2)
	if err != nil || len(page) != 2 {
		t.Fatalf("bounded request records=%d err=%v", len(page), err)
	}
	if err := ValidateEvidenceRun("run/1"); err == nil {
		t.Fatal("a malformed run identity was accepted by an evidence read")
	}
}

// The governed retention categories and the deadline derived from them are
// one authority: a store that filters per category reads the same list.
func TestRetentionCategoriesAndDerivedDeadlinesAreOneAuthority(t *testing.T) {
	categories := RetentionCategories()
	if len(categories) != 3 {
		t.Fatalf("registered retention categories=%v", categories)
	}
	recorded := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	cutoffs, err := RetentionCutoffs(recorded)
	if err != nil || len(cutoffs) != len(categories) {
		t.Fatalf("cutoffs=%v err=%v", cutoffs, err)
	}
	for _, category := range categories {
		window, err := RetentionWindow(category)
		if err != nil {
			t.Fatal(err)
		}
		deadline, err := DisclosureDeadline(recorded, category)
		if err != nil || !deadline.Equal(recorded.Add(window)) {
			t.Fatalf("%s deadline=%v err=%v", category, deadline, err)
		}
		if !cutoffs[category].Equal(recorded.Add(-window)) {
			t.Fatalf("%s cutoff=%v", category, cutoffs[category])
		}
	}
	if _, err := DisclosureDeadline(recorded, "forever"); err == nil {
		t.Fatal("an unregistered retention category yielded a deadline")
	}
}

// A clearance the scope shares with everything running in it is not this
// actor's clearance. Evidence is disclosed on what the subject register binds
// to the accessor personally, so a workspace-wide data-class grant admits
// nobody to internal evidence on its own.
func TestScopeWideDataClassesConferNoEvidenceClearance(t *testing.T) {
	material := json.RawMessage(`{"synthetic":true}`)
	shared := authority.NewStatic(authority.Current{
		Definition: material, ContractBOM: material, Policy: material, Budget: material,
		WorkspaceActive: true, ActorActive: true, PermissionActive: true, PolicyActive: true,
		ActorRole: "agent-operator",
		// Every dispatch grant the scope has, and nothing bound to the actor.
		Grants: authority.Grants{DataClasses: []string{"public", "internal", "confidential", "restricted"}},
	})
	if _, err := MintEvidenceAuthority(context.Background(), verifiedRequest{scope: operatorScope()}, shared, auth.Claims{}, "incident-debug"); err == nil {
		t.Fatal("the scope's shared data classes were read as the accessor's own clearance")
	}
}
