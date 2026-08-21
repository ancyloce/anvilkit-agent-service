package events

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/auth"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
)

// A clearance nobody granted cannot be presented. The only evidence authority
// a caller can build without minting is the zero value, and it discloses
// nothing: there is no field to set, no constructor to call, and no default to
// fall back to.
func TestForgedEvidenceClearanceDisclosesNothing(t *testing.T) {
	store := NewMemoryEvidence()
	restricted := validEvidence("evidence.restricted")
	restricted.Classification = "restricted"
	if _, err := store.AppendEvidence(context.Background(), restricted); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReadEvidence(context.Background(), EvidenceAuthority{}, "run.1", 10); err == nil {
		t.Fatal("an unminted evidence authority was allowed to read")
	}
	// A caller declaring the highest purpose still reads only what current
	// authority grants: the clearance comes from the authority source, never
	// from the request.
	claimed := mintAuthority(t, operatorScope(), "read everything restricted", grantingAuthority("agent-operator", "public", "internal"))
	if claimed.Clearance() != "internal" {
		t.Fatalf("minted clearance=%q, want the granted internal", claimed.Clearance())
	}
	records, err := store.ReadEvidence(context.Background(), claimed, "run.1", 10)
	if err != nil || len(records) != 0 {
		t.Fatalf("records=%d err=%v, want the restricted fact withheld", len(records), err)
	}
}

// Clearance bounds disclosure by data classification, and the bound is
// applied to the authority in force rather than to the one that was minted.
func TestInsufficientClearanceWithholdsHigherClassifications(t *testing.T) {
	store := NewMemoryEvidence()
	restricted := validEvidence("evidence.restricted")
	restricted.Classification = "restricted"
	confidential := validEvidence("evidence.confidential")
	confidential.Classification = "confidential"
	for _, fact := range []Evidence{validEvidence("evidence.internal"), confidential, restricted} {
		if _, err := store.AppendEvidence(context.Background(), fact); err != nil {
			t.Fatal(err)
		}
	}
	cleared := mintAuthority(t, operatorScope(), "incident-debug", grantingAuthority("agent-operator", "public", "internal", "confidential"))
	records, err := store.ReadEvidence(context.Background(), cleared, "run.1", 10)
	if err != nil || len(records) != 2 {
		t.Fatalf("records=%d err=%v, want the two facts at or below confidential", len(records), err)
	}
	for _, record := range records {
		if record.Classification == "restricted" {
			t.Fatalf("a restricted fact was disclosed to a confidential clearance: %+v", record)
		}
	}
}

// Authority is re-read at disclosure, never trusted from minting time: an
// accessor whose authority is withdrawn between the two reads nothing.
func TestRevokedAuthorityStopsDisclosingOnTheNextRead(t *testing.T) {
	store := NewMemoryEvidence()
	if _, err := store.AppendEvidence(context.Background(), validEvidence("evidence.1")); err != nil {
		t.Fatal(err)
	}
	source := grantingAuthority("agent-operator", "restricted")
	accessor := mintAuthority(t, operatorScope(), "incident-debug", source)
	if records, err := store.ReadEvidence(context.Background(), accessor, "run.1", 10); err != nil || len(records) != 1 {
		t.Fatalf("records=%d err=%v, want the recorded fact", len(records), err)
	}
	source.Revoke()
	if _, err := store.ReadEvidence(context.Background(), accessor, "run.1", 10); err == nil {
		t.Fatal("a revoked authority was still allowed to read evidence")
	}
	source.Restore()
	if records, err := store.ReadEvidence(context.Background(), accessor, "run.1", 10); err != nil || len(records) != 1 {
		t.Fatalf("restored records=%d err=%v, want the recorded fact again", len(records), err)
	}
}

// A read reaches exactly the tenant the accessor is authorized for. The scope
// is not a parameter a caller supplies, so a cross-tenant read is not a shape
// the interface can express — an accessor authorized elsewhere simply finds
// nothing here.
func TestCrossTenantEvidenceReadReachesNothing(t *testing.T) {
	store := NewMemoryEvidence()
	if _, err := store.AppendEvidence(context.Background(), validEvidence("evidence.1")); err != nil {
		t.Fatal(err)
	}
	foreign := operatorScope()
	foreign.WorkspaceID = "workspace.other"
	accessor := mintAuthority(t, foreign, "incident-debug", grantingAuthority("agent-operator", "restricted"))
	if accessor.Scope().WorkspaceID != "workspace.other" {
		t.Fatalf("minted scope=%+v, want the accessor's own workspace", accessor.Scope())
	}
	records, err := store.ReadEvidence(context.Background(), accessor, "run.1", 10)
	if err != nil || len(records) != 0 {
		t.Fatalf("records=%d err=%v, want none", len(records), err)
	}
}

// An actor the scope's subject register admits under no role cannot mint an
// evidence authority at all: evidence disclosure requires an admitted role,
// not merely an authenticated request.
func TestEvidenceAuthorityRequiresAnAdmittedRole(t *testing.T) {
	if _, err := MintEvidenceAuthority(context.Background(), verifiedRequest{scope: operatorScope()}, grantingAuthority("", "restricted"), authClaims(), "incident-debug"); err == nil {
		t.Fatal("an actor with no admitted role minted an evidence authority")
	}
	if _, err := MintEvidenceAuthority(context.Background(), verifiedRequest{scope: operatorScope()}, grantingAuthority("agent-operator"), authClaims(), "incident-debug"); err == nil {
		t.Fatal("an actor granted no data classification minted an evidence authority")
	}
}

// Evidence idempotency is decided on the stable identity: an identical replay
// answers with the original sequence, and the same identifier carrying a
// different fact is a typed conflict rather than a silent answer with someone
// else's record. The controlled store and the durable store apply the same
// rule, so a test that passes here is testing the real contract.
func TestEvidenceReplayConvergesAndDivergenceConflicts(t *testing.T) {
	store := NewMemoryEvidence()
	fact := validEvidence("evidence.1")
	first, err := store.AppendEvidence(context.Background(), fact)
	if err != nil || first != 1 {
		t.Fatalf("first append sequence=%d err=%v", first, err)
	}
	if replayed, err := store.AppendEvidence(context.Background(), fact); err != nil || replayed != first {
		t.Fatalf("identical replay sequence=%d err=%v, want the original %d", replayed, err, first)
	}
	divergent := map[string]func(Evidence) Evidence{
		"different payload":        func(v Evidence) Evidence { v.Payload = map[string]string{"authorizationId": "other"}; return v },
		"different run":            func(v Evidence) Evidence { v.RunID = "run.2"; return v },
		"different type":           func(v Evidence) Evidence { v.Type = "domain.effect-confirmed"; return v },
		"different classification": func(v Evidence) Evidence { v.Classification = "confidential"; return v },
		"different retention":      func(v Evidence) Evidence { v.Retention = RetentionSecurity; return v },
		"different occurrence":     func(v Evidence) Evidence { v.OccurredAt = v.OccurredAt.Add(time.Millisecond); return v },
	}
	for name, mutate := range divergent {
		_, err := store.AppendEvidence(context.Background(), mutate(fact))
		if err == nil {
			t.Fatalf("%s under a reused evidence identity was accepted", name)
		}
		var details problem.Details
		if !errors.As(err, &details) || details.Code != string(problem.CodeIdempotencyConflict) {
			t.Fatalf("%s conflict = %v, want a typed IDEMPOTENCY_CONFLICT", name, err)
		}
	}
	// The recorded fact is untouched by every refused divergence.
	if records, err := store.ReadEvidence(context.Background(), readAuthority(t), "run.1", 10); err != nil || len(records) != 1 || records[0].Sequence != first {
		t.Fatalf("records=%d err=%v, want exactly the original fact", len(records), err)
	}
}

// The lookup a producer converges on reports the recorded fact's identity and
// times without disclosing anything, and reports absence rather than guessing.
func TestRecordedEvidenceLookupAnswersIdentityAndTimes(t *testing.T) {
	store := NewMemoryEvidence()
	fact := validEvidence("evidence.1")
	if _, err := store.AppendEvidence(context.Background(), fact); err != nil {
		t.Fatal(err)
	}
	scope := Scope{WorkspaceID: fact.WorkspaceID, ProjectID: fact.ProjectID}
	record, present, err := store.RecordedEvidence(context.Background(), scope, fact.EvidenceID)
	if err != nil || !present || record.Sequence != 1 || !record.OccurredAt.Equal(fact.OccurredAt) {
		t.Fatalf("lookup record=%+v present=%v err=%v", record, present, err)
	}
	if _, present, err := store.RecordedEvidence(context.Background(), scope, "evidence.absent"); err != nil || present {
		t.Fatalf("absent lookup present=%v err=%v, want absence reported plainly", present, err)
	}
	elsewhere := Scope{WorkspaceID: "workspace.other", ProjectID: fact.ProjectID}
	if _, present, err := store.RecordedEvidence(context.Background(), elsewhere, fact.EvidenceID); err != nil || present {
		t.Fatalf("cross-tenant lookup present=%v err=%v, want absence", present, err)
	}
}

// authClaims is the verified claim set these tests mint under. The claims
// carry no clearance by construction; the verifier stands in for the real
// authorization, and the clearance comes from current authority.
func authClaims() auth.Claims { return auth.Claims{} }
