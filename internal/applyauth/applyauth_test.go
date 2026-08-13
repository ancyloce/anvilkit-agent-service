package applyauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	contractguard "github.com/ancyloce/anvilkit-agent-service/internal/contracts"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
)

var authNow = time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)

type fixedClock struct{ value time.Time }

func (c fixedClock) Now() time.Time { return c.value }

type fixedIDs struct{ value AuthorizationID }

func (i fixedIDs) AuthorizationID() (AuthorizationID, error) { return i.value, nil }

type fixedAuthority struct {
	proof Proof
	err   error
}

func (a *fixedAuthority) Resolve(context.Context, Command) (Proof, error) { return a.proof, a.err }

type failingAudit struct{}

func (failingAudit) Record(context.Context, AuditRecord) error { return errors.New("disk unavailable") }

func binding() Binding {
	digest := "sha256:" + strings.Repeat("a", 64)
	return Binding{RunID: "run-01", ActionDigest: digest, ArtifactDigest: "sha256:" + strings.Repeat("b", 64), Target: Target{Type: "page", ID: "page-01", WorkspaceID: "workspace-01"}, BaseRevision: "revision-01", ActorID: "actor-01", WorkspaceID: "workspace-01", ApprovalVersion: 7, ContractBOMDigest: "sha256:" + strings.Repeat("c", 64), PolicyDigest: "sha256:" + strings.Repeat("d", 64)}
}

func issuer(t *testing.T, authority *fixedAuthority, audit Audit, ring *MemoryKeyRing) *IssuerService {
	t.Helper()
	service, err := New(authority, fixedIDs{"authorization-01"}, ring, audit, fixedClock{authNow}, 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func TestIssueDerivesCanonicalFullBindingAndAuditsBeforeReturn(t *testing.T) {
	current := binding()
	authority := &fixedAuthority{proof: Proof{Approved: current, Current: current, ApprovalCurrent: true, ArtifactEligible: true}}
	ring, err := NewMemoryKeyRing("urn:anvilkit:key:apply-2026-08-a")
	if err != nil {
		t.Fatal(err)
	}
	audit := &MemoryAudit{}
	issued, err := issuer(t, authority, audit, ring).Issue(context.Background(), Command{WorkspaceID: "workspace-01", ProjectID: "project-01", RunID: "run-01", ApprovalRequestID: "approval-01", ArtifactID: "artifact-01"})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := Verify(context.Background(), issued.Compact, ring, authNow.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if verified.ActionDigest != current.ActionDigest || verified.ArtifactDigest != current.ArtifactDigest || verified.ApprovalVersion != 7 || verified.Audience != Audience || verified.AuthorizationID != "authorization-01" {
		t.Fatalf("full binding was not signed: %#v", verified)
	}
	if len(audit.Records) != 1 || audit.Records[0].TokenDigest == "" || audit.Records[0].PayloadDigest == "" {
		t.Fatalf("issuance audit missing: %#v", audit.Records)
	}
	payloadBytes, _ := json.Marshal(verified)
	guard, err := contractguard.NewGuard("../..")
	if err != nil {
		t.Fatal(err)
	}
	if findings := guard.Validate(context.Background(), contractguard.PagixOut, "anvilkit://schema/apply-authorization.v1@1.0.0?digest=sha256:67ce757f4792deccb1fc6c442611bfed2fff76aa1cac39ad1aa5ff70eddf97a3", payloadBytes); len(findings) != 0 {
		t.Fatalf("authorization payload violates pinned contract: %#v", findings)
	}
	parts := strings.Split(issued.Compact, ".")
	headerBytes, _ := base64.RawURLEncoding.DecodeString(parts[0])
	var header map[string]any
	_ = json.Unmarshal(headerBytes, &header)
	if !reflect.DeepEqual(header, map[string]any{"alg": "EdDSA", "kid": "urn:anvilkit:key:apply-2026-08-a", "typ": Type}) {
		t.Fatalf("wrong compact profile: %s", headerBytes)
	}
}

func TestIssuanceFailsClosedWithoutAuthoritativeTime(t *testing.T) {
	value := binding()
	authority := &fixedAuthority{proof: Proof{Approved: value, Current: value, ApprovalCurrent: true, ArtifactEligible: true}}
	ring, _ := NewMemoryKeyRing("urn:anvilkit:key:apply-time")
	service, _ := New(authority, fixedIDs{"authorization-time"}, ring, &MemoryAudit{}, fixedClock{}, time.Minute)
	if _, err := service.Issue(context.Background(), Command{WorkspaceID: "workspace-01", ProjectID: "project-01", RunID: "run-01", ApprovalRequestID: "approval-01", ArtifactID: "artifact-01"}); err == nil {
		t.Fatal("authorization issued without authoritative time")
	}
}

func TestIssueFailsClosedOnEveryBindingDrift(t *testing.T) {
	base := binding()
	cases := map[string]func(*Binding){
		"artifact": func(v *Binding) { v.ArtifactDigest = "sha256:" + strings.Repeat("e", 64) },
		"action":   func(v *Binding) { v.ActionDigest = "sha256:" + strings.Repeat("e", 64) },
		"revision": func(v *Binding) { v.BaseRevision = "revision-02" },
		"decision": func(v *Binding) { v.ApprovalVersion++ },
		"policy":   func(v *Binding) { v.PolicyDigest = "sha256:" + strings.Repeat("e", 64) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			current := base
			mutate(&current)
			authority := &fixedAuthority{proof: Proof{Approved: base, Current: current, ApprovalCurrent: true, ArtifactEligible: true}}
			ring, _ := NewMemoryKeyRing("urn:anvilkit:key:apply-2026-08-a")
			_, err := issuer(t, authority, &MemoryAudit{}, ring).Issue(context.Background(), Command{WorkspaceID: "workspace-01", ProjectID: "project-01", RunID: "run-01", ApprovalRequestID: "approval-01", ArtifactID: "artifact-01"})
			var details problem.Details
			if !errors.As(err, &details) || details.Code != string(problem.CodeApplyAuthorizationDenied) {
				t.Fatalf("drift was not denied: %v", err)
			}
		})
	}
}

func TestRotationOverlapRevocationExpiryAndSubstitution(t *testing.T) {
	value := binding()
	authority := &fixedAuthority{proof: Proof{Approved: value, Current: value, ApprovalCurrent: true, ArtifactEligible: true}}
	ring, _ := NewMemoryKeyRing("urn:anvilkit:key:apply-2026-08-a")
	first, err := issuer(t, authority, &MemoryAudit{}, ring).Issue(context.Background(), Command{WorkspaceID: "workspace-01", ProjectID: "project-01", RunID: "run-01", ApprovalRequestID: "approval-01", ArtifactID: "artifact-01"})
	if err != nil {
		t.Fatal(err)
	}
	if err := ring.Rotate("urn:anvilkit:key:apply-2026-08-b"); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(context.Background(), first.Compact, ring, authNow.Add(time.Minute)); err != nil {
		t.Fatalf("rotation overlap rejected old key: %v", err)
	}
	ring.Revoke(first.KeyID)
	if _, err := Verify(context.Background(), first.Compact, ring, authNow.Add(time.Minute)); err == nil {
		t.Fatal("revoked key accepted")
	}
	ring2, _ := NewMemoryKeyRing("urn:anvilkit:key:apply-2026-08-c")
	second, _ := issuer(t, authority, &MemoryAudit{}, ring2).Issue(context.Background(), Command{WorkspaceID: "workspace-01", ProjectID: "project-01", RunID: "run-01", ApprovalRequestID: "approval-01", ArtifactID: "artifact-01"})
	if _, err := Verify(context.Background(), second.Compact, ring2, authNow.Add(3*time.Minute)); err == nil {
		t.Fatal("expired authorization accepted")
	}
	parts := strings.Split(second.Compact, ".")
	parts[1] = strings.TrimSuffix(parts[1], "A") + "A"
	if _, err := Verify(context.Background(), strings.Join(parts, "."), ring2, authNow.Add(time.Minute)); err == nil {
		t.Fatal("substituted authorization accepted")
	}
}

func TestAuditFailureAndCallerAuthoredPayloadCannotEscape(t *testing.T) {
	value := binding()
	authority := &fixedAuthority{proof: Proof{Approved: value, Current: value, ApprovalCurrent: true, ArtifactEligible: true}}
	ring, _ := NewMemoryKeyRing("urn:anvilkit:key:apply-2026-08-a")
	serializedRing, marshalErr := json.Marshal(ring)
	if marshalErr != nil || strings.Contains(string(serializedRing), "private") || len(serializedRing) > 2 {
		t.Fatalf("private signing state escaped serialization: %s %v", serializedRing, marshalErr)
	}
	_, err := issuer(t, authority, failingAudit{}, ring).Issue(context.Background(), Command{WorkspaceID: "workspace-01", ProjectID: "project-01", RunID: "run-01", ApprovalRequestID: "approval-01", ArtifactID: "artifact-01"})
	if err == nil {
		t.Fatal("authorization escaped without durable audit")
	}
	typ := reflect.TypeOf(Command{})
	for index := 0; index < typ.NumField(); index++ {
		if typ.Field(index).Type == reflect.TypeOf(Payload{}) || strings.Contains(strings.ToLower(typ.Field(index).Name), "payload") || strings.Contains(strings.ToLower(typ.Field(index).Name), "jws") {
			t.Fatalf("caller-authored authorization surface exists: %s", typ.Field(index).Name)
		}
	}
}
