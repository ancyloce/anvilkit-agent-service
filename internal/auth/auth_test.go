package auth

import (
	"context"
	"testing"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
)

type fixedClock struct{ value time.Time }

func (c fixedClock) Now() time.Time { return c.value }

type mutableTrust struct{ key, subject, delegation bool }

func (t *mutableTrust) KeyActive(context.Context, string) (bool, error)     { return t.key, nil }
func (t *mutableTrust) SubjectActive(context.Context, string) (bool, error) { return t.subject, nil }
func (t *mutableTrust) DelegationActive(context.Context, string, string) (bool, error) {
	return t.delegation, nil
}

func TestEveryProtectedOperationDeclaresScopes(t *testing.T) {
	for _, operation := range ProtectedOperations() {
		if len(RequiredScopes(operation)) == 0 {
			t.Fatalf("operation %s is unscoped", operation)
		}
	}
}

func TestScopeByOperationAndWrongAudienceFailClosed(t *testing.T) {
	now := time.Unix(1000, 0)
	trust := &mutableTrust{true, true, true}
	validator, _ := NewValidator(Config{Issuers: []string{"issuer"}, Audience: "agent-service", MaximumClockSkew: time.Second}, trust, fixedClock{now})
	base := Claims{Verified: true, Source: SourceDelegated, Issuer: "issuer", Audience: "agent-service", Subject: "workload", ActorID: "actor", TenantID: "tenant", WorkspaceID: "workspace", ProjectID: "project", Purpose: "agent-run", KeyID: "key", Scopes: []string{ScopeRead, ScopeWrite, ScopeReviewer, ScopeIssuer}, ExpiresAt: now.Add(time.Minute), NotBefore: now.Add(-time.Minute)}
	for _, operation := range ProtectedOperations() {
		claims := base
		claims.Scopes = RequiredScopes(operation)
		if _, err := validator.Authorize(context.Background(), claims, operation); err != nil {
			t.Fatalf("operation %s rejected: %v", operation, err)
		}
		claims.Scopes = []string{"wrong"}
		assertCode(t, validator.Revalidate(context.Background(), claims, operation), problem.CodeAuthorizationDenied)
	}
	wrongAudience := base
	wrongAudience.Audience = "browser"
	assertCode(t, validator.Revalidate(context.Background(), wrongAudience, OpGetRun), problem.CodeAuthenticationInvalid)
}

func TestIssuerSubjectDelegationTimeAndTrustMatrix(t *testing.T) {
	now := time.Unix(1000, 0)
	baseTrust := &mutableTrust{true, true, true}
	validator, _ := NewValidator(Config{Issuers: []string{"issuer"}, Audience: "agent-service", MaximumClockSkew: time.Second}, baseTrust, fixedClock{now})
	base := Claims{Verified: true, Source: SourceDelegated, Issuer: "issuer", Audience: "agent-service", Subject: "workload", ActorID: "actor", TenantID: "tenant", WorkspaceID: "workspace", ProjectID: "project", Purpose: "purpose", KeyID: "key", Scopes: []string{ScopeRead}, ExpiresAt: now.Add(time.Minute), NotBefore: now.Add(-time.Minute)}
	cases := []Claims{func() Claims { c := base; c.Verified = false; return c }(), func() Claims { c := base; c.Source = SourceBrowser; return c }(), func() Claims { c := base; c.Issuer = "wrong"; return c }(), func() Claims { c := base; c.Subject = ""; return c }(), func() Claims { c := base; c.ExpiresAt = now.Add(-time.Minute); return c }(), func() Claims { c := base; c.NotBefore = now.Add(time.Minute); return c }()}
	for index, claims := range cases {
		if _, err := validator.Authorize(context.Background(), claims, OpGetRun); err == nil {
			t.Fatalf("case %d accepted", index)
		}
	}
	for name, trust := range map[string]*mutableTrust{"key": {false, true, true}, "subject": {true, false, true}, "delegation": {true, true, false}} {
		candidate, _ := NewValidator(Config{Issuers: []string{"issuer"}, Audience: "agent-service", MaximumClockSkew: time.Second}, trust, fixedClock{now})
		if _, err := candidate.Authorize(context.Background(), base, OpGetRun); err == nil {
			t.Fatalf("revoked %s accepted", name)
		}
	}
}

func TestBrowserClaimsNeverBecomeServerScope(t *testing.T) {
	now := time.Now()
	validator, _ := NewValidator(Config{Issuers: []string{"issuer"}, Audience: "agent", MaximumClockSkew: 0}, &mutableTrust{true, true, true}, fixedClock{now})
	claims := Claims{Verified: true, Source: SourceBrowser, Issuer: "issuer", Audience: "agent", Subject: "actor", ActorID: "actor", TenantID: "attacker", WorkspaceID: "attacker", ProjectID: "attacker", Purpose: "agent", KeyID: "key", Scopes: []string{ScopeRead}, ExpiresAt: now.Add(time.Hour)}
	if _, err := validator.Authorize(context.Background(), claims, OpGetRun); err == nil {
		t.Fatal("browser-derived scope accepted")
	}
}

func TestZeroAuthoritativeTimeFailsClosed(t *testing.T) {
	now := time.Now()
	validator, _ := NewValidator(Config{Issuers: []string{"issuer"}, Audience: "agent", MaximumClockSkew: time.Second}, &mutableTrust{true, true, true}, fixedClock{})
	claims := Claims{Verified: true, Source: SourceWorkload, Issuer: "issuer", Audience: "agent", Subject: "actor", ActorID: "actor", TenantID: "tenant", WorkspaceID: "workspace", ProjectID: "project", Purpose: "purpose", KeyID: "key", Scopes: []string{ScopeRead}, NotBefore: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)}
	if _, err := validator.Authorize(context.Background(), claims, OpGetRun); err == nil {
		t.Fatal("authorization accepted without authoritative time")
	}
}

func assertCode(t *testing.T, err error, code problem.Code) {
	t.Helper()
	details, ok := err.(problem.Details)
	if !ok || details.Code != string(code) {
		t.Fatalf("got %v want %s", err, code)
	}
}
