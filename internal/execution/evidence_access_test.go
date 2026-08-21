package execution_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/ancyloce/anvilkit-agent-service/internal/auth"
	"github.com/ancyloce/anvilkit-agent-service/internal/authority"
	"github.com/ancyloce/anvilkit-agent-service/internal/events"
	"github.com/ancyloce/anvilkit-agent-service/internal/runs"
)

// verifiedEvidenceRequest stands in for the service's request-authority
// verification: it returns the tenant scope a caller proved and nothing else.
// Clearance is deliberately not expressible here — it comes from current
// authority, which is what makes a forged clearance impossible rather than
// merely rejected.
type verifiedEvidenceRequest struct{ scope runs.Scope }

func (v verifiedEvidenceRequest) Authorize(context.Context, auth.Claims, auth.Operation) (runs.Scope, error) {
	return v.scope, nil
}

// verifierAuthority mints the evidence read authority these tests read under,
// exactly as the composition would.
func verifierAuthority(t *testing.T) events.EvidenceAuthority {
	t.Helper()
	source := authority.NewStatic(authority.Current{
		Definition:       json.RawMessage(`{"definitionId":"definition.1"}`),
		ContractBOM:      json.RawMessage(`{"bomDigest":"sha256:1"}`),
		Policy:           json.RawMessage(`{"policyId":"policy.1"}`),
		Budget:           json.RawMessage(`{"kind":"AgentBudget"}`),
		WorkspaceActive:  true,
		ActorActive:      true,
		PermissionActive: true,
		PolicyActive:     true,
		ActorRole:        authority.RoleOperator,
		Grants:           authority.Grants{DataClasses: []string{"public", "internal", "confidential", "restricted"}},
	})
	value, err := events.MintEvidenceAuthority(
		context.Background(),
		verifiedEvidenceRequest{scope: runs.Scope{WorkspaceID: testWorkspace, ProjectID: testProject, ActorID: "reconciliation-verifier"}},
		source,
		auth.Claims{},
		"assert recorded reconciliation evidence",
	)
	if err != nil {
		t.Fatalf("mint evidence authority: %v", err)
	}
	return value
}
