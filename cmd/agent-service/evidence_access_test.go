package main

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
// A clearance is not expressible here, which is what makes a forged clearance
// impossible rather than merely rejected.
type verifiedEvidenceRequest struct{ scope runs.Scope }

func (v verifiedEvidenceRequest) Authorize(context.Context, auth.Claims, auth.Operation) (runs.Scope, error) {
	return v.scope, nil
}

// sliceEvidenceAuthority mints the evidence read authority the vertical slice
// verifies under, exactly as the composition would: the scope comes from the
// verified request, the clearance from current authority.
func sliceEvidenceAuthority(t *testing.T, workspaceID, projectID string) events.EvidenceAuthority {
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
		ActorGrants:      authority.ActorAuthority{DataClasses: []string{"public", "internal", "confidential", "restricted"}},
	})
	value, err := events.MintEvidenceAuthority(
		context.Background(),
		verifiedEvidenceRequest{scope: runs.Scope{WorkspaceID: workspaceID, ProjectID: projectID, ActorID: "slice-verifier"}},
		source,
		auth.Claims{},
		"vertical-slice-verification",
	)
	if err != nil {
		t.Fatalf("mint evidence authority: %v", err)
	}
	return value
}
