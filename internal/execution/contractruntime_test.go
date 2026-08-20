package execution

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ancyloce/anvilkit-agent-service/internal/agent"
	"github.com/ancyloce/anvilkit-agent-service/internal/contractclient"
)

// acceptingSchemaValidator accepts every payload, so these tests isolate the
// runtime's material-identity verification from schema validation itself.
type acceptingSchemaValidator struct{}

func (acceptingSchemaValidator) Validate(context.Context, agent.SchemaReference, json.RawMessage) error {
	return nil
}

func runtimeFixture(t *testing.T) (*ControlledContractRuntime, contractclient.Request) {
	t.Helper()
	schemaDigest := "sha256:" + strings.Repeat("1", 64)
	catalogDigest := "sha256:" + strings.Repeat("2", 64)
	policyDigest := "sha256:" + strings.Repeat("3", 64)
	bomDigest := "sha256:" + strings.Repeat("4", 64)
	runtime, err := NewControlledContractRuntime(
		acceptingSchemaValidator{},
		[]agent.SchemaReference{{ComponentName: "anvilkit.contract.schema.example", Digest: schemaDigest}},
		"sha256:"+strings.Repeat("0", 64),
		catalogDigest,
		[]string{policyDigest},
		StaticBOMAuthority{Digest: bomDigest},
	)
	if err != nil {
		t.Fatal(err)
	}
	return runtime, contractclient.Request{
		WorkspaceID:   "workspace-01",
		ProjectID:     "project-01",
		RunID:         "run-01",
		Kind:          contractclient.Artifact,
		Payload:       []byte(`{"kind":"example"}`),
		BOMDigest:     bomDigest,
		SchemaDigest:  schemaDigest,
		CatalogDigest: catalogDigest,
		PolicyDigest:  policyDigest,
	}
}

func TestControlledContractRuntimeVerifiesEveryClaimedMaterialIdentity(t *testing.T) {
	runtime, request := runtimeFixture(t)
	valid, err := runtime.CompileValidate(context.Background(), request)
	if err != nil || !valid.Valid {
		t.Fatalf("approved material result=%+v err=%v", valid, err)
	}
	drifted := "sha256:" + strings.Repeat("f", 64)
	cases := map[string]struct {
		mutate func(*contractclient.Request)
		code   string
	}{
		"catalog": {func(r *contractclient.Request) { r.CatalogDigest = drifted }, "contract.catalog.mismatch"},
		"policy":  {func(r *contractclient.Request) { r.PolicyDigest = drifted }, "contract.policy.unapproved"},
		"bom":     {func(r *contractclient.Request) { r.BOMDigest = drifted }, "contract.bom.mismatch"},
		"schema":  {func(r *contractclient.Request) { r.SchemaDigest = drifted }, "contract.subject.unsupported"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			claimed := request
			tc.mutate(&claimed)
			result, err := runtime.CompileValidate(context.Background(), claimed)
			if err != nil {
				t.Fatal(err)
			}
			if result.Valid || len(result.Findings) != 1 || result.Findings[0].Code != tc.code {
				t.Fatalf("caller-supplied %s identity was recorded as verified: %+v", name, result)
			}
		})
	}
}
