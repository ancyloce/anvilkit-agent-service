package execution

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/ancyloce/anvilkit-agent-service/internal/agent"
	"github.com/ancyloce/anvilkit-agent-service/internal/canonical"
	"github.com/ancyloce/anvilkit-agent-service/internal/contractclient"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/runs"
)

// ContractValidator is the transport-neutral Contract Runtime boundary the
// workflow validates candidates through. The contract-validation orchestrator
// satisfies it: every validation records durable evidence, deterministic
// rejection is a typed problem, and runtime unavailability is bounded retry
// followed by a stable retryable problem — never a bypass.
type ContractValidator interface {
	Validate(context.Context, contractclient.Request) (contractclient.Evidence, error)
	ReviewProof(contractclient.Evidence) (runs.ValidationProof, error)
}

// SchemaValidator validates a payload against one pinned schema reference.
// The pinned schema validator satisfies it.
type SchemaValidator interface {
	Validate(context.Context, agent.SchemaReference, json.RawMessage) error
}

// BoundedSleeper sleeps under context control. Composition uses it for the
// contract-validation retry backoff.
type BoundedSleeper = contextSleeper

// BOMAuthority answers the approved Contract BOM digest one scope currently
// pins, from the durable current-authority record. The runtime verifies a
// request's claimed BOM identity against this authority-owned value, never
// against the caller's claim alone.
type BOMAuthority interface {
	PinnedBOMDigest(ctx context.Context, workspaceID, projectID string) (string, error)
}

// ControlledContractRuntime is the kernel's in-process Contract Runtime
// behind the transport-neutral boundary (ADR-022). It is a strict controlled
// implementation, not a permissive mock: it accepts only schema subjects the
// approved definition catalog pins, verifies the claimed catalog, policy, and
// Contract BOM identities against approved runtime material before anything
// is recorded as validated, really parses and validates every payload against
// the pinned schema material, enforces payload bounds, and answers with the
// runtime identity of the canonical lock it was built from. It has no
// network, file, process, or environment capability by construction.
type ControlledContractRuntime struct {
	validator     SchemaValidator
	schemas       map[string]agent.SchemaReference
	version       string
	catalogDigest string
	policies      map[string]bool
	boms          BOMAuthority
	maximumBytes  int
}

func NewControlledContractRuntime(validator SchemaValidator, references []agent.SchemaReference, version, catalogDigest string, policyDigests []string, boms BOMAuthority) (*ControlledContractRuntime, error) {
	if validator == nil || len(references) == 0 || !validDigestString(version) {
		return nil, fmt.Errorf("controlled contract runtime: the pinned validator, approved schema subjects, and runtime identity are required")
	}
	if !validDigestString(catalogDigest) || len(policyDigests) == 0 || boms == nil {
		return nil, fmt.Errorf("controlled contract runtime: the approved catalog digest, approved policy digests, and the scoped BOM authority are required")
	}
	schemas := make(map[string]agent.SchemaReference, len(references))
	for _, reference := range references {
		if reference.ComponentName == "" || !validDigestString(reference.Digest) {
			return nil, fmt.Errorf("controlled contract runtime: every approved subject requires a component name and digest")
		}
		schemas[reference.Digest] = reference
	}
	policies := make(map[string]bool, len(policyDigests))
	for _, digest := range policyDigests {
		if !validDigestString(digest) {
			return nil, fmt.Errorf("controlled contract runtime: every approved policy requires a digest")
		}
		policies[digest] = true
	}
	return &ControlledContractRuntime{validator: validator, schemas: schemas, version: version, catalogDigest: catalogDigest, policies: policies, boms: boms, maximumBytes: 16 * 1024 * 1024}, nil
}

var _ contractclient.Runtime = (*ControlledContractRuntime)(nil)

// CompileValidate answers deterministically: an unapproved subject, a catalog,
// policy, or BOM identity that is not the approved runtime material, an
// uncanonicalizable payload, an oversized payload, and a schema violation are
// all recorded findings, never errors, so the orchestrator does not retry
// what cannot change. Errors are reserved for genuine unavailability, which
// for this in-process implementation is only the authority read.
func (r *ControlledContractRuntime) CompileValidate(ctx context.Context, request contractclient.Request) (contractclient.Result, error) {
	if err := ctx.Err(); err != nil {
		return contractclient.Result{}, err
	}
	if request.CatalogDigest != r.catalogDigest {
		return invalidResult(r.version, "contract.catalog.mismatch", "the claimed catalog digest is not the approved catalog this runtime was built from"), nil
	}
	if !r.policies[request.PolicyDigest] {
		return invalidResult(r.version, "contract.policy.unapproved", "the claimed policy digest is not a policy the approved catalog attests"), nil
	}
	pinnedBOM, err := r.boms.PinnedBOMDigest(ctx, request.WorkspaceID, request.ProjectID)
	if err != nil {
		return contractclient.Result{}, fmt.Errorf("resolve the approved contract BOM for the scope: %w", err)
	}
	if request.BOMDigest != pinnedBOM {
		return invalidResult(r.version, "contract.bom.mismatch", "the claimed contract BOM digest is not the BOM current authority pins for this scope"), nil
	}
	reference, approved := r.schemas[request.SchemaDigest]
	if !approved {
		return invalidResult(r.version, "contract.subject.unsupported", "the schema digest is not an approved subject of the pinned contract set"), nil
	}
	if len(request.Payload) > r.maximumBytes {
		return invalidResult(r.version, "contract.payload.bounds", "the payload exceeds the runtime's size bound"), nil
	}
	if _, err := canonical.Bytes(request.Payload); err != nil {
		return invalidResult(r.version, "contract.payload.canonical", "the payload is not canonicalizable JSON"), nil
	}
	if err := r.validator.Validate(ctx, reference, request.Payload); err != nil {
		return invalidResult(r.version, "contract.schema.violation", truncate(err.Error(), 4096)), nil
	}
	return contractclient.Result{Valid: true, ValidatorVersion: r.version}, nil
}

func invalidResult(version, code, message string) contractclient.Result {
	return contractclient.Result{
		Valid:            false,
		ValidatorVersion: version,
		Findings:         []problem.FieldError{{Code: code, Message: message}},
	}
}

// StaticBOMAuthority serves one approved BOM digest for every scope. It is a
// test fixture; composition uses the durable authority store.
type StaticBOMAuthority struct{ Digest string }

func (a StaticBOMAuthority) PinnedBOMDigest(context.Context, string, string) (string, error) {
	if a.Digest == "" {
		return "", fmt.Errorf("no approved contract BOM is configured")
	}
	return a.Digest, nil
}
