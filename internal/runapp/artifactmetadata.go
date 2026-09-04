package runapp

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/ancyloce/anvilkit-agent-service/internal/artifacts"
	"github.com/ancyloce/anvilkit-agent-service/internal/auth"
	"github.com/ancyloce/anvilkit-agent-service/internal/canonical"
	contractguard "github.com/ancyloce/anvilkit-agent-service/internal/contracts"
	"github.com/ancyloce/anvilkit-agent-service/internal/execution"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/runs"
)

// agentArtifactSchema pins the canonical wire contract every artifact
// representation is proved against before it leaves.
const agentArtifactSchema = "anvilkit://schema/agent-artifact?digest=sha256:ad13f62312765d898c106d12da58b77b5d1124211d8a4e8ecadd0db65a55e2b8"

// AgentArtifactKind is the canonical representation discriminator.
const AgentArtifactKind = "AgentArtifact"

// ArtifactMetadataReader is the governed artifact metadata surface. The
// execution pipeline satisfies it: it owns the current-authority read the
// disclosure is authorized against and the artifact record itself. This
// boundary only resolves a request into a scoped, authenticated read and
// renders what comes back.
type ArtifactMetadataReader interface {
	ArtifactMetadata(ctx context.Context, scope runs.Scope, id artifacts.ID, disclosure execution.ArtifactDisclosure) (execution.GovernedArtifact, error)
}

// WithArtifactMetadata publishes the governed artifact metadata surface. An
// unbound surface answers as unavailable rather than as absent: a caller must
// not learn from a 404 that a deployment simply has not composed this path.
func (a *App) WithArtifactMetadata(reader ArtifactMetadataReader) *App {
	a.artifactMetadata = reader
	return a
}

// ArtifactInput is one metadata read as transport received it.
//
// Purpose is the governed access purpose the caller declared in the request.
// It is the caller's statement of why they are reading the artifact, and the
// canonical description makes it required: a disclosure recorded without one
// says who was told what and leaves out the only part a reviewer would ask
// about afterwards.
type ArtifactInput struct {
	WorkspaceID, ArtifactID, Purpose, Traceparent string
}

// GetArtifact authorizes and answers one governed artifact metadata read.
//
// The workspace in the path must be the workspace the caller proved authority
// for, and a mismatch is answered as an absent resource rather than as a
// denial, so the path cannot be used to enumerate other tenants' workspaces.
// The project is never in the path: it comes from the verified authority, and
// it is what confines the lookup to the caller's own tenant. Whether the
// caller may read artifacts at all is decided further in, against current
// authority re-read on this request, and it is decided before the record is
// read — so an unauthorized caller learns the same thing whether the artifact
// exists or not.
//
// The whole decision is taken inside a protected-audit record: the accessor,
// the purpose they declared, the tenant, the artifact, the outcome, and the
// trace are written before anything is disclosed. A disclosure that cannot be
// recorded does not happen.
func (a *App) GetArtifact(ctx context.Context, claims auth.Claims, input ArtifactInput) (Representation, error) {
	if a.artifactMetadata == nil {
		return Representation{}, problem.New(problem.CodeInfrastructureUnavailable, "")
	}
	if a.guard == nil {
		return Representation{}, fmt.Errorf("read artifact metadata: the command guard is required")
	}
	scope, err := a.scope(ctx, claims, auth.OpAccessArtifact, input.WorkspaceID)
	if err != nil {
		return Representation{}, err
	}
	if input.ArtifactID == "" || len(input.ArtifactID) > 128 {
		return Representation{}, problem.New(problem.CodeRequestInvalid, "")
	}
	// The declared purpose is checked against the governed vocabulary here,
	// where the request is still a request. A purpose outside it, or a request
	// with no trace to record the disclosure under, is a malformed request
	// rather than a denial: the caller has stated something the contract does
	// not offer, and answering that as a refusal would suggest it was
	// considered and rejected.
	if !artifacts.ValidPurpose(artifacts.Purpose(input.Purpose)) || !validTraceparent(input.Traceparent) {
		value := problem.New(problem.CodeRequestInvalid, "")
		value.Detail = "reading artifact metadata requires a governed access purpose and a trace to record the disclosure under"
		return Representation{}, value
	}
	governed, err := a.artifactMetadata.ArtifactMetadata(ctx, scope, artifacts.ID(input.ArtifactID), execution.ArtifactDisclosure{
		Purpose:     input.Purpose,
		Traceparent: input.Traceparent,
	})
	if err != nil {
		return Representation{}, err
	}
	body, err := a.artifactRepresentation(ctx, governed.Record)
	if err != nil {
		return Representation{}, err
	}
	return Representation{Body: body, ETag: governed.Record.ETag()}, nil
}

// artifactRepresentation renders one artifact record as the canonical
// AgentArtifact and proves it against the pinned contract before it leaves.
//
// A record the contract cannot describe is refused rather than served in a
// shape of its own. That is the fail-closed direction: a client whose
// generated types reject the answer has an integration that fails at the
// consumer, at a moment nobody chose, and reading the artifact would have been
// the last chance to notice.
func (a *App) artifactRepresentation(ctx context.Context, record artifacts.Record) ([]byte, error) {
	// The canonical lineage is a list of complete artifact references —
	// identity, digest, media type, and size. The record keeps only input
	// identities, which is enough for the lifecycle to reason about and not
	// enough to represent. Nothing today produces an artifact with inputs, so
	// rather than serve a lineage entry with invented fields, a record that
	// somehow has them is refused and says why.
	if len(record.Lineage.Inputs) > 0 {
		return nil, fmt.Errorf("artifact %s carries input lineage the record cannot fully represent", record.ID)
	}
	lineage := make([]artifactReference, 0)
	checks := make([]artifactCheck, 0, len(record.Validation.Checks))
	for _, check := range record.Validation.Checks {
		checks = append(checks, artifactCheck{Name: check.Name, Result: check.Result, EvidenceDigest: check.EvidenceDigest})
	}
	body, err := json.Marshal(agentArtifact{
		ContractType: AgentArtifactKind,
		ArtifactID:   string(record.ID),
		Kind:         string(record.Kind),
		Schema:       schemaReference{ComponentName: record.Schema.Component, Digest: record.Schema.Digest},
		Digest:       record.Digest,
		Reference: objectReference{
			Bucket:    record.Reference.Bucket,
			ObjectKey: record.Reference.ObjectKey,
			SizeBytes: record.Reference.SizeBytes,
			MediaType: record.Reference.MediaType,
		},
		Lineage: lineage,
		Producer: artifactProducer{
			TaskID:              record.Lineage.Producer.TaskID,
			RecoveryEpoch:       record.Lineage.Producer.RecoveryEpoch,
			ExecutionGeneration: record.Lineage.Producer.ExecutionGeneration,
			PhysicalAttemptID:   record.Lineage.Producer.PhysicalAttemptID,
			LeaseEpoch:          record.Lineage.Producer.LeaseEpoch,
		},
		Validation: artifactValidation{
			ValidatedAt: record.Validation.ValidatedAt.UTC().Format(canonicalTimestamp),
			Checks:      checks,
		},
		Lifecycle: string(record.State),
		CreatedAt: record.CreatedAt.UTC().Format(canonicalTimestamp),
	})
	if err != nil {
		return nil, fmt.Errorf("render artifact representation: %w", err)
	}
	canonicalBody, err := canonical.Bytes(body)
	if err != nil {
		return nil, fmt.Errorf("canonicalize artifact representation: %w", err)
	}
	if err := a.guard.Require(ctx, contractguard.ArtifactOut, agentArtifactSchema, canonicalBody); err != nil {
		return nil, fmt.Errorf("artifact representation violates the canonical AgentArtifact contract: %w", err)
	}
	return canonicalBody, nil
}

// canonicalTimestamp is the instant format the canonical contracts declare.
const canonicalTimestamp = "2006-01-02T15:04:05.000Z"

// The canonical AgentArtifact wire shape. It is written here rather than
// reused from the record because the record is the service's own state and
// the representation is a contract: the two are allowed to differ, and the
// place they are reconciled has to be one deliberate mapping.
type agentArtifact struct {
	ContractType string              `json:"contractType"`
	ArtifactID   string              `json:"artifactId"`
	Kind         string              `json:"kind"`
	Schema       schemaReference     `json:"schema"`
	Digest       string              `json:"digest"`
	Reference    objectReference     `json:"reference"`
	Lineage      []artifactReference `json:"lineage"`
	Producer     artifactProducer    `json:"producer"`
	Validation   artifactValidation  `json:"validation"`
	Lifecycle    string              `json:"lifecycle"`
	CreatedAt    string              `json:"createdAt"`
}

type schemaReference struct {
	ComponentName string `json:"componentName"`
	Digest        string `json:"digest"`
}

type objectReference struct {
	Bucket    string `json:"bucket"`
	ObjectKey string `json:"objectKey"`
	SizeBytes int64  `json:"sizeBytes"`
	MediaType string `json:"mediaType"`
}

type artifactReference struct {
	ArtifactID string `json:"artifactId"`
	Digest     string `json:"digest"`
	MediaType  string `json:"mediaType"`
	SizeBytes  int64  `json:"sizeBytes"`
}

type artifactProducer struct {
	TaskID              string `json:"taskId"`
	RecoveryEpoch       uint64 `json:"recoveryEpoch"`
	ExecutionGeneration uint64 `json:"executionGeneration"`
	PhysicalAttemptID   string `json:"physicalAttemptId"`
	LeaseEpoch          uint64 `json:"leaseEpoch"`
}

type artifactCheck struct {
	Name           string `json:"name"`
	Result         string `json:"result"`
	EvidenceDigest string `json:"evidenceDigest"`
}

type artifactValidation struct {
	ValidatedAt string          `json:"validatedAt"`
	Checks      []artifactCheck `json:"checks"`
}
