package execution

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/artifacts"
	"github.com/ancyloce/anvilkit-agent-service/internal/canonical"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
)

// ArtifactCandidate is the validated final candidate one durable finalize
// operation records as an immutable artifact.
type ArtifactCandidate struct {
	WorkspaceID, ProjectID, RunID string
	Digest                        string
	Bytes                         []byte
	SchemaComponent, SchemaDigest string
	BOMDigest, CatalogDigest      string
	// OperationKey is the durable finalize operation identity; it doubles as
	// the producer task identity because the kernel produces candidates on the
	// workflow's own durable operations rather than on dispatched worker tasks.
	OperationKey        string
	ExecutionGeneration uint64
	BuildIdentity       string
	Producer            string
	// Kind is what the artifact is, and Validation is what the Contract
	// Runtime proved about it. Both are known here and nowhere later: an
	// artifact classified after the fact was classified by something other
	// than what produced it, and validation recomputed later answers about
	// whatever the content is then rather than what was checked.
	Kind       artifacts.Kind
	Validation artifacts.Validation
}

// ArtifactBucket is the single logical bucket the kernel stores run artifacts
// under. Scoping lives in the object key, which embeds workspace, project,
// and run identity.
const ArtifactBucket = "anvilkit-agent-artifacts"

// ArtifactRecordID derives the deterministic artifact identity for one run's
// candidate digest, so every replay of the same durable operation converges on
// the same immutable record.
func ArtifactRecordID(runID, digest string) artifacts.ID {
	sum := sha256.Sum256([]byte(runID + "\x00" + digest))
	return artifacts.ID("artifact." + hex.EncodeToString(sum[:16]))
}

// ServiceArtifactPort drives the real artifact lifecycle for the executor:
// candidates become immutable records that scan to valid, review acceptance
// finalizes them, and a confirmed governed effect commits them. Eligibility
// for a governed effect is the finalized state and nothing else.
type ServiceArtifactPort struct {
	service *artifacts.Service
	clock   Clock
}

func NewServiceArtifactPort(service *artifacts.Service, clock Clock) (*ServiceArtifactPort, error) {
	if service == nil || clock == nil {
		return nil, fmt.Errorf("artifact port: the artifact service and clock are required")
	}
	return &ServiceArtifactPort{service: service, clock: clock}, nil
}

var _ ArtifactPort = (*ServiceArtifactPort)(nil)

func (p *ServiceArtifactPort) RecordCandidate(ctx context.Context, candidate ArtifactCandidate) error {
	if candidate.WorkspaceID == "" || candidate.ProjectID == "" || candidate.RunID == "" || !validDigestString(candidate.Digest) || len(candidate.Bytes) == 0 || candidate.OperationKey == "" {
		return fmt.Errorf("artifact port: a complete candidate identity is required")
	}
	if !artifacts.ValidKind(candidate.Kind) || !candidate.Validation.Valid() {
		return fmt.Errorf("artifact port: a candidate must declare what it is and what was validated about it")
	}
	id := ArtifactRecordID(candidate.RunID, candidate.Digest)
	now := p.clock.Now()
	if now.IsZero() {
		return fmt.Errorf("artifact port: authoritative time is unavailable")
	}
	// The digest attests the canonical bytes, so the canonical bytes are what
	// the immutable object stores.
	canonicalBytes, err := canonical.Bytes(candidate.Bytes)
	if err != nil {
		return fmt.Errorf("canonicalize candidate artifact: %w", err)
	}
	record, err := p.service.Create(ctx, artifacts.Create{
		WorkspaceID:   candidate.WorkspaceID,
		ProjectID:     candidate.ProjectID,
		RunID:         candidate.RunID,
		ID:            id,
		Kind:          candidate.Kind,
		Bytes:         canonicalBytes,
		ClaimedDigest: candidate.Digest,
		Validation:    candidate.Validation,
		Reference: artifacts.Reference{
			Bucket:    ArtifactBucket,
			ObjectKey: candidate.WorkspaceID + "/" + candidate.ProjectID + "/" + candidate.RunID + "/" + string(id) + ".json",
			SizeBytes: int64(len(canonicalBytes)),
			MediaType: "application/json",
		},
		// Canonical contracts are non-versioned by governance (ADR-018), so
		// the schema identity version is the canonical set itself.
		Schema: artifacts.SchemaIdentity{Component: candidate.SchemaComponent, Version: "canonical", Digest: candidate.SchemaDigest},
		Lineage: artifacts.Lineage{
			RunID:             candidate.RunID,
			TaskID:            candidate.OperationKey,
			PhysicalAttemptID: candidate.OperationKey + ":1",
			Producer: artifacts.Producer{
				TaskID:              candidate.OperationKey,
				PhysicalAttemptID:   candidate.OperationKey + ":1",
				ExecutionGeneration: candidate.ExecutionGeneration,
				RecoveryEpoch:       1,
				LeaseEpoch:          1,
				BuildIdentity:       candidate.BuildIdentity,
				Provider:            candidate.Producer,
			},
			BOMDigest:     candidate.BOMDigest,
			SchemaDigest:  candidate.SchemaDigest,
			CatalogDigest: candidate.CatalogDigest,
		},
		CreatedAt: now,
	})
	if err != nil {
		return fmt.Errorf("record candidate artifact: %w", err)
	}
	// The kernel's validation already ran before this record exists, so the
	// scan converges pending → scanning → valid. A record another execution
	// already advanced converges without touching it.
	return p.advance(ctx, record, artifacts.Valid, now)
}

func (p *ServiceArtifactPort) EnsureFinalized(ctx context.Context, query ArtifactQuery) error {
	return p.ensure(ctx, query, artifacts.Finalized)
}

func (p *ServiceArtifactPort) EnsureCommitted(ctx context.Context, query ArtifactQuery) error {
	return p.ensure(ctx, query, artifacts.Committed)
}

func (p *ServiceArtifactPort) ensure(ctx context.Context, query ArtifactQuery, target artifacts.State) error {
	if query.WorkspaceID == "" || query.ProjectID == "" || query.RunID == "" || !validDigestString(query.ArtifactDigest) {
		return fmt.Errorf("artifact port: workspace, project, run, and artifact identity are required")
	}
	record, err := p.service.Get(ctx, query.WorkspaceID, query.ProjectID, ArtifactRecordID(query.RunID, query.ArtifactDigest))
	if err != nil {
		return fmt.Errorf("read candidate artifact: %w", err)
	}
	// Product compatibility is decided here, before the record advances out of
	// a revocable state. The lifecycle already proved the transition is legal;
	// this proves the artifact is one the admitted operation may produce, so a
	// run cannot carry another domain's artifact to a final state.
	//
	// The gate is on crossing into finalization, not on the requested target
	// being exactly Finalized: advance walks one state at a time, so a commit
	// requested over a still-valid record passes through Finalized on its way
	// and must be judged by the same rule.
	if crossesFinalization(record.State, target) && !artifacts.FinalizableBy(query.Operation, record.Kind) {
		return fmt.Errorf("artifact port: operation %q may not finalize a %q artifact", query.Operation, record.Kind)
	}
	now := p.clock.Now()
	if now.IsZero() {
		return fmt.Errorf("artifact port: authoritative time is unavailable")
	}
	return p.advance(ctx, record, target, now)
}

// crossesFinalization reports whether advancing a record from current to
// target enters the finalized state. A record already at or past Finalized has
// been judged once and is not re-judged; a record short of it that is being
// carried to Finalized or beyond is.
func crossesFinalization(current, target artifacts.State) bool {
	currentRank, ok := lifecycleRank(current)
	if !ok {
		return false
	}
	targetRank, ok := lifecycleRank(target)
	if !ok {
		return false
	}
	finalRank, _ := lifecycleRank(artifacts.Finalized)
	return currentRank < finalRank && targetRank >= finalRank
}

// lifecycleRank orders the forward lifecycle so convergence can tell an
// already-advanced record from one that fell off the path.
func lifecycleRank(state artifacts.State) (int, bool) {
	switch state {
	case artifacts.Pending:
		return 0, true
	case artifacts.Scanning:
		return 1, true
	case artifacts.Valid:
		return 2, true
	case artifacts.Finalized:
		return 3, true
	case artifacts.Committed:
		return 4, true
	default:
		return 0, false
	}
}

// advance walks the record forward along pending → scanning → valid →
// finalized → committed until it reaches the target, converging when another
// execution already advanced it and failing closed when the record left the
// forward path (quarantine, expiry, deletion).
func (p *ServiceArtifactPort) advance(ctx context.Context, record artifacts.Record, target artifacts.State, now time.Time) error {
	targetRank, ok := lifecycleRank(target)
	if !ok {
		return fmt.Errorf("artifact port: %q is not a forward lifecycle state", target)
	}
	for {
		currentRank, ok := lifecycleRank(record.State)
		if !ok {
			denied := problem.New(problem.CodeArtifactAccessDenied, "")
			denied.Detail = "the candidate artifact left the forward lifecycle: " + string(record.State)
			return denied
		}
		if currentRank >= targetRank {
			return nil
		}
		next := [...]artifacts.State{artifacts.Pending, artifacts.Scanning, artifacts.Valid, artifacts.Finalized, artifacts.Committed}[currentRank+1]
		advanced, err := p.service.Transition(ctx, record.WorkspaceID, record.ProjectID, record.ID, record.Version, next, now)
		if err != nil {
			var details problem.Details
			if errors.As(err, &details) && details.Code == string(problem.CodeVersionConflict) {
				// Another execution moved the record; re-read and converge.
				record, err = p.service.Get(ctx, record.WorkspaceID, record.ProjectID, record.ID)
				if err != nil {
					return fmt.Errorf("re-read candidate artifact: %w", err)
				}
				continue
			}
			return fmt.Errorf("advance candidate artifact to %s: %w", next, err)
		}
		record = advanced
	}
}

func (p *ServiceArtifactPort) Eligible(ctx context.Context, query ArtifactQuery) (ArtifactEligibility, error) {
	if query.WorkspaceID == "" || query.ProjectID == "" || query.RunID == "" || !validDigestString(query.ArtifactDigest) {
		return ArtifactEligibility{}, fmt.Errorf("artifact port: workspace, project, run, and artifact identity are required")
	}
	record, err := p.service.Get(ctx, query.WorkspaceID, query.ProjectID, ArtifactRecordID(query.RunID, query.ArtifactDigest))
	if err != nil {
		var details problem.Details
		if errors.As(err, &details) && details.Code == string(problem.CodeResourceNotFound) {
			return ArtifactEligibility{Eligible: false, Reason: "no immutable artifact record exists for the candidate"}, nil
		}
		return ArtifactEligibility{}, fmt.Errorf("read candidate artifact: %w", err)
	}
	if record.Digest != query.ArtifactDigest {
		return ArtifactEligibility{Eligible: false, Reason: "the artifact record does not attest the candidate digest"}, nil
	}
	if record.State != artifacts.Finalized {
		return ArtifactEligibility{Eligible: false, Reason: "the artifact is not finalized: " + string(record.State)}, nil
	}
	return ArtifactEligibility{Eligible: true}, nil
}
