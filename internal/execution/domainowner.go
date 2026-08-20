package execution

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/applyauth"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
)

// DomainRedemption is the authoritative owner's record of one governed effect:
// which operation redeemed which authorization, attested by the token digest,
// and what the owner decided. It is written exactly once, atomically with the
// decision, and never changes.
type DomainRedemption struct {
	WorkspaceID     string
	ProjectID       string
	OperationID     string
	AuthorizationID string
	TokenDigest     string
	RunID           string
	ArtifactDigest  string
	Outcome         string
	RedeemedAt      time.Time
}

// RedemptionResult reports whether the redemption was recorded now or replayed
// from the durable record.
type RedemptionResult struct {
	Outcome  string
	Replayed bool
}

// DomainRedemptionStore is the owner's atomic redeem-once record. Redeem
// inserts exactly once per operation and exactly once per authorization: a
// replay with the identical binding returns the recorded outcome, a different
// token for the same operation fails, and a second operation for the same
// token fails.
type DomainRedemptionStore interface {
	Redeem(context.Context, DomainRedemption) (RedemptionResult, error)
	Redeemed(ctx context.Context, workspaceID, projectID, operationID string) (DomainRedemption, bool, error)
}

// VerifyingDomainPort is the kernel's strict authoritative domain owner. It is
// a controlled implementation, not a permissive mock: it accepts a governed
// effect only after verifying the complete signed apply authorization — JWS
// signature, key revocation, issuer, audience, validity interval, action,
// artifact, target, base revision, actor, and material digest bindings — and
// it redeems the authorization atomically in its durable redemption record.
// Replay returns the recorded outcome; nothing is ever applied twice, in this
// process or any successor.
type VerifyingDomainPort struct {
	outcome     string
	keys        applyauth.SigningPort
	redemptions DomainRedemptionStore
	clock       Clock
}

func NewVerifyingDomainPort(outcome string, keys applyauth.SigningPort, redemptions DomainRedemptionStore, clock Clock) (*VerifyingDomainPort, error) {
	switch outcome {
	case DomainConfirmed, DomainConflict, DomainRejected:
	default:
		return nil, fmt.Errorf("verifying domain port: %q is not a domain outcome", outcome)
	}
	if keys == nil || redemptions == nil || clock == nil {
		return nil, fmt.Errorf("verifying domain port: verification keys, a durable redemption record, and a clock are required")
	}
	return &VerifyingDomainPort{outcome: outcome, keys: keys, redemptions: redemptions, clock: clock}, nil
}

var _ DomainPort = (*VerifyingDomainPort)(nil)

func (p *VerifyingDomainPort) Commit(ctx context.Context, command DomainCommand) (DomainOutcome, error) {
	if command.OperationID == "" || command.WorkspaceID == "" || command.ProjectID == "" || command.RunID == "" || command.AuthorizationID == "" || command.AuthorizationJWS == "" {
		return DomainOutcome{}, fmt.Errorf("verifying domain port: operation, scope, run, and the complete signed authorization are required")
	}
	now := p.clock.Now()
	if now.IsZero() {
		return DomainOutcome{}, fmt.Errorf("verifying domain port: authoritative time is unavailable")
	}
	// The owner verifies the capability itself: signature, key state, issuer,
	// audience, kind, validity interval, and complete binding shape.
	payload, err := applyauth.Verify(ctx, command.AuthorizationJWS, p.keys, now)
	if err != nil {
		return DomainOutcome{Status: DomainRejected}, nil
	}
	// Every binding the command asserts must be exactly what the token signs.
	// A single drifted axis is an unauthorized effect and is rejected before
	// anything is recorded.
	if string(payload.AuthorizationID) != command.AuthorizationID ||
		payload.WorkspaceID != command.WorkspaceID ||
		payload.Target.ProjectID != command.ProjectID ||
		payload.RunID != command.RunID ||
		payload.ArtifactDigest != command.ArtifactDigest ||
		payload.ActionDigest != command.ActionDigest ||
		payload.Target != command.Target ||
		payload.BaseRevision != command.BaseRevision ||
		payload.ActorID != command.ActorID ||
		payload.DefinitionDigest != command.DefinitionDigest ||
		payload.ContractBOMDigest != command.ContractBOMDigest ||
		payload.PolicyDigest != command.PolicyDigest {
		return DomainOutcome{Status: DomainRejected}, nil
	}
	tokenSum := sha256.Sum256([]byte(command.AuthorizationJWS))
	redemption, err := p.redemptions.Redeem(ctx, DomainRedemption{
		WorkspaceID:     command.WorkspaceID,
		ProjectID:       command.ProjectID,
		OperationID:     command.OperationID,
		AuthorizationID: command.AuthorizationID,
		TokenDigest:     "sha256:" + hex.EncodeToString(tokenSum[:]),
		RunID:           command.RunID,
		ArtifactDigest:  command.ArtifactDigest,
		Outcome:         p.outcome,
		RedeemedAt:      now,
	})
	if err != nil {
		var details problem.Details
		if errors.As(err, &details) && details.Code == string(problem.CodeIdempotencyConflict) {
			// The operation already redeemed a different token, or the token
			// was already redeemed by a different operation. Neither is ever a
			// second effect: the replay identity is violated and the command
			// is rejected without touching the recorded redemption.
			return DomainOutcome{Status: DomainRejected}, nil
		}
		return DomainOutcome{}, fmt.Errorf("redeem apply authorization: %w", err)
	}
	return DomainOutcome{Status: redemption.Outcome}, nil
}

// Reconcile answers what became of one submitted effect from the durable
// redemption record. An operation with no record proves nothing landed.
func (p *VerifyingDomainPort) Reconcile(ctx context.Context, query DomainQuery) (DomainOutcome, bool, error) {
	if query.OperationID == "" || query.WorkspaceID == "" || query.RunID == "" {
		return DomainOutcome{}, false, fmt.Errorf("verifying domain port: operation, workspace, and run identity are required")
	}
	record, found, err := p.redemptions.Redeemed(ctx, query.WorkspaceID, query.ProjectID, query.OperationID)
	if err != nil {
		return DomainOutcome{}, false, fmt.Errorf("read domain redemption: %w", err)
	}
	if !found {
		return DomainOutcome{}, false, nil
	}
	if record.RunID != query.RunID {
		return DomainOutcome{}, false, problem.New(problem.CodeIdempotencyConflict, "")
	}
	return DomainOutcome{Status: record.Outcome}, true, nil
}

// MemoryRedemptionStore is the in-memory redemption record for tests. It
// enforces the same two uniqueness axes as the durable table.
type MemoryRedemptionStore struct {
	lock            sync.Mutex
	byOperation     map[string]DomainRedemption
	byAuthorization map[string]string
}

func NewMemoryRedemptionStore() *MemoryRedemptionStore {
	return &MemoryRedemptionStore{byOperation: map[string]DomainRedemption{}, byAuthorization: map[string]string{}}
}

func redemptionKey(workspaceID, projectID, id string) string {
	return workspaceID + "\x00" + projectID + "\x00" + id
}

func (s *MemoryRedemptionStore) Redeem(_ context.Context, redemption DomainRedemption) (RedemptionResult, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	operationKey := redemptionKey(redemption.WorkspaceID, redemption.ProjectID, redemption.OperationID)
	if prior, ok := s.byOperation[operationKey]; ok {
		if prior.AuthorizationID != redemption.AuthorizationID || prior.TokenDigest != redemption.TokenDigest || prior.RunID != redemption.RunID || prior.ArtifactDigest != redemption.ArtifactDigest {
			return RedemptionResult{}, problem.New(problem.CodeIdempotencyConflict, "")
		}
		return RedemptionResult{Outcome: prior.Outcome, Replayed: true}, nil
	}
	authorityKey := redemptionKey(redemption.WorkspaceID, redemption.ProjectID, redemption.AuthorizationID)
	if _, redeemed := s.byAuthorization[authorityKey]; redeemed {
		return RedemptionResult{}, problem.New(problem.CodeIdempotencyConflict, "")
	}
	s.byOperation[operationKey] = redemption
	s.byAuthorization[authorityKey] = redemption.OperationID
	return RedemptionResult{Outcome: redemption.Outcome}, nil
}

func (s *MemoryRedemptionStore) Redeemed(_ context.Context, workspaceID, projectID, operationID string) (DomainRedemption, bool, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	record, ok := s.byOperation[redemptionKey(workspaceID, projectID, operationID)]
	return record, ok, nil
}
