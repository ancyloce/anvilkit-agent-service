package execution

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/applyauth"
	"github.com/ancyloce/anvilkit-agent-service/internal/canonical"
	"github.com/ancyloce/anvilkit-agent-service/internal/interrupts"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/runs"
)

// ApplyAuthorityResolver answers the issuer's bounded command with an
// independently re-proved binding. It re-reads the run aggregate, the
// approval record, the one current-authority source, and the artifact owner —
// it never trusts the caller's claim that a commit gate already passed, so an
// authorization can only bind facts that are still true at issuance time.
type ApplyAuthorityResolver struct {
	runs      RunStore
	reader    InterruptReader
	authority AuthorityProvider
	artifacts ArtifactPort
}

func NewApplyAuthorityResolver(runStore RunStore, reader InterruptReader, authority AuthorityProvider, artifacts ArtifactPort) (*ApplyAuthorityResolver, error) {
	if runStore == nil || reader == nil || authority == nil || artifacts == nil {
		return nil, fmt.Errorf("apply authority resolver: run store, interrupt reader, authority source, and artifact port are required")
	}
	return &ApplyAuthorityResolver{runs: runStore, reader: reader, authority: authority, artifacts: artifacts}, nil
}

var _ applyauth.Authority = (*ApplyAuthorityResolver)(nil)

// Resolve builds the approved and current bindings the issuer compares. The
// approved side comes from the material pinned on the run and the accepted
// approval decision; the current side re-reads the authority source and the
// artifact being committed. Any byte drift between the two sides surfaces as
// unequal bindings and the issuer fails closed.
func (r *ApplyAuthorityResolver) Resolve(ctx context.Context, command applyauth.Command) (applyauth.Proof, error) {
	scope := runs.Scope{WorkspaceID: command.WorkspaceID, ProjectID: command.ProjectID}
	snapshot, err := r.runs.Get(ctx, scope, runs.ID(command.RunID))
	if err != nil {
		return applyauth.Proof{}, fmt.Errorf("resolve run for authorization: %w", err)
	}
	scope.ActorID = snapshot.ActorID
	approval, err := r.reader.Approval(ctx, scope, runs.ID(command.RunID), interrupts.RequestID(command.ApprovalRequestID))
	if err != nil {
		return applyauth.Proof{}, fmt.Errorf("resolve approval for authorization: %w", err)
	}
	current, err := r.authority.Current(ctx, scope.AuthorityScope())
	if err != nil {
		return applyauth.Proof{}, fmt.Errorf("resolve current authority for authorization: %w", err)
	}
	if !current.MaterialComplete() || !current.Active() {
		return applyauth.Proof{}, fmt.Errorf("resolve current authority for authorization: authority no longer permits this run")
	}
	// Identity-specific withdrawals gate issuance exactly like whole-scope
	// deactivation: a revoked target or a revoked approval can never receive a
	// signed capability.
	if current.TargetRevoked(snapshot.Target.ID) {
		return applyauth.Proof{}, fmt.Errorf("resolve current authority for authorization: authority over the run's target is revoked")
	}
	approvalRevoked := current.ApprovalRevoked(command.ApprovalRequestID)
	pinnedDefinition, pinnedBOM, pinnedPolicy, err := materialDigests(snapshot.Definition, snapshot.ContractBOM, snapshot.Policy)
	if err != nil {
		return applyauth.Proof{}, fmt.Errorf("digest pinned run material: %w", err)
	}
	currentDefinition, currentBOM, currentPolicy, err := materialDigests(current.Definition, current.ContractBOM, current.Policy)
	if err != nil {
		return applyauth.Proof{}, fmt.Errorf("digest current authority material: %w", err)
	}
	eligibility, err := r.artifacts.Eligible(ctx, ArtifactQuery{
		WorkspaceID:    snapshot.WorkspaceID,
		ProjectID:      snapshot.Target.ProjectID,
		RunID:          string(snapshot.RunID),
		ArtifactDigest: command.ArtifactID,
	})
	if err != nil {
		return applyauth.Proof{}, fmt.Errorf("resolve artifact eligibility for authorization: %w", err)
	}
	// The kernel's base revision is the durable approval checkpoint identity.
	// Both binding sides read the same accepted approval row, so this axis
	// drifts only when the approval itself was replaced; an authoritative
	// domain target revision arrives with the Pagix integration.
	baseRevision := "rev:" + string(approval.ID)
	approvalCurrent := approval.Decision != nil && approval.Decision.Kind == interrupts.DecisionApprove && approval.ExpiredAt == nil && !approvalRevoked
	approvedVersion := uint64(0)
	if approval.Decision != nil {
		approvedVersion = approval.Decision.RequestVersion
	}
	shared := applyauth.Binding{
		RunID:        string(snapshot.RunID),
		Target:       applyauth.Target{Type: snapshot.Target.Type, ID: snapshot.Target.ID, WorkspaceID: snapshot.Target.WorkspaceID, ProjectID: snapshot.Target.ProjectID},
		BaseRevision: baseRevision,
		ActorID:      snapshot.ActorID,
		WorkspaceID:  snapshot.WorkspaceID,
	}
	approved := shared
	approved.ActionDigest = approval.ActionDigest
	approved.ArtifactDigest = approval.ActionDigest
	approved.ApprovalVersion = approvedVersion
	approved.ContractBOMDigest = pinnedBOM
	approved.PolicyDigest = pinnedPolicy
	approved.DefinitionDigest = pinnedDefinition
	approved.CatalogDigest = eligibility.CatalogDigest
	currentBinding := shared
	currentBinding.ActionDigest = approval.ActionDigest
	currentBinding.ArtifactDigest = command.ArtifactID
	currentBinding.ApprovalVersion = approval.Version
	currentBinding.ContractBOMDigest = currentBOM
	currentBinding.PolicyDigest = currentPolicy
	currentBinding.DefinitionDigest = currentDefinition
	currentBinding.CatalogDigest = eligibility.CatalogDigest
	return applyauth.Proof{Approved: approved, Current: currentBinding, ApprovalCurrent: approvalCurrent, ArtifactEligible: eligibility.Eligible}, nil
}

func materialDigests(definition, contractBOM, policy []byte) (string, string, string, error) {
	definitionDigest, err := canonical.Digest(definition)
	if err != nil {
		return "", "", "", fmt.Errorf("definition: %w", err)
	}
	bomDigest, err := canonical.Digest(contractBOM)
	if err != nil {
		return "", "", "", fmt.Errorf("contract BOM: %w", err)
	}
	policyDigest, err := canonical.Digest(policy)
	if err != nil {
		return "", "", "", fmt.Errorf("policy: %w", err)
	}
	return definitionDigest, bomDigest, policyDigest, nil
}

// Issuer is the bounded issuance boundary the commit authority calls. The
// apply-authorization issuer service satisfies it.
type Issuer interface {
	Issue(context.Context, applyauth.Command) (applyauth.Authorization, error)
}

// IssuanceRecord is the durable record binding one durable commit operation to
// exactly one issued authorization: its identity, the complete signed token,
// and its expiry. Replay returns this persisted capability, never a new one.
type IssuanceRecord struct {
	WorkspaceID      string
	ProjectID        string
	RunID            string
	OperationKey     string
	AuthorizationID  string
	AuthorizationJWS string
	ExpiresAt        time.Time
}

// IssuanceStore reads the insert-once record of which authorization one
// durable commit operation issued. Writing the record happens inside the
// issuer's atomic audit write, never through this port.
type IssuanceStore interface {
	Recorded(ctx context.Context, workspaceID, projectID, operationKey string) (IssuanceRecord, bool, error)
}

// IssuerCommitAuthority is the real commit authority: it issues a signed,
// audited apply authorization through the issuer service, whose audit write
// atomically pins the issued identity and complete token to the durable
// operation key. A replay of the same durable operation returns the recorded
// original authorization instead of minting a second one, and a racing
// execution that loses the operation insert never produces a durably audited
// token at all.
type IssuerCommitAuthority struct {
	issuer Issuer
	store  IssuanceStore
}

func NewIssuerCommitAuthority(issuer Issuer, store IssuanceStore) (*IssuerCommitAuthority, error) {
	if issuer == nil || store == nil {
		return nil, fmt.Errorf("commit authority: the issuer service and a durable issuance record are required")
	}
	return &IssuerCommitAuthority{issuer: issuer, store: store}, nil
}

var _ CommitAuthority = (*IssuerCommitAuthority)(nil)

func (a *IssuerCommitAuthority) Issue(ctx context.Context, request AuthorizationRequest) (IssuedAuthorization, error) {
	if request.IdempotencyKey == "" || request.WorkspaceID == "" || request.ProjectID == "" || request.RunID == "" || request.ApprovalRequestID == "" {
		return IssuedAuthorization{}, fmt.Errorf("commit authority: the durable operation identity, scope, run, and approval identities are required")
	}
	if !validDigestString(request.ArtifactDigest) || request.ActionDigest != request.ArtifactDigest {
		return IssuedAuthorization{}, fmt.Errorf("commit authority: the approved action digest must bind the exact artifact being committed")
	}
	if recorded, ok, err := a.store.Recorded(ctx, request.WorkspaceID, request.ProjectID, request.IdempotencyKey); err != nil {
		return IssuedAuthorization{}, fmt.Errorf("read recorded issuance: %w", err)
	} else if ok {
		return issuedFromRecord(recorded)
	}
	authorization, err := a.issuer.Issue(ctx, applyauth.Command{
		WorkspaceID:       request.WorkspaceID,
		ProjectID:         request.ProjectID,
		RunID:             request.RunID,
		ApprovalRequestID: request.ApprovalRequestID,
		ArtifactID:        request.ArtifactDigest,
		OperationKey:      request.IdempotencyKey,
	})
	if err != nil {
		// A racing execution recorded first: its atomic audit write holds the
		// operation, this execution's token was rolled back unaudited, and the
		// recorded original is the only valid capability for the operation.
		var details problem.Details
		if errors.As(err, &details) && details.Code == string(problem.CodeIdempotencyConflict) {
			recorded, ok, readErr := a.store.Recorded(ctx, request.WorkspaceID, request.ProjectID, request.IdempotencyKey)
			if readErr != nil {
				return IssuedAuthorization{}, fmt.Errorf("read winning issuance after race: %w", readErr)
			}
			if ok {
				return issuedFromRecord(recorded)
			}
		}
		return IssuedAuthorization{}, err
	}
	return IssuedAuthorization{AuthorizationID: string(authorization.ID), CompactJWS: authorization.Compact, ExpiresAt: authorization.ExpiresAt}, nil
}

// issuedFromRecord converts the persisted issuance into the issued shape. A
// record without its complete signed token is an incomplete capability and
// fails closed rather than answering with only an identity.
func issuedFromRecord(recorded IssuanceRecord) (IssuedAuthorization, error) {
	if recorded.AuthorizationID == "" || recorded.AuthorizationJWS == "" {
		return IssuedAuthorization{}, fmt.Errorf("commit authority: the recorded issuance does not carry the complete signed authorization")
	}
	return IssuedAuthorization{AuthorizationID: recorded.AuthorizationID, CompactJWS: recorded.AuthorizationJWS, ExpiresAt: recorded.ExpiresAt}, nil
}

// RandomAuthorizationIDs allocates unguessable authorization identities.
type RandomAuthorizationIDs struct{}

func (RandomAuthorizationIDs) AuthorizationID() (applyauth.AuthorizationID, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("allocate authorization identity: %w", err)
	}
	return applyauth.AuthorizationID("authorization." + hex.EncodeToString(raw)), nil
}

// MemoryIssuanceStore is the in-memory issuance record for tests. It plays
// both sides of the durable contract: it is the issuer's atomic audit port
// (insert-once by operation, audit and mapping in one write) and the commit
// authority's issuance reader.
type MemoryIssuanceStore struct {
	lock    sync.Mutex
	records map[string]IssuanceRecord
}

func NewMemoryIssuanceStore() *MemoryIssuanceStore {
	return &MemoryIssuanceStore{records: make(map[string]IssuanceRecord)}
}

func issuanceKey(workspaceID, projectID, operationKey string) string {
	return workspaceID + "\x00" + projectID + "\x00" + operationKey
}

func (s *MemoryIssuanceStore) Recorded(_ context.Context, workspaceID, projectID, operationKey string) (IssuanceRecord, bool, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	record, ok := s.records[issuanceKey(workspaceID, projectID, operationKey)]
	return record, ok, nil
}

// Record is the applyauth.Audit implementation: one atomic insert-once write
// of the audit fact and the operation mapping. Losing the operation race is an
// idempotency conflict, exactly like the rolled-back database transaction.
func (s *MemoryIssuanceStore) Record(_ context.Context, record applyauth.AuditRecord) error {
	if record.OperationKey == "" || record.Token == "" {
		return fmt.Errorf("issuance record requires the durable operation identity and the signed token")
	}
	s.lock.Lock()
	defer s.lock.Unlock()
	key := issuanceKey(record.WorkspaceID, record.ProjectID, record.OperationKey)
	if winner, ok := s.records[key]; ok {
		if winner.AuthorizationID != string(record.AuthorizationID) {
			return problem.New(problem.CodeIdempotencyConflict, "")
		}
		return nil
	}
	s.records[key] = IssuanceRecord{
		WorkspaceID:      record.WorkspaceID,
		ProjectID:        record.ProjectID,
		RunID:            record.RunID,
		OperationKey:     record.OperationKey,
		AuthorizationID:  string(record.AuthorizationID),
		AuthorizationJWS: record.Token,
		ExpiresAt:        record.ExpiresAt,
	}
	return nil
}

var _ applyauth.Audit = (*MemoryIssuanceStore)(nil)
var _ IssuanceStore = (*MemoryIssuanceStore)(nil)
