// Package artifacts owns immutable artifact identity, lifecycle, grants, and reconciliation.
package artifacts

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/authority"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/securityaudit"
)

type ID string
type State string

const (
	Pending     State = "pending"
	Scanning    State = "scanning"
	Valid       State = "valid"
	Finalized   State = "finalized"
	Committed   State = "committed"
	Quarantined State = "quarantined"
	Expired     State = "expired"
	Deleted     State = "deleted"
)

type Purpose string

const (
	ProducerAccess     Purpose = "producer"
	ScannerAccess      Purpose = "scanner"
	ReviewAccess       Purpose = "review"
	ApprovalAccess     Purpose = "approval"
	FinalizationAccess Purpose = "finalization"
	CommitAccess       Purpose = "commit"
	ReadAccess         Purpose = "read"
)

type SchemaIdentity struct{ Component, Version, Digest string }
type Producer struct {
	TaskID                             string
	RecoveryEpoch, ExecutionGeneration uint64
	PhysicalAttemptID                  string
	LeaseEpoch                         uint64
	BuildIdentity, Provider            string
}
type Lineage struct {
	RunID, TaskID, PhysicalAttemptID       string
	Inputs                                 []ID
	Producer                               Producer
	BOMDigest, SchemaDigest, CatalogDigest string
}
type Reference struct {
	Bucket, ObjectKey string
	SizeBytes         int64
	MediaType         string
}
type Record struct {
	WorkspaceID, ProjectID, RunID string
	ID                            ID
	Digest, ActualDigest          string
	Reference                     Reference
	Schema                        SchemaIdentity
	Lineage                       Lineage
	State                         State
	Version, SecurityGeneration   uint64
	LegalHold                     bool
	CreatedAt, UpdatedAt          time.Time
	DeletedAt                     *time.Time
	DeletionReason                string
	// DeletionClaim names the decision that durably owns this artifact's
	// destruction, and DeletionClaimedAt when it took ownership. They are set
	// before anything is revoked or destroyed and never change afterwards, so
	// a destruction interrupted part-way through is resumable by the decision
	// that owns it and closed to every other.
	DeletionClaim     string
	DeletionClaimedAt *time.Time
}

// DeletionClaim is the durable ownership one decision holds over an artifact's
// destruction.
type DeletionClaim struct {
	// Decision is the protected-audit identity of the decision that owns the
	// destruction. The same decision resumes its own claim; any other decision
	// meets an artifact that is already owned and is refused.
	Decision string
	// Terminal is the revocable state the artifact is carried into as the
	// claim is taken. It is quarantined or expired, never a live state and
	// never the tombstone: the tombstone lands only once the content is gone.
	Terminal State
	At       time.Time
}

// Valid reports whether the claim names a decision, a revocable terminal
// state, and the moment it was taken.
func (c DeletionClaim) Valid() bool {
	return c.Decision != "" && len(c.Decision) <= 128 && (c.Terminal == Quarantined || c.Terminal == Expired) && !c.At.IsZero()
}

type Create struct {
	WorkspaceID, ProjectID, RunID string
	ID                            ID
	Bytes                         []byte
	ClaimedDigest                 string
	Reference                     Reference
	Schema                        SchemaIdentity
	Lineage                       Lineage
	CreatedAt                     time.Time
}
type ObjectStore interface {
	PutOnce(context.Context, Reference, []byte) error
	Delete(context.Context, Reference) error
	Exists(context.Context, Reference) (bool, error)
}

// Reader signs bounded read access, verifies presented capabilities, and
// revokes what it signed. SignRead receives the grant being issued so real
// implementations audit every grant durably before any capability leaves the
// service. Verify proves a presented grant: its signature, its durable
// audited record, and its revocation state — a forged, tampered, unknown, or
// revoked capability fails closed. Revoke withdraws every outstanding grant
// on the record immutably: the audit history is marked, never deleted.
type Reader interface {
	SignRead(context.Context, Record, Grant, time.Duration) (string, error)
	Verify(context.Context, Record, Grant) error
	Revoke(context.Context, Record) error
}
type Grant struct {
	ArtifactID         ID
	Digest             string
	SecurityGeneration uint64
	Purpose            Purpose
	ActorID            string
	URL                string
	ExpiresAt          time.Time
}

// ProtectedAudit is the tamper-evident record every authorization-changing
// artifact decision is made through. The decision is recorded before it is
// applied and its outcome is recorded after, so a decision that was taken is
// reconstructable even when the change it authorized did not complete.
//
// It is a required dependency, not an option: an artifact service composed
// without one could revoke access leaving no protected account of who revoked
// it or why, and that is precisely the record an incident needs.
type ProtectedAudit interface {
	PrivilegedMutation(ctx context.Context, record securityaudit.Record, mutation securityaudit.Mutation) error
}

// CustodyCapability names one artifact-custody operation. An actor must
// currently hold the named capability, in the grants bound to the acting
// scope, to perform it.
//
// These are custody operations on the artifact record itself, and they are
// spelled under their own prefix so they can never be confused with — or
// satisfied by — the tool capabilities an agent runs under. A workspace that
// grants an agent the right to scan artifacts has not thereby granted it the
// right to destroy them.
type CustodyCapability string

const (
	// LegalHoldCapability authorizes placing or lifting the hold that decides
	// whether an artifact may be destroyed.
	LegalHoldCapability CustodyCapability = "artifact-custody.legal-hold"
	// DeleteCapability authorizes destroying an artifact's content.
	DeleteCapability CustodyCapability = "artifact-custody.delete"
)

// Custody is the accountable identity behind one authorization-changing
// artifact decision. Every field is required: an artifact whose access is
// withdrawn without a named actor, a stated reason, and the change record it
// answers to cannot be reviewed afterwards.
type Custody struct {
	ActorID, Workload, Reason, Ticket, Traceparent string
}

func (c Custody) valid() bool {
	return c.ActorID != "" && len(c.ActorID) <= 128 && c.Workload != "" && len(c.Workload) <= 128 &&
		c.Reason != "" && len(c.Reason) <= 1024 && c.Ticket != "" && len(c.Ticket) <= 128 && c.Traceparent != ""
}

// systemCustody is the identity automated retention and orphan reconciliation
// acts under. Reconciliation revokes access on the lifecycle's own terms, so
// it is audited exactly like an operator's revocation — the record simply
// names the reconciler as the actor.
func systemCustody(reason, traceparent string) Custody {
	return Custody{ActorID: "artifact-reconciler", Workload: "artifact-lifecycle", Reason: reason, Ticket: "artifact-lifecycle-reconciliation", Traceparent: traceparent}
}

type Service struct {
	store                Store
	objects              ObjectStore
	reader               Reader
	authority            authority.Source
	audit                ProtectedAudit
	pendingTTL, grantTTL time.Duration
}

func New(store Store, objects ObjectStore, reader Reader, source authority.Source, audit ProtectedAudit, pendingTTL, grantTTL time.Duration) (*Service, error) {
	if store == nil || objects == nil || reader == nil || source == nil || audit == nil || pendingTTL <= 0 || grantTTL <= 0 || grantTTL > 15*time.Minute {
		return nil, fmt.Errorf("artifact dependencies, protected audit, or TTLs are invalid")
	}
	return &Service{store: store, objects: objects, reader: reader, authority: source, audit: audit, pendingTTL: pendingTTL, grantTTL: grantTTL}, nil
}

// decisionIdentity is the identity of one authorization-changing decision:
// the action, the artifact, and the exact version being changed. Two attempts
// at the same change under the same version are the same decision, so a retry
// resumes what is already recorded instead of opening a second one.
//
// The version is named separately rather than read off a record because a
// retry meets the artifact after its own earlier attempt already moved it. The
// decision is still about the version it set out to change.
func decisionIdentity(action, workspace, project string, id ID, version uint64) string {
	identity := sha256.Sum256([]byte(action + "\x00" + workspace + "\x00" + project + "\x00" + string(id) + "\x00" + strconv.FormatUint(version, 10)))
	return "artifact." + hex.EncodeToString(identity[:16])
}

// auditedChange runs one authorization-changing decision through the protected
// audit under the given decision identity. The audit records the decision
// before the change is applied and its outcome after, and resumes rather than
// restarts when an attempt was interrupted between the two — so the change
// itself has to be idempotent under this same identity, which is what every
// caller below is written to be.
func (s *Service) auditedChange(ctx context.Context, identity, action string, value Record, custody Custody, oldDigest, newDigest string, change func(context.Context) error) error {
	record := securityaudit.Record{
		ID:          identity,
		Action:      action,
		Actor:       custody.ActorID,
		Workload:    custody.Workload,
		Reason:      custody.Reason,
		Ticket:      custody.Ticket,
		OldDigest:   oldDigest,
		NewDigest:   newDigest,
		Traceparent: custody.Traceparent,
		Scope:       securityaudit.Scope{WorkspaceID: value.WorkspaceID, ProjectID: value.ProjectID, ResourceID: string(value.ID)},
	}
	return s.audit.PrivilegedMutation(ctx, record, change)
}

// permittedByAuthority re-reads the one current-authority source for the
// acting scope. Artifact access is an external disclosure: issuing or using a
// grant under revoked or incomplete authority fails closed.
//
// Callers prove this before they read the artifact record, not after. An actor
// that may not act on artifacts at all learns the same thing whether the
// artifact it named exists or not, so the surface cannot be used to find out
// which artifact identities are real.
func (s *Service) permittedByAuthority(ctx context.Context, workspace, project, actor string) error {
	current, err := s.authority.Current(ctx, authority.Scope{WorkspaceID: workspace, ProjectID: project, ActorID: actor})
	if err != nil || !current.MaterialComplete() || !current.Active() {
		return problem.New(problem.CodeArtifactAccessDenied, "")
	}
	return nil
}

// permittedToChangeCustody authorizes one custody operation — the legal hold,
// or destruction — against current authority. Like every other artifact
// authorization it is proved before the record is read, so an unauthorized
// caller cannot tell an artifact that exists from one that does not.
//
// An active subject is not enough, and that is the whole point. Everything
// that runs in a workspace runs as an active subject; if that alone admitted a
// deletion, then every actor able to produce an artifact was also able to
// destroy one, and the record would say the deletion was authorized because
// the caller was logged in. Two further facts are required, and both are
// authority's own rather than the caller's: the role the scope's subject
// register admits this actor under, and the capability for this exact
// operation, both bound to this actor by that register rather than shared with
// everything else in the scope. The caller names the actor it is acting as;
// what that actor may do is not the caller's to assert.
func (s *Service) permittedToChangeCustody(ctx context.Context, workspace, project, actor string, id ID, capability CustodyCapability) error {
	if workspace == "" || project == "" || actor == "" || len(actor) > 128 || id == "" {
		return problem.New(problem.CodeArtifactAccessDenied, "")
	}
	current, err := s.authority.Current(ctx, authority.Scope{WorkspaceID: workspace, ProjectID: project, ActorID: actor})
	if err != nil || !current.MaterialComplete() || !current.Active() {
		return problem.New(problem.CodeArtifactAccessDenied, "")
	}
	if !current.HasRole(authority.RoleArtifactCustodian) {
		return problem.New(problem.CodeArtifactAccessDenied, "")
	}
	// The capability and the clearance are the actor's own, read from the
	// scope's subject register. They are deliberately not the scope's dispatch
	// grants: those are shared by every actor in the workspace, so a custody
	// capability held there would be held by all of them at once, with only
	// the admitted role standing between any of them and the artifact.
	if !current.ActorGrants.HasCapability(string(capability)) {
		return problem.New(problem.CodeArtifactAccessDenied, "")
	}
	// Authority over one artifact can be withdrawn without deactivating the
	// scope it lives in, and a custodian whose authority over this artifact
	// was withdrawn is not one who may still decide its fate.
	if current.TargetRevoked(string(id)) {
		return problem.New(problem.CodeArtifactAccessDenied, "")
	}
	// Artifact bytes are tenant content, and custody is a decision about that
	// content: a hold freezes it in place and a deletion destroys it. So the
	// clearance the register binds to this actor has to reach the
	// classification artifact content is governed under. An actor cleared only
	// for public material, or for nothing at all, holds the role and the
	// capability and still cannot decide the fate of tenant content.
	if !current.ActorGrants.Clears(CustodyDataClass) {
		return problem.New(problem.CodeArtifactAccessDenied, "")
	}
	return nil
}

// CustodyDataClass is the registered data classification a custodian must be
// cleared for. Artifact bytes are at minimum internal material — what an agent
// produced inside a tenant's workspace, limited to authenticated AnvilKit
// workloads and operators — so deciding their fate is authorized at that
// classification and not below it. An actor cleared only for public material,
// or for nothing at all, holds no clearance over artifact content whatever
// role and capability the register grants it.
const CustodyDataClass = "internal"

// ETag renders the strong resource revision this record stands at. A custodian
// pins it on the decision they make, so the decision names the exact revision
// they observed.
func (r Record) ETag() string { return fmt.Sprintf("\"%s:v%d\"", r.ID, r.Version) }

// ParseETag reads the artifact revision a caller pinned. A missing
// precondition and a stale one are different answers: the caller who sent
// nothing is told the precondition is required and retries with the current
// revision; the caller who sent a stale value is told its revision no longer
// stands.
func ParseETag(value string, id ID) (uint64, error) {
	if strings.TrimSpace(value) == "" {
		return 0, problem.New(problem.CodePreconditionRequired, "")
	}
	prefix := "\"" + string(id) + ":v"
	if !strings.HasPrefix(value, prefix) || !strings.HasSuffix(value, "\"") {
		return 0, problem.New(problem.CodeVersionConflict, "")
	}
	version, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(value, prefix), "\""), 10, 64)
	if err != nil || version == 0 {
		return 0, problem.New(problem.CodeVersionConflict, "")
	}
	return version, nil
}
func key(workspace, project string, id ID) string {
	return workspace + "\x00" + project + "\x00" + string(id)
}
func (s *Service) Create(ctx context.Context, input Create) (Record, error) {
	if input.WorkspaceID == "" || input.ProjectID == "" || input.RunID == "" || input.ID == "" || len(input.Bytes) == 0 || input.Reference.Bucket == "" || input.Reference.ObjectKey == "" || input.Reference.SizeBytes != int64(len(input.Bytes)) || input.Reference.MediaType == "" || !digest(input.ClaimedDigest) || input.CreatedAt.IsZero() || !schema(input.Schema) || !lineage(input.Lineage, input.RunID) {
		return Record{}, problem.New(problem.CodeRequestInvalid, "")
	}
	actual := sha256.Sum256(input.Bytes)
	actualDigest := "sha256:" + hex.EncodeToString(actual[:])
	state := Pending
	if actualDigest != input.ClaimedDigest {
		state = Quarantined
	}
	if prior, ok, err := s.store.Get(ctx, input.WorkspaceID, input.ProjectID, input.ID); err != nil {
		return Record{}, fmt.Errorf("read artifact record: %w", err)
	} else if ok {
		if prior.Digest != input.ClaimedDigest || prior.ActualDigest != actualDigest || prior.Reference != input.Reference {
			return Record{}, problem.New(problem.CodeIdempotencyConflict, "")
		}
		return prior, nil
	}
	if err := s.objects.PutOnce(ctx, input.Reference, append([]byte(nil), input.Bytes...)); err != nil {
		return Record{}, fmt.Errorf("write immutable artifact: %w", err)
	}
	record := Record{WorkspaceID: input.WorkspaceID, ProjectID: input.ProjectID, RunID: input.RunID, ID: input.ID, Digest: input.ClaimedDigest, ActualDigest: actualDigest, Reference: input.Reference, Schema: input.Schema, Lineage: cloneLineage(input.Lineage), State: state, Version: 1, SecurityGeneration: 1, CreatedAt: input.CreatedAt, UpdatedAt: input.CreatedAt}
	winner, created, err := s.store.Create(ctx, record)
	if err != nil {
		return Record{}, fmt.Errorf("record artifact identity: %w", err)
	}
	if !created && (winner.Digest != record.Digest || winner.ActualDigest != record.ActualDigest || winner.Reference != record.Reference) {
		return Record{}, problem.New(problem.CodeIdempotencyConflict, "")
	}
	return winner, nil
}
func (s *Service) Get(ctx context.Context, workspace, project string, id ID) (Record, error) {
	value, ok, err := s.store.Get(ctx, workspace, project, id)
	if err != nil {
		return Record{}, fmt.Errorf("read artifact record: %w", err)
	}
	if !ok {
		return Record{}, problem.New(problem.CodeResourceNotFound, "")
	}
	return value, nil
}
func (s *Service) Transition(ctx context.Context, workspace, project string, id ID, expected uint64, next State, now time.Time) (Record, error) {
	value, ok, err := s.store.Get(ctx, workspace, project, id)
	if err != nil {
		return Record{}, fmt.Errorf("read artifact record: %w", err)
	}
	if !ok {
		return Record{}, problem.New(problem.CodeResourceNotFound, "")
	}
	if expected == 0 || value.Version != expected {
		return Record{}, problem.New(problem.CodeVersionConflict, "")
	}
	if !allowed(value.State, next) {
		return Record{}, problem.New(problem.CodeInvalidTransition, "")
	}
	if next == Expired && value.LegalHold {
		return Record{}, problem.New(problem.CodeArtifactAccessDenied, "")
	}
	if (next == Quarantined && value.State != Quarantined) || next == Expired {
		value.SecurityGeneration++
		if err := s.reader.Revoke(ctx, value); err != nil {
			return Record{}, fmt.Errorf("revoke artifact grants: %w", err)
		}
	}
	value.State = next
	value.Version++
	value.UpdatedAt = now
	return s.store.Update(ctx, value, expected)
}
func (s *Service) Grant(ctx context.Context, workspace, project string, id ID, purpose Purpose, actor string, now time.Time) (Grant, error) {
	if actor == "" || len(actor) > 128 || now.IsZero() {
		return Grant{}, problem.New(problem.CodeArtifactAccessDenied, "")
	}
	if err := s.permittedByAuthority(ctx, workspace, project, actor); err != nil {
		return Grant{}, err
	}
	value, ok, err := s.store.Get(ctx, workspace, project, id)
	if err != nil {
		return Grant{}, fmt.Errorf("read artifact record: %w", err)
	}
	if !ok {
		return Grant{}, problem.New(problem.CodeResourceNotFound, "")
	}
	if !eligible(value.State, purpose) || now.Before(value.CreatedAt) {
		return Grant{}, problem.New(problem.CodeArtifactAccessDenied, "")
	}
	grant := Grant{ArtifactID: value.ID, Digest: value.Digest, SecurityGeneration: value.SecurityGeneration, Purpose: purpose, ActorID: actor, ExpiresAt: now.Add(s.grantTTL)}
	url, err := s.reader.SignRead(ctx, value, grant, s.grantTTL)
	if err != nil {
		return Grant{}, err
	}
	if url == "" {
		return Grant{}, fmt.Errorf("artifact reader returned an empty signed URL")
	}
	grant.URL = url
	return grant, nil
}

// UseGrant admits one artifact access. Everything is verified before any
// bytes are disclosed: the current record's scope, digest, and security
// generation; the acting actor and the grant's purpose against the record's
// state; the grant's expiry; the signed capability itself together with its
// durable audited record and revocation state; and the current authority for
// the acting scope. Any failed axis denies access.
func (s *Service) UseGrant(ctx context.Context, workspace, project, actor string, grant Grant, now time.Time) (Record, error) {
	if actor == "" || actor != grant.ActorID || now.IsZero() || !now.Before(grant.ExpiresAt) || grant.URL == "" {
		return Record{}, problem.New(problem.CodeArtifactAccessDenied, "")
	}
	if err := s.permittedByAuthority(ctx, workspace, project, actor); err != nil {
		return Record{}, err
	}
	value, ok, err := s.store.Get(ctx, workspace, project, grant.ArtifactID)
	if err != nil {
		return Record{}, fmt.Errorf("read artifact record: %w", err)
	}
	if !ok {
		return Record{}, problem.New(problem.CodeResourceNotFound, "")
	}
	if now.Before(value.CreatedAt) || value.Digest != grant.Digest || value.SecurityGeneration != grant.SecurityGeneration || !eligible(value.State, grant.Purpose) {
		return Record{}, problem.New(problem.CodeArtifactAccessDenied, "")
	}
	if err := s.reader.Verify(ctx, value, grant); err != nil {
		return Record{}, problem.New(problem.CodeArtifactAccessDenied, "")
	}
	return value, nil
}

// SetLegalHold places or lifts the hold that makes an artifact undeletable. It
// decides whether the artifact can be destroyed, so it is an authorization
// change: it requires explicit custody authority for this operation, and it is
// recorded in the protected audit before it is applied and again after.
//
// The change is idempotent under its own decision identity. An attempt that
// applied the hold and was interrupted before its outcome could be recorded
// leaves the artifact one version on with exactly the hold this decision was
// making; the retry recognises its own completed work and finishes the
// decision rather than reporting a version conflict against itself.
func (s *Service) SetLegalHold(ctx context.Context, workspace, project string, id ID, expected uint64, hold bool, custody Custody, now time.Time) (Record, error) {
	if !custody.valid() || now.IsZero() || expected == 0 {
		return Record{}, problem.New(problem.CodeRequestInvalid, "")
	}
	if err := s.permittedToChangeCustody(ctx, workspace, project, custody.ActorID, id, LegalHoldCapability); err != nil {
		return Record{}, err
	}
	value, ok, err := s.store.Get(ctx, workspace, project, id)
	if err != nil {
		return Record{}, fmt.Errorf("read artifact record: %w", err)
	}
	if !ok {
		return Record{}, problem.New(problem.CodeResourceNotFound, "")
	}
	if value.DeletionClaim != "" {
		// This artifact's destruction is already durably owned, which means it
		// has already left every live state and its content may already be
		// gone. A hold that arrives now cannot stop that, so it is refused
		// rather than recorded: nothing is ever left holding an artifact whose
		// bytes no longer exist.
		return Record{}, problem.New(problem.CodeArtifactAccessDenied, "")
	}
	alreadyApplied := false
	if value.Version != expected {
		if value.Version != expected+1 || value.LegalHold != hold {
			return Record{}, problem.New(problem.CodeVersionConflict, "")
		}
		alreadyApplied = true
	}
	action := "artifact-legal-hold-lifted"
	if hold {
		action = "artifact-legal-hold-placed"
	}
	// The hold changes what may be done to the artifact, never its content, so
	// the audit record carries the same digest on both sides.
	if err := s.auditedChange(ctx, decisionIdentity(action, workspace, project, id, expected), action, value, custody, value.Digest, value.Digest, func(ctx context.Context) error {
		if alreadyApplied {
			return nil
		}
		next := value
		next.LegalHold = hold
		next.Version++
		next.UpdatedAt = now
		if _, err := s.store.Update(ctx, next, expected); err != nil {
			current, found, readErr := s.store.Get(ctx, workspace, project, id)
			if readErr == nil && found && current.Version == expected+1 && current.LegalHold == hold && current.DeletionClaim == "" {
				return nil
			}
			return err
		}
		return nil
	}); err != nil {
		return Record{}, err
	}
	return s.Get(ctx, workspace, project, id)
}

// Delete revokes every grant on an artifact and destroys its content. It is
// the most consequential authorization change the lifecycle has, so it
// requires explicit custody authority for destruction and is recorded in the
// protected audit before anything is revoked or destroyed.
//
// A destruction that is already durably owned is resumed under the decision
// that owns it rather than opened as a new one. Once ownership is taken the
// version precondition has been decided and the artifact has already left
// every live state, so there is nothing left for a caller's expectation to
// decide — only the remaining steps to finish. Without that, an interrupted
// deletion could never be completed by anyone: every retry would carry the
// version the claim had already moved past.
func (s *Service) Delete(ctx context.Context, workspace, project string, id ID, expected uint64, custody Custody, now time.Time) (Record, error) {
	if !custody.valid() || now.IsZero() {
		return Record{}, problem.New(problem.CodeRequestInvalid, "")
	}
	if err := s.permittedToChangeCustody(ctx, workspace, project, custody.ActorID, id, DeleteCapability); err != nil {
		return Record{}, err
	}
	value, ok, err := s.store.Get(ctx, workspace, project, id)
	if err != nil {
		return Record{}, fmt.Errorf("read artifact record: %w", err)
	}
	if !ok {
		return Record{}, problem.New(problem.CodeResourceNotFound, "")
	}
	own := decisionIdentity("artifact-deleted", workspace, project, id, expected)
	if value.State == Deleted && value.DeletionClaim != own {
		// The artifact is already destroyed, and not by this decision. There is
		// nothing left to decide about content that no longer exists, so the
		// tombstone is the answer rather than a second decision over it.
		return value, nil
	}
	decision := value.DeletionClaim
	if decision == "" {
		if value.LegalHold {
			return Record{}, problem.New(problem.CodeArtifactAccessDenied, "")
		}
		if expected == 0 || value.Version != expected {
			return Record{}, problem.New(problem.CodeVersionConflict, "")
		}
		decision = own
	}
	// The artifact's content ceases to exist, so the audit record carries the
	// digest that was and no digest that is.
	if err := s.auditedChange(ctx, decision, "artifact-deleted", value, custody, value.Digest, "", func(ctx context.Context) error {
		_, err := s.destroy(ctx, decision, value, custody.Reason, now)
		return err
	}); err != nil {
		return Record{}, err
	}
	return s.Get(ctx, workspace, project, id)
}

// destroy takes durable ownership of the artifact's destruction and only then
// revokes its grants, removes its content, and lands the tombstone.
//
// The order is the whole correctness argument. Revoking and deleting first,
// and moving the metadata afterwards, meant the irreversible half happened
// before the record had left its live states — so a legal hold or any other
// version change that landed in between made the closing compare-and-set fail
// and left a live, holdable record naming an object whose bytes were already
// gone. Ownership is taken by one compare-and-set that carries the artifact
// into a revocable terminal state in the same write. After it commits, a
// concurrent hold either won the version and stopped the deletion before
// anything was destroyed, or arrives at an artifact that has already left the
// live states and is refused.
//
// Every step after the claim is idempotent, so an interrupted destruction is
// finished by re-running it: the claim resumes for the decision that owns it,
// revocation is a no-op once nothing is outstanding, removing an absent object
// is a no-op, and the tombstone is recognised if it already landed.
func (s *Service) destroy(ctx context.Context, decision string, value Record, reason string, now time.Time) (Record, error) {
	if value.State == Deleted {
		return value, nil
	}
	terminal := Expired
	if value.State == Quarantined {
		terminal = Quarantined
	}
	claimed, err := s.store.ClaimDeletion(ctx, value.WorkspaceID, value.ProjectID, value.ID, value.Version, DeletionClaim{Decision: decision, Terminal: terminal, At: now})
	if err != nil {
		return Record{}, err
	}
	if claimed.State == Deleted {
		return claimed, nil
	}
	if err := s.reader.Revoke(ctx, claimed); err != nil {
		return Record{}, fmt.Errorf("revoke artifact grants: %w", err)
	}
	if err := s.objects.Delete(ctx, claimed.Reference); err != nil {
		return Record{}, fmt.Errorf("delete artifact object: %w", err)
	}
	next := claimed
	next.State = Deleted
	next.Version++
	next.SecurityGeneration++
	next.UpdatedAt = now
	deleted := now
	next.DeletedAt = &deleted
	next.DeletionReason = reason
	tombstoned, err := s.store.Update(ctx, next, claimed.Version)
	if err != nil {
		current, found, readErr := s.store.Get(ctx, value.WorkspaceID, value.ProjectID, value.ID)
		if readErr == nil && found && current.State == Deleted && current.DeletionClaim == decision {
			return current, nil
		}
		return Record{}, err
	}
	return tombstoned, nil
}

// Reconcile applies retention and orphan handling across the live corpus.
// Both outcomes revoke access, so both are recorded in the protected audit on
// the same terms an operator's revocation is: the record simply names the
// reconciler as the actor.
//
// One artifact never decides the fate of the others. A record whose
// reconciliation fails — including one whose decision the protected audit has
// already recorded — is reported and the sweep continues, so a single stuck
// artifact cannot hold the whole corpus's retention hostage.
func (s *Service) Reconcile(ctx context.Context, traceparent string, now time.Time) error {
	if now.IsZero() {
		return problem.New(problem.CodeRequestInvalid, "")
	}
	values, err := s.store.Snapshot(ctx)
	if err != nil {
		return fmt.Errorf("list artifact records: %w", err)
	}
	var failures []error
	for _, value := range values {
		if err := s.reconcileOne(ctx, value, traceparent, now); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func (s *Service) reconcileOne(ctx context.Context, value Record, traceparent string, now time.Time) error {
	exists, err := s.objects.Exists(ctx, value.Reference)
	if err != nil {
		return fmt.Errorf("read artifact object %s: %w", value.ID, err)
	}
	expire := func(record Record, reason string) (Record, error) {
		identity := decisionIdentity("artifact-expired", record.WorkspaceID, record.ProjectID, record.ID, record.Version)
		if err := s.auditedChange(ctx, identity, "artifact-expired", record, systemCustody(reason, traceparent), record.Digest, record.Digest, func(ctx context.Context) error {
			next := record
			next.State = Expired
			next.Version++
			next.SecurityGeneration++
			if err := s.reader.Revoke(ctx, next); err != nil {
				return fmt.Errorf("revoke expired artifact grants: %w", err)
			}
			next.UpdatedAt = now
			if _, err := s.store.Update(ctx, next, record.Version); err != nil {
				// An earlier attempt at this same decision may have applied it
				// and been interrupted before it could record the outcome.
				current, found, readErr := s.store.Get(ctx, record.WorkspaceID, record.ProjectID, record.ID)
				if readErr == nil && found && current.Version == record.Version+1 && current.State == Expired {
					return nil
				}
				return err
			}
			return nil
		}); err != nil {
			return Record{}, err
		}
		expired, err := s.Get(ctx, record.WorkspaceID, record.ProjectID, record.ID)
		if err != nil {
			return Record{}, err
		}
		return expired, nil
	}
	if value.State == Pending && now.Sub(value.CreatedAt) >= s.pendingTTL && !value.LegalHold {
		expired, err := expire(value, "retention-expired")
		if err != nil {
			return fmt.Errorf("reconcile expired artifact %s: %w", value.ID, err)
		}
		value = expired
	}
	if exists || value.State == Deleted {
		return nil
	}
	// An orphaned record routes through the revocable terminal states the
	// lifecycle permits before its tombstone lands.
	if value.State != Quarantined && value.State != Expired {
		expired, err := expire(value, "orphaned-object")
		if err != nil {
			return fmt.Errorf("reconcile orphaned artifact %s: %w", value.ID, err)
		}
		value = expired
	}
	orphaned := value
	decision := orphaned.DeletionClaim
	if decision == "" {
		decision = decisionIdentity("artifact-deleted", orphaned.WorkspaceID, orphaned.ProjectID, orphaned.ID, orphaned.Version)
	}
	// The sweep destroys an orphaned record through exactly the same ordered,
	// owned path an operator's deletion takes. A record whose object has
	// vanished is still a record whose grants must be withdrawn before its
	// tombstone lands, and the reconciler has no licence the operator lacks.
	if err := s.auditedChange(ctx, decision, "artifact-deleted", orphaned, systemCustody("orphaned-object", traceparent), orphaned.Digest, "", func(ctx context.Context) error {
		_, err := s.destroy(ctx, decision, orphaned, "orphaned-object", now)
		return err
	}); err != nil {
		return fmt.Errorf("reconcile artifact record %s: %w", orphaned.ID, err)
	}
	return nil
}

// SweepClock is the time source retention reconciliation reads. It is the
// same authoritative clock the rest of the lifecycle uses: retention decided
// against an unverified local clock could expire an artifact early.
type SweepClock interface{ Now() time.Time }

// Sweep runs retention and orphan reconciliation until the context ends. Each
// sweep opens its own trace: it is not continuing the trace of whatever
// created the artifacts it is reconciling, which may have completed in another
// process days earlier.
func (s *Service) Sweep(ctx context.Context, clock SweepClock, interval time.Duration, observe func(error)) {
	if interval <= 0 || interval > time.Hour {
		interval = 15 * time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		now := clock.Now()
		if now.IsZero() {
			// Authoritative time is unavailable. Retention is a decision about
			// elapsed time, so it is not one this sweep may make on a clock it
			// cannot trust; the next sweep tries again.
			if observe != nil {
				observe(fmt.Errorf("artifact reconciliation skipped: authoritative time is unavailable"))
			}
			continue
		}
		traceparent, err := sweepTraceparent()
		if err != nil {
			if observe != nil {
				observe(fmt.Errorf("artifact reconciliation could not open a trace: %w", err))
			}
			continue
		}
		if err := s.Reconcile(ctx, traceparent, now); err != nil && observe != nil && ctx.Err() == nil {
			observe(err)
		}
	}
}

// sweepTraceparent starts a new trace for one reconciliation sweep.
func sweepTraceparent() (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	// Both identifiers must be non-zero, which random bytes are with
	// overwhelming probability; a leading one is set so the format holds even
	// in the degenerate draw.
	raw[0] |= 1
	raw[16] |= 1
	return "00-" + hex.EncodeToString(raw[:16]) + "-" + hex.EncodeToString(raw[16:]) + "-01", nil
}

func allowed(current, next State) bool {
	switch current {
	case Pending:
		return next == Scanning || next == Quarantined || next == Expired
	case Scanning:
		return next == Valid || next == Quarantined || next == Expired
	case Valid:
		return next == Finalized || next == Quarantined || next == Expired
	case Finalized:
		return next == Committed || next == Quarantined || next == Expired
	case Committed:
		return next == Quarantined || next == Expired
	case Quarantined:
		return next == Deleted
	case Expired:
		return next == Deleted
	default:
		return false
	}
}

func eligible(state State, purpose Purpose) bool {
	switch purpose {
	case ProducerAccess, ScannerAccess:
		return state == Pending || state == Scanning
	case ReviewAccess, ApprovalAccess, ReadAccess:
		return state == Valid || state == Finalized || state == Committed
	case FinalizationAccess:
		return state == Valid
	case CommitAccess:
		return state == Finalized
	default:
		return false
	}
}
func lineage(value Lineage, run string) bool {
	return value.RunID == run && value.TaskID != "" && value.PhysicalAttemptID != "" && value.Producer.TaskID == value.TaskID && value.Producer.PhysicalAttemptID == value.PhysicalAttemptID && value.Producer.BuildIdentity != "" && value.Producer.Provider != "" && digest(value.BOMDigest) && digest(value.SchemaDigest) && digest(value.CatalogDigest)
}
func schema(value SchemaIdentity) bool {
	return value.Component != "" && len(value.Component) <= 256 && value.Version != "" && len(value.Version) <= 64 && digest(value.Digest)
}
func digest(value string) bool {
	if len(value) != 71 || value[:7] != "sha256:" {
		return false
	}
	for _, c := range value[7:] {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
func clone(value Record) Record {
	value.Lineage = cloneLineage(value.Lineage)
	if value.DeletedAt != nil {
		copyTime := *value.DeletedAt
		value.DeletedAt = &copyTime
	}
	if value.DeletionClaimedAt != nil {
		copyTime := *value.DeletionClaimedAt
		value.DeletionClaimedAt = &copyTime
	}
	return value
}
func cloneLineage(value Lineage) Lineage {
	value.Inputs = append([]ID(nil), value.Inputs...)
	return value
}

type MemoryObjects struct {
	lock       sync.Mutex
	values     map[string][]byte
	FailDelete bool
	// FailExists makes the store refuse to answer for the named object keys,
	// so a test can hold one artifact's reconciliation open while the rest of
	// the corpus is reconciled around it.
	FailExists map[string]bool
}

func NewMemoryObjects() *MemoryObjects { return &MemoryObjects{values: map[string][]byte{}} }
func (o *MemoryObjects) PutOnce(_ context.Context, ref Reference, value []byte) error {
	o.lock.Lock()
	defer o.lock.Unlock()
	key := ref.Bucket + "/" + ref.ObjectKey
	if previous, ok := o.values[key]; ok {
		if string(previous) != string(value) {
			return fmt.Errorf("write-once conflict")
		}
		return nil
	}
	o.values[key] = append([]byte(nil), value...)
	return nil
}
func (o *MemoryObjects) Delete(_ context.Context, ref Reference) error {
	o.lock.Lock()
	defer o.lock.Unlock()
	if o.FailDelete {
		return fmt.Errorf("injected delete failure")
	}
	delete(o.values, ref.Bucket+"/"+ref.ObjectKey)
	return nil
}
func (o *MemoryObjects) Exists(_ context.Context, ref Reference) (bool, error) {
	o.lock.Lock()
	defer o.lock.Unlock()
	if o.FailExists[ref.ObjectKey] {
		return false, fmt.Errorf("injected object lookup failure")
	}
	_, ok := o.values[ref.Bucket+"/"+ref.ObjectKey]
	return ok, nil
}
func (o *MemoryObjects) Restore(ref Reference, value []byte) {
	o.lock.Lock()
	defer o.lock.Unlock()
	o.values[ref.Bucket+"/"+ref.ObjectKey] = append([]byte(nil), value...)
}
