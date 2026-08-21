// Package artifacts owns immutable artifact identity, lifecycle, grants, and reconciliation.
package artifacts

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/authority"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
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
type Service struct {
	store                Store
	objects              ObjectStore
	reader               Reader
	authority            authority.Source
	pendingTTL, grantTTL time.Duration
}

func New(store Store, objects ObjectStore, reader Reader, source authority.Source, pendingTTL, grantTTL time.Duration) (*Service, error) {
	if store == nil || objects == nil || reader == nil || source == nil || pendingTTL <= 0 || grantTTL <= 0 || grantTTL > 15*time.Minute {
		return nil, fmt.Errorf("artifact dependencies or TTLs are invalid")
	}
	return &Service{store: store, objects: objects, reader: reader, authority: source, pendingTTL: pendingTTL, grantTTL: grantTTL}, nil
}

// permittedByAuthority re-reads the one current-authority source for the
// acting scope. Artifact access is an external disclosure: issuing or using a
// grant under revoked or incomplete authority fails closed.
func (s *Service) permittedByAuthority(ctx context.Context, workspace, project, actor string) error {
	current, err := s.authority.Current(ctx, authority.Scope{WorkspaceID: workspace, ProjectID: project, ActorID: actor})
	if err != nil || !current.MaterialComplete() || !current.Active() {
		return problem.New(problem.CodeArtifactAccessDenied, "")
	}
	return nil
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
	value, ok, err := s.store.Get(ctx, workspace, project, id)
	if err != nil {
		return Grant{}, fmt.Errorf("read artifact record: %w", err)
	}
	if !ok {
		return Grant{}, problem.New(problem.CodeResourceNotFound, "")
	}
	if !eligible(value.State, purpose) || actor == "" || len(actor) > 128 || now.IsZero() || now.Before(value.CreatedAt) {
		return Grant{}, problem.New(problem.CodeArtifactAccessDenied, "")
	}
	if err := s.permittedByAuthority(ctx, workspace, project, actor); err != nil {
		return Grant{}, err
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
	value, ok, err := s.store.Get(ctx, workspace, project, grant.ArtifactID)
	if err != nil {
		return Record{}, fmt.Errorf("read artifact record: %w", err)
	}
	if !ok {
		return Record{}, problem.New(problem.CodeResourceNotFound, "")
	}
	if actor == "" || actor != grant.ActorID || now.IsZero() || !now.Before(grant.ExpiresAt) || now.Before(value.CreatedAt) || value.Digest != grant.Digest || value.SecurityGeneration != grant.SecurityGeneration || !eligible(value.State, grant.Purpose) {
		return Record{}, problem.New(problem.CodeArtifactAccessDenied, "")
	}
	if grant.URL == "" {
		return Record{}, problem.New(problem.CodeArtifactAccessDenied, "")
	}
	if err := s.reader.Verify(ctx, value, grant); err != nil {
		return Record{}, problem.New(problem.CodeArtifactAccessDenied, "")
	}
	if err := s.permittedByAuthority(ctx, workspace, project, actor); err != nil {
		return Record{}, err
	}
	return value, nil
}
func (s *Service) SetLegalHold(ctx context.Context, workspace, project string, id ID, expected uint64, hold bool, now time.Time) (Record, error) {
	value, ok, err := s.store.Get(ctx, workspace, project, id)
	if err != nil {
		return Record{}, fmt.Errorf("read artifact record: %w", err)
	}
	if !ok {
		return Record{}, problem.New(problem.CodeResourceNotFound, "")
	}
	if value.Version != expected {
		return Record{}, problem.New(problem.CodeVersionConflict, "")
	}
	value.LegalHold = hold
	value.Version++
	value.UpdatedAt = now
	return s.store.Update(ctx, value, expected)
}
func (s *Service) Delete(ctx context.Context, workspace, project string, id ID, expected uint64, reason string, now time.Time) (Record, error) {
	value, ok, err := s.store.Get(ctx, workspace, project, id)
	if err != nil {
		return Record{}, fmt.Errorf("read artifact record: %w", err)
	}
	if !ok {
		return Record{}, problem.New(problem.CodeResourceNotFound, "")
	}
	if value.State == Deleted {
		return value, nil
	}
	if value.LegalHold {
		return Record{}, problem.New(problem.CodeArtifactAccessDenied, "")
	}
	if value.Version != expected || reason == "" {
		return Record{}, problem.New(problem.CodeVersionConflict, "")
	}
	if err := s.reader.Revoke(ctx, value); err != nil {
		return Record{}, fmt.Errorf("revoke artifact grants: %w", err)
	}
	if err := s.objects.Delete(ctx, value.Reference); err != nil {
		return Record{}, fmt.Errorf("delete artifact object: %w", err)
	}
	// Deletion routes through the revocable terminal states the lifecycle
	// permits: a live artifact expires first, then the tombstone lands. Each
	// step is one CAS with one version and security-generation increment.
	if value.State != Quarantined && value.State != Expired {
		expiredStep := value
		expiredStep.State = Expired
		expiredStep.Version++
		expiredStep.SecurityGeneration++
		expiredStep.UpdatedAt = now
		next, err := s.store.Update(ctx, expiredStep, value.Version)
		if err != nil {
			return Record{}, err
		}
		value = next
	}
	expected = value.Version
	value.State = Deleted
	value.Version++
	value.SecurityGeneration++
	value.UpdatedAt = now
	deleted := now
	value.DeletedAt = &deleted
	value.DeletionReason = reason
	return s.store.Update(ctx, value, expected)
}
func (s *Service) Reconcile(ctx context.Context, now time.Time) error {
	values, err := s.store.Snapshot(ctx)
	if err != nil {
		return fmt.Errorf("list artifact records: %w", err)
	}
	for _, value := range values {
		exists, err := s.objects.Exists(ctx, value.Reference)
		if err != nil {
			return err
		}
		expire := func(record Record) (Record, error) {
			record.State = Expired
			record.Version++
			record.SecurityGeneration++
			if err := s.reader.Revoke(ctx, record); err != nil {
				return Record{}, fmt.Errorf("revoke expired artifact grants: %w", err)
			}
			record.UpdatedAt = now
			return s.store.Update(ctx, record, record.Version-1)
		}
		if value.State == Pending && now.Sub(value.CreatedAt) >= s.pendingTTL && !value.LegalHold {
			value, err = expire(value)
			if err != nil {
				return fmt.Errorf("reconcile expired artifact: %w", err)
			}
		}
		if !exists && value.State != Deleted {
			// An orphaned record routes through the revocable terminal states
			// the lifecycle permits before its tombstone lands.
			if value.State != Quarantined && value.State != Expired {
				value, err = expire(value)
				if err != nil {
					return fmt.Errorf("reconcile orphaned artifact: %w", err)
				}
			}
			expected := value.Version
			value.State = Deleted
			value.Version++
			value.SecurityGeneration++
			if err := s.reader.Revoke(ctx, value); err != nil {
				return fmt.Errorf("revoke orphaned artifact grants: %w", err)
			}
			value.UpdatedAt = now
			deleted := now
			value.DeletedAt = &deleted
			value.DeletionReason = "orphaned-object"
			if _, err := s.store.Update(ctx, value, expected); err != nil {
				return fmt.Errorf("reconcile artifact record: %w", err)
			}
		}
	}
	return nil
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
	_, ok := o.values[ref.Bucket+"/"+ref.ObjectKey]
	return ok, nil
}
func (o *MemoryObjects) Restore(ref Reference, value []byte) {
	o.lock.Lock()
	defer o.lock.Unlock()
	o.values[ref.Bucket+"/"+ref.ObjectKey] = append([]byte(nil), value...)
}
