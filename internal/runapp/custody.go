package runapp

import (
	"context"
	"fmt"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/artifacts"
	"github.com/ancyloce/anvilkit-agent-service/internal/auth"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
)

// decideArtifactCustodyRequestSchema pins the canonical wire contract every
// custody command is validated against before anything is decoded.
const decideArtifactCustodyRequestSchema = "anvilkit://schema/decide-artifact-custody-request?digest=sha256:cb7411664588d1527de0ab3cb68f5f2e966fc2c2f466adfeb30dfa0c12e96c03"

// DecideArtifactCustodyRoute is the normalized route a custody receipt is
// scoped to. It is the route template rather than a resolved path, for the
// same reason every other receipt route is: key isolation is a property of the
// operation being invoked, not of which identifiers the path happened to
// carry. Which artifact is addressed is checked separately, against the
// resource the key was claimed for.
const DecideArtifactCustodyRoute = "POST /workspaces/{workspaceId}/artifacts/{artifactId}/custody"

// ArtifactCustodyKind is the canonical command discriminator.
const ArtifactCustodyKind = "DecideArtifactCustodyRequest"

// custodyWorkload is the workload every custody decision taken through this
// boundary is audited under. It is server-owned: the caller states what it is
// deciding, never what it is acting through.
const custodyWorkload = "agent-service.artifact-custody"

// ArtifactCustodian is the artifact lifecycle's custody surface: the legal
// hold that decides whether an artifact may be destroyed, and its destruction.
// The artifact service satisfies it. Every authorization decision stays behind
// this seam — the role the scope's subject register admits the actor under,
// the capability for the exact operation, the clearance for artifact content,
// and revocation of authority over this artifact — because that is where
// current authority is read and the protected audit is written. This boundary
// only resolves a request into a scoped, authenticated command.
type ArtifactCustodian interface {
	SetLegalHold(ctx context.Context, workspace, project string, id artifacts.ID, expected uint64, hold bool, custody artifacts.Custody, now time.Time) (artifacts.Record, error)
	Delete(ctx context.Context, workspace, project string, id artifacts.ID, expected uint64, custody artifacts.Custody, now time.Time) (artifacts.Record, error)
}

// ArtifactCustody is the canonical DecideArtifactCustodyRequest as it arrives
// on the wire. It carries no identity at all: the acting custodian, the
// workspace, and the project are derived from the verified request authority,
// and the canonical contract closes the object, so smuggling any of them in is
// structurally rejected before this shape is ever filled.
type ArtifactCustody struct {
	Kind       string `json:"kind"`
	ArtifactID string `json:"artifactId"`
	Decision   string `json:"decision"`
	Basis      string `json:"basis"`
	Ticket     string `json:"ticket"`
}

// The governed custody decisions. Placing and lifting the hold are separate
// decisions rather than a boolean, so the audited record names what was
// decided rather than a value that has to be read against the record's prior
// state to be understood.
const (
	CustodyLegalHoldPlaced = "legal-hold-placed"
	CustodyLegalHoldLifted = "legal-hold-lifted"
	CustodyDeleted         = "deleted"
)

// CustodyInput is one custody request as transport received it. The workspace
// is the one addressed in the path and is checked against the verified
// authority rather than trusted; every other tenant coordinate comes from that
// authority alone.
type CustodyInput struct {
	WorkspaceID, ArtifactID, ETag, Key, Digest, Traceparent string
}

// TimeAuthority is the approved time source as this boundary reads it: an
// instant, and — when it cannot give one — the governed reason.
//
// The reason is part of the port rather than an afterthought because the two
// ways time can fail lead somewhere different. An authority that is briefly
// unreachable says nothing about whether the caller may act; the honest answer
// is a retryable dependency failure. An authority whose answer failed its
// checks is a refusal that will not change, and telling a caller to retry that
// is telling them to ask a possibly hostile answer again. A clock that could
// only return the zero instant collapsed both into one denial.
type TimeAuthority interface {
	Now() time.Time
	// Refusal answers why the last reading gave no instant, or nil when it
	// gave one.
	Refusal() error
}

// WithArtifactCustody publishes the artifact custody path together with the
// receipt store its idempotency is kept in and the time authority its
// decisions are stamped from. They are bound as one because a governed
// mutation with no durable receipt has undefined replay semantics, and a
// lifecycle decision timed by an unverified clock is one whose ordering cannot
// be relied on. Neither half is separately installable, and an unbound custody
// path answers as unavailable rather than as absent.
func (a *App) WithArtifactCustody(custodian ArtifactCustodian, receipts CommandReceipts, clock TimeAuthority) *App {
	a.custodian, a.custodyReceipts, a.custodyNow = custodian, receipts, clock
	return a
}

// DecideArtifactCustody authenticates and authorizes one artifact custody
// decision, derives the acting custodian from the verified request authority,
// and hands the scoped command to the artifact lifecycle.
//
// Nothing about who is deciding, or where, comes from the command. The scope
// is projected from verified claims by the validator; the actor is that
// scope's actor; the workspace in the path must be the workspace the caller
// proved authority for, and a mismatch is answered as an absent resource
// rather than as a denial, so the path cannot be used to enumerate other
// tenants' workspaces. The project is never in the path at all: it comes from
// the verified authority, which is what confines the lookup below to the
// caller's own tenant.
//
// What may be done is decided further in, by the artifact lifecycle, against
// current authority re-read on this request — the custodian role, the
// capability for this exact operation, the clearance artifact content is
// governed under, and revocation of authority over this artifact — and every
// decision is written to the protected audit before it is applied and again
// after. A decision that cannot be audited is not made.
//
// Concurrency and idempotency keep the contract every other governed mutation
// keeps: If-Match pins the artifact revision the custodian observed, the
// canonical request digest pins the exact decision bytes, and the receipt is
// claimed before the command runs and recorded after it succeeds.
func (a *App) DecideArtifactCustody(ctx context.Context, claims auth.Claims, input CustodyInput, raw []byte) (Representation, error) {
	if a.custodian == nil || a.custodyReceipts == nil || a.custodyNow == nil {
		return Representation{}, problem.New(problem.CodeInfrastructureUnavailable, "")
	}
	if a.guard == nil {
		return Representation{}, fmt.Errorf("decide artifact custody: the command guard is required")
	}
	scope, err := a.scope(ctx, claims, auth.OpDecideArtifactCustody, input.WorkspaceID)
	if err != nil {
		return Representation{}, err
	}
	if input.ArtifactID == "" || len(input.ArtifactID) > 128 {
		return Representation{}, problem.New(problem.CodeRequestInvalid, "")
	}
	version, err := artifacts.ParseETag(input.ETag, artifacts.ID(input.ArtifactID))
	if err != nil {
		return Representation{}, err
	}
	if input.Key == "" || len(input.Key) > 256 || !validTraceparent(input.Traceparent) {
		value := problem.New(problem.CodeRequestInvalid, "")
		value.Detail = "a custody decision requires a bounded idempotency key and traceparent"
		return Representation{}, value
	}
	// The wire shape is proved against the pinned canonical contract before
	// anything is decoded: a command carrying a caller-owned server field — a
	// custodian identity or a tenant coordinate above all — is structurally
	// rejected here, never silently trusted and never merely ignored.
	var command ArtifactCustody
	if err := a.decodeCanonicalCommand(ctx, decideArtifactCustodyRequestSchema, ArtifactCustodyKind, raw, &command); err != nil {
		return Representation{}, err
	}
	// The artifact identity is carried in both the addressed resource and the
	// command, so the canonical request digest covers which artifact is being
	// decided. A decision whose body names a different artifact than the
	// resource it was sent to is refused rather than redirected.
	if command.Kind != ArtifactCustodyKind || command.ArtifactID != input.ArtifactID {
		value := problem.New(problem.CodeRequestInvalid, "")
		value.Detail = "the decision names a different artifact than the resource it addresses"
		return Representation{}, value
	}
	if err := verifyControlDigest(input.Digest, command); err != nil {
		return Representation{}, err
	}
	// The moment the decision is stamped with is resolved before the key is
	// claimed. A custody decision is recorded and ordered by the approved time
	// authority, so it is not one the service may make on a clock it cannot
	// read — and refusing here is what keeps that outage from reaching the
	// artifact lifecycle as a zero timestamp and being reported to the
	// custodian as a malformed command.
	//
	// What the custodian is told depends on which way the clock failed. A time
	// authority that is briefly unreachable is a dependency to wait for, and
	// answering that as a denial sent operators looking for a revoked
	// authority they never lost.
	now := a.custodyNow.Now()
	if now.IsZero() {
		if refusal := a.custodyNow.Refusal(); refusal != nil {
			return Representation{}, refusal
		}
		return Representation{}, problem.New(problem.CodeInfrastructureUnavailable, "")
	}
	receipt := CommandReceiptRequest{
		WorkspaceID: scope.WorkspaceID,
		ProjectID:   scope.ProjectID,
		// The subject is the verified credential subject, not the actor the
		// scope projects: under delegation several subjects may act as one
		// actor, and keying on the actor would merge their namespaces and let
		// one subject's recorded custody decision be replayed to another. The
		// audited custodian below is the actor, and stays so.
		Subject:    claims.Subject,
		Method:     ReceiptMethod,
		Route:      DecideArtifactCustodyRoute,
		Key:        input.Key,
		ResourceID: input.ArtifactID,
		Digest:     input.Digest,
		Version:    version,
	}
	recorded, claim, replayed, err := a.custodyReceipts.Begin(ctx, receipt)
	if err != nil {
		return Representation{}, err
	}
	if replayed {
		return Representation{ETag: recorded.ETag, Replayed: true, Digest: input.Digest}, nil
	}
	custody := artifacts.Custody{
		// The acting custodian is the authenticated actor the validator
		// projected into server-owned scope — never a body field.
		ActorID:     scope.ActorID,
		Workload:    custodyWorkload,
		Reason:      command.Basis,
		Ticket:      command.Ticket,
		Traceparent: input.Traceparent,
	}
	var record artifacts.Record
	switch command.Decision {
	case CustodyLegalHoldPlaced, CustodyLegalHoldLifted:
		record, err = a.custodian.SetLegalHold(ctx, scope.WorkspaceID, scope.ProjectID, artifacts.ID(input.ArtifactID), version, command.Decision == CustodyLegalHoldPlaced, custody, now)
	case CustodyDeleted:
		record, err = a.custodian.Delete(ctx, scope.WorkspaceID, scope.ProjectID, artifacts.ID(input.ArtifactID), version, custody, now)
	default:
		// The canonical contract admits only the governed decisions, so this
		// is unreachable through the contract guard above. It is here because
		// a decision this boundary does not understand must never fall
		// through to one it does.
		value := problem.New(problem.CodeRequestInvalid, "")
		value.Detail = "the custody decision is outside the governed vocabulary"
		err = value
	}
	if err != nil {
		// The command produced no outcome to record. The claim is released so
		// the key stays usable: holding it would convert a denial the
		// custodian can correct into a key they can never retry with.
		_ = a.custodyReceipts.Abandon(ctx, receipt, claim)
		return Representation{}, err
	}
	// The decision changes what may be done to the artifact rather than
	// producing a representation of it, so the recorded outcome is the
	// revision it produced. A replay reproduces exactly that.
	outcome := CommandReceipt{ETag: record.ETag()}
	if err := a.custodyReceipts.Record(ctx, receipt, claim, outcome); err != nil {
		return Representation{}, err
	}
	return Representation{ETag: outcome.ETag, Digest: input.Digest}, nil
}
