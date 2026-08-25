package runapp

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/artifacts"
	"github.com/ancyloce/anvilkit-agent-service/internal/auth"
	"github.com/ancyloce/anvilkit-agent-service/internal/canonical"
	contractguard "github.com/ancyloce/anvilkit-agent-service/internal/contracts"
	"github.com/ancyloce/anvilkit-agent-service/internal/execution"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/runs"
)

// The pinned canonical wire contracts this boundary is bound to: the command
// every request is proved against before anything is decoded, and the
// representation every issued grant is proved against before it leaves.
const (
	issueArtifactContentGrantRequestSchema = "anvilkit://schema/issue-artifact-content-grant-request?digest=sha256:2270580ea7b2e0226b8450130e4ee7312db2b101650fc012ea2f90823892c0b1"
	artifactContentGrantSchema             = "anvilkit://schema/artifact-content-grant?digest=sha256:d4608f216d773faf2747d5350440deb844e17d93a7602e06397d0f18d1c81a3c"
)

// IssueArtifactContentGrantRoute is the normalized route a content-grant
// receipt is scoped to. Like every other receipt route it is the template
// rather than a resolved path: key isolation is a property of the operation
// invoked, not of the identifiers the path carried. Which artifact is
// addressed is checked separately, against the resource the key was claimed
// for.
const IssueArtifactContentGrantRoute = "POST /workspaces/{workspaceId}/artifacts/{artifactId}/content-grant"

// ArtifactContentGrantRequestKind is the canonical command discriminator.
const ArtifactContentGrantRequestKind = "IssueArtifactContentGrantRequest"

// ArtifactContentGrantKind is the canonical representation discriminator.
const ArtifactContentGrantKind = "ArtifactContentGrant"

// ArtifactContentGrantIssuer is the governed artifact content surface. The
// execution pipeline satisfies it: it owns the current-authority read the
// disclosure is authorized against, the protected audit the decision is
// recorded in, and the artifact lifecycle that signs the access. This boundary
// only resolves a request into a scoped, authenticated command and renders
// what comes back.
type ArtifactContentGrantIssuer interface {
	IssueArtifactContentGrant(ctx context.Context, scope runs.Scope, id artifacts.ID, disclosure execution.ArtifactDisclosure, now time.Time) (execution.GovernedContentGrant, error)
}

// ArtifactContentGrantRequest is the canonical command as it arrives on the
// wire. It carries no identity: the reader, the workspace, and the project are
// derived from the verified request authority, and the canonical contract
// closes the object, so smuggling any of them in is structurally rejected
// before this shape is ever filled.
//
// The purpose is a body field rather than a header so that the canonical
// request digest covers it, which is what makes the idempotency key bind it: a
// retry under the same key declaring a different purpose is a different
// request, and is refused as key reuse rather than answered with a capability
// issued for a purpose nobody asked for.
type ArtifactContentGrantRequest struct {
	Kind       string `json:"kind"`
	ArtifactID string `json:"artifactId"`
	Purpose    string `json:"purpose"`
}

// ContentGrantInput is one grant request as transport received it. The
// workspace is the one addressed in the path and is checked against the
// verified authority rather than trusted; every other tenant coordinate comes
// from that authority alone.
type ContentGrantInput struct {
	WorkspaceID, ArtifactID, ETag, Key, Digest, Traceparent string
}

// WithArtifactContentGrants publishes the governed artifact content path
// together with the receipt store its idempotency is kept in and the time
// authority its grants are stamped and bounded from. They are bound as one for
// the same reason custody is: a governed issuance with no durable receipt has
// undefined replay semantics, and a capability whose expiry came from an
// unverified clock is one whose bound cannot be relied on. Neither half is
// separately installable, and an unbound path answers as unavailable rather
// than as absent — a caller must not learn from a 404 that a deployment simply
// has not composed this route.
func (a *App) WithArtifactContentGrants(issuer ArtifactContentGrantIssuer, receipts CommandReceipts, clock TimeAuthority) *App {
	a.contentGrants, a.contentGrantReceipts, a.contentGrantNow = issuer, receipts, clock
	return a
}

// IssueArtifactContentGrant authorizes and answers one governed request for
// bounded read access to an artifact's bytes.
//
// Content is deliberately not reachable from the metadata route. Metadata
// describes an artifact and changes nothing; bytes are the artifact, and
// handing them over is a disclosure that has to be decided, attributed, and
// bounded in time. Separate routes keep that difference visible rather than
// making it a flag on a read.
//
// Nothing about who is reading, or where, comes from the command. The scope is
// projected from verified claims by the validator; the reader is that scope's
// actor; the workspace in the path must be the workspace the caller proved
// authority for, and a mismatch is answered as an absent resource rather than
// as a denial, so the path cannot be used to enumerate other tenants'
// workspaces. The project is never in the path: it comes from the verified
// authority, which is what confines the lookup to the caller's own tenant.
//
// Whether this reader may read this artifact for this purpose is decided
// further in, against current authority re-read on this request, and the whole
// decision is taken inside a protected-audit record. A disclosure that cannot
// be recorded does not happen.
func (a *App) IssueArtifactContentGrant(ctx context.Context, claims auth.Claims, input ContentGrantInput, raw []byte) (Representation, error) {
	if a.contentGrants == nil || a.contentGrantReceipts == nil || a.contentGrantNow == nil {
		return Representation{}, problem.New(problem.CodeInfrastructureUnavailable, "")
	}
	if a.guard == nil {
		return Representation{}, fmt.Errorf("issue artifact content grant: the command guard is required")
	}
	scope, err := a.scope(ctx, claims, auth.OpAccessArtifact, input.WorkspaceID)
	if err != nil {
		return Representation{}, err
	}
	if input.ArtifactID == "" || len(input.ArtifactID) > 128 {
		return Representation{}, problem.New(problem.CodeRequestInvalid, "")
	}
	// The revision the reader observed is pinned. A grant binds the record's
	// digest and security generation, so without the precondition a reader
	// could be handed a capability for a version other than the one they read.
	version, err := artifacts.ParseETag(input.ETag, artifacts.ID(input.ArtifactID))
	if err != nil {
		return Representation{}, err
	}
	if input.Key == "" || len(input.Key) > 256 || !validTraceparent(input.Traceparent) {
		value := problem.New(problem.CodeRequestInvalid, "")
		value.Detail = "issuing an artifact content grant requires a bounded idempotency key and traceparent"
		return Representation{}, value
	}
	// The wire shape is proved against the pinned canonical contract before
	// anything is decoded: a command carrying a caller-owned server field — a
	// reader identity or a tenant coordinate above all — is structurally
	// rejected here, never silently trusted and never merely ignored.
	var command ArtifactContentGrantRequest
	if err := a.decodeCanonicalCommand(ctx, issueArtifactContentGrantRequestSchema, ArtifactContentGrantRequestKind, raw, &command); err != nil {
		return Representation{}, err
	}
	// The artifact identity is carried in both the addressed resource and the
	// command, so the canonical request digest covers which artifact is being
	// read. A request whose body names a different artifact than the resource
	// it was sent to is refused rather than redirected.
	if command.Kind != ArtifactContentGrantRequestKind || command.ArtifactID != input.ArtifactID {
		value := problem.New(problem.CodeRequestInvalid, "")
		value.Detail = "the request names a different artifact than the resource it addresses"
		return Representation{}, value
	}
	if err := verifyControlDigest(input.Digest, command); err != nil {
		return Representation{}, err
	}
	// The instant the grant is stamped and bounded from is resolved before the
	// key is claimed. An expiry is only a bound if the clock it came from was
	// the approved one, so a service that cannot read that clock does not issue
	// — and refusing here is what keeps an outage from reaching the artifact
	// lifecycle as a zero timestamp and being reported to the reader as a
	// malformed command. Which way the clock failed decides what the reader is
	// told: an authority briefly unreachable is a dependency to wait for, not a
	// denial that sends operators looking for authority nobody lost.
	now := a.contentGrantNow.Now()
	if now.IsZero() {
		if refusal := a.contentGrantNow.Refusal(); refusal != nil {
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
		// one subject's issued capability be replayed to another.
		Subject:    claims.Subject,
		Method:     ReceiptMethod,
		Route:      IssueArtifactContentGrantRoute,
		Key:        input.Key,
		ResourceID: input.ArtifactID,
		Digest:     input.Digest,
		Version:    version,
	}
	recorded, claim, replayed, err := a.contentGrantReceipts.Begin(ctx, receipt)
	if err != nil {
		return Representation{}, err
	}
	if replayed {
		// The recorded grant is returned exactly as it was issued, expiry
		// included, rather than re-minted with a fresh bound. A retry is the
		// same request, and answering it with a longer-lived capability would
		// let a caller extend a grant indefinitely by repeating itself. What
		// protects a grant that has since gone stale is redemption: every
		// access re-verifies the record's digest and security generation, the
		// grant's expiry, its revocation state, and current authority.
		return Representation{Body: recorded.Body, ETag: recorded.ETag, Replayed: true, Digest: input.Digest}, nil
	}
	governed, err := a.contentGrants.IssueArtifactContentGrant(ctx, scope, artifacts.ID(input.ArtifactID), execution.ArtifactDisclosure{
		Purpose:     command.Purpose,
		Traceparent: input.Traceparent,
	}, now)
	if err != nil {
		// The command produced no capability to record. The claim is released
		// so the key stays usable: holding it would convert a denial the reader
		// can correct into a key they can never retry with.
		_ = a.contentGrantReceipts.Abandon(ctx, receipt, claim)
		return Representation{}, err
	}
	body, err := a.contentGrantRepresentation(ctx, governed.Grant)
	if err != nil {
		_ = a.contentGrantReceipts.Abandon(ctx, receipt, claim)
		return Representation{}, err
	}
	outcome := CommandReceipt{Body: body}
	if err := a.contentGrantReceipts.Record(ctx, receipt, claim, outcome); err != nil {
		return Representation{}, err
	}
	return Representation{Body: outcome.Body, Digest: input.Digest}, nil
}

// contentGrantRepresentation renders one issued grant as the canonical
// ArtifactContentGrant and proves it against the pinned contract before it
// leaves.
//
// A grant the contract cannot describe is refused rather than served in a
// shape of its own: a client whose generated types reject a capability has a
// capability nobody can redeem, and it would fail at the consumer at a moment
// nobody chose.
func (a *App) contentGrantRepresentation(ctx context.Context, grant artifacts.Grant) ([]byte, error) {
	body, err := json.Marshal(artifactContentGrant{
		Kind:               ArtifactContentGrantKind,
		ArtifactID:         string(grant.ArtifactID),
		Digest:             grant.Digest,
		SecurityGeneration: grant.SecurityGeneration,
		Purpose:            string(grant.Purpose),
		ActorID:            grant.ActorID,
		URL:                grant.URL,
		ExpiresAt:          grant.ExpiresAt.UTC().Format(canonicalTimestamp),
	})
	if err != nil {
		return nil, fmt.Errorf("render artifact content grant: %w", err)
	}
	canonicalBody, err := canonical.Bytes(body)
	if err != nil {
		return nil, fmt.Errorf("canonicalize artifact content grant: %w", err)
	}
	if err := a.guard.Require(ctx, contractguard.ArtifactOut, artifactContentGrantSchema, canonicalBody); err != nil {
		return nil, fmt.Errorf("content grant violates the canonical ArtifactContentGrant contract: %w", err)
	}
	return canonicalBody, nil
}

// The canonical ArtifactContentGrant wire shape. It is written here rather
// than reused from the lifecycle's own grant because that grant is the
// service's state and this is a contract: the two are allowed to differ, and
// the place they are reconciled has to be one deliberate mapping.
type artifactContentGrant struct {
	Kind               string `json:"kind"`
	ArtifactID         string `json:"artifactId"`
	Digest             string `json:"digest"`
	SecurityGeneration uint64 `json:"securityGeneration"`
	Purpose            string `json:"purpose"`
	ActorID            string `json:"actorId"`
	URL                string `json:"url"`
	ExpiresAt          string `json:"expiresAt"`
}
