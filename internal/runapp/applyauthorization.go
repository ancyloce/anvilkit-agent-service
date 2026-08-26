package runapp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/ancyloce/anvilkit-agent-service/internal/auth"
	"github.com/ancyloce/anvilkit-agent-service/internal/canonical"
	contractguard "github.com/ancyloce/anvilkit-agent-service/internal/contracts"
	"github.com/ancyloce/anvilkit-agent-service/internal/execution"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/runs"
)

// issueApplyAuthorizationRequestSchema and issuedApplyAuthorizationSchema pin
// the canonical wire contracts this operation is validated against — the
// command on the way in, and the representation on the way out. The response
// is validated too, because a representation that drifts from its contract is
// a broken integration that only the consumer discovers.
const issueApplyAuthorizationRequestSchema = "anvilkit://schema/issue-apply-authorization-request?digest=sha256:653d8dba345b8e1fae093dd491321a6cb4b5b7b56b896efe88c38739be0e8bca"
const issuedApplyAuthorizationSchema = "anvilkit://schema/issued-apply-authorization?digest=sha256:c9a436fa08c5e1c43c1bbfda5ad87e0b7aa4c1d2ada620929284028fbb7b3b5e"

// IssueApplyAuthorizationRoute is the normalized route an issuance receipt is
// scoped to.
const IssueApplyAuthorizationRoute = "POST /workspaces/{workspaceId}/agent-runs/{runId}/apply-authorizations"

// IssueApplyAuthorizationKind is the canonical command discriminator.
const IssueApplyAuthorizationKind = "IssueApplyAuthorizationRequest"

// IssuedApplyAuthorizationKind is the canonical representation discriminator.
const IssuedApplyAuthorizationKind = "IssuedApplyAuthorization"

// ApplyAuthorizationIssuer is the governed issuance path. The execution
// pipeline satisfies it: it owns the run aggregate, the approval record, the
// one current-authority source, the artifact owner, and the durable issuance
// audit, which is where every part of the decision has to be proved. This
// boundary only resolves a request into a scoped, authenticated intent.
type ApplyAuthorizationIssuer interface {
	IssueApplyAuthorization(ctx context.Context, scope runs.Scope, intent execution.ApplyAuthorizationIntent) (execution.IssuedAuthorization, error)
}

// ArtifactReference is the canonical shape of the artifact a command names.
type ArtifactReference struct {
	ArtifactID string `json:"artifactId"`
	Digest     string `json:"digest"`
	MediaType  string `json:"mediaType"`
	SizeBytes  int64  `json:"sizeBytes"`
}

// TargetReference is the canonical shape of the target a command names.
type TargetReference struct {
	TargetType  string `json:"targetType"`
	TargetID    string `json:"targetId"`
	WorkspaceID string `json:"workspaceId"`
	ProjectID   string `json:"projectId"`
}

// ApprovalReference names the accepted approval an authorization must bind.
type ApprovalReference struct {
	RequestID       string `json:"requestId"`
	DecisionVersion uint64 `json:"decisionVersion"`
}

// IssueApplyAuthorization is the canonical command as it arrives on the wire.
//
// It carries no server-owned field at all: the issuer, subject, audience, key
// identity, validity window, and every digest binding the signed
// authorization asserts are resolved from the run, the approval, and current
// authority. The canonical contract closes the object, so a caller attempting
// to supply any of them is structurally rejected before this shape is filled.
type IssueApplyAuthorization struct {
	Kind                string            `json:"kind"`
	RunID               string            `json:"runId"`
	ActionDigest        string            `json:"actionDigest"`
	Artifact            ArtifactReference `json:"artifact"`
	Target              TargetReference   `json:"target"`
	BaseRevision        string            `json:"baseRevision"`
	ApprovalReference   ApprovalReference `json:"approvalReference"`
	ExpectedRunRevision uint64            `json:"expectedRunRevision"`
}

// WithApplyAuthorization publishes the issuance path together with the receipt
// store its idempotency is kept in. They are bound as one for the same reason
// every other governed mutation binds them: an issuance with no durable
// receipt is one whose replay semantics are undefined, and this mutation mints
// a signed capability, which is the last thing that should be mintable twice
// because a client retried.
func (a *App) WithApplyAuthorization(issuer ApplyAuthorizationIssuer, receipts CommandReceipts) *App {
	a.authorizations, a.authorizationReceipts = issuer, receipts
	return a
}

// IssueApplyAuthorization authenticates and authorizes one apply-authorization
// issuance and hands the scoped intent to the execution pipeline.
//
// Nothing about who is asking, or where, comes from the command. The scope is
// projected from verified claims by the validator; the workspace in the path
// must be the workspace the caller proved authority for, and a mismatch is
// answered as an absent resource rather than as a denial, so the path cannot
// be used to enumerate other tenants' workspaces. The project is never in the
// path at all: it comes from the verified authority, and it is what confines
// the run lookup below to the caller's own tenant.
//
// Whether a capability may be issued is decided further in, against the run,
// the approval, the artifact, and current authority re-read on this request.
// The representation is the canonical document and the compact JWS that
// carries it, and the document is taken from the token rather than rebuilt
// beside it — so the contract's requirement that the two be byte-equivalent
// holds by construction rather than by two code paths agreeing.
func (a *App) IssueApplyAuthorization(ctx context.Context, claims auth.Claims, input ControlInput, raw []byte) (Representation, error) {
	if a.authorizations == nil || a.authorizationReceipts == nil {
		return Representation{}, problem.New(problem.CodeInfrastructureUnavailable, "")
	}
	if a.guard == nil {
		return Representation{}, fmt.Errorf("issue apply authorization: the command guard is required")
	}
	scope, err := a.scope(ctx, claims, auth.OpIssueAuthorization, input.WorkspaceID)
	if err != nil {
		return Representation{}, err
	}
	if input.RunID == "" || len(input.RunID) > 128 {
		return Representation{}, problem.New(problem.CodeRequestInvalid, "")
	}
	version, err := runs.ParseETag(input.ETag, runs.ID(input.RunID))
	if err != nil {
		return Representation{}, err
	}
	if input.Key == "" || len(input.Key) > 256 || !validTraceparent(input.Traceparent) {
		value := problem.New(problem.CodeRequestInvalid, "")
		value.Detail = "an issuance requires a bounded idempotency key and traceparent"
		return Representation{}, value
	}
	var command IssueApplyAuthorization
	if err := a.decodeCanonicalCommand(ctx, issueApplyAuthorizationRequestSchema, IssueApplyAuthorizationKind, raw, &command); err != nil {
		return Representation{}, err
	}
	// The run identity is carried in both the addressed resource and the
	// command, so the canonical request digest covers which run is being
	// authorized. A command whose body names a different run than the
	// resource it was sent to is refused rather than redirected.
	if command.Kind != IssueApplyAuthorizationKind || command.RunID != input.RunID {
		value := problem.New(problem.CodeRequestInvalid, "")
		value.Detail = "the command names a different run than the resource it addresses"
		return Representation{}, value
	}
	// The revision is stated twice — once as the concurrency precondition and
	// once inside the signed intent — and both must be the same observation.
	// They are separate fields because they answer different questions, and a
	// caller whose two answers disagree has not made one observation.
	if command.ExpectedRunRevision != version {
		value := problem.New(problem.CodeRequestInvalid, "")
		value.Detail = "the command's expected run revision does not match the If-Match precondition"
		return Representation{}, value
	}
	if err := verifyControlDigest(input.Digest, command); err != nil {
		return Representation{}, err
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
		Route:      IssueApplyAuthorizationRoute,
		Key:        input.Key,
		ResourceID: input.RunID,
		Digest:     input.Digest,
		Version:    version,
	}
	recorded, claim, replayed, err := a.authorizationReceipts.Begin(ctx, receipt)
	if err != nil {
		return Representation{}, err
	}
	if replayed {
		return Representation{Body: recorded.Body, ETag: recorded.ETag, Replayed: true, Digest: input.Digest}, nil
	}
	issued, err := a.authorizations.IssueApplyAuthorization(ctx, scope, execution.ApplyAuthorizationIntent{
		RunID:                   command.RunID,
		ActionDigest:            command.ActionDigest,
		ArtifactID:              command.Artifact.ArtifactID,
		ArtifactDigest:          command.Artifact.Digest,
		ArtifactMedia:           command.Artifact.MediaType,
		ArtifactSize:            command.Artifact.SizeBytes,
		TargetType:              command.Target.TargetType,
		TargetID:                command.Target.TargetID,
		TargetWorkspace:         command.Target.WorkspaceID,
		TargetProject:           command.Target.ProjectID,
		BaseRevision:            command.BaseRevision,
		ApprovalRequestID:       command.ApprovalReference.RequestID,
		ApprovalDecisionVersion: command.ApprovalReference.DecisionVersion,
		ExpectedRunRevision:     command.ExpectedRunRevision,
	})
	if err != nil {
		// No capability was issued, so the key is released and stays usable:
		// holding it would turn a denial the caller can correct into a key
		// they can never retry with.
		_ = a.authorizationReceipts.Abandon(ctx, receipt, claim)
		return Representation{}, err
	}
	body, err := a.issuedRepresentation(ctx, issued)
	if err != nil {
		_ = a.authorizationReceipts.Abandon(ctx, receipt, claim)
		return Representation{}, err
	}
	// The run has not moved: an issuance mints a capability without changing
	// the run, so the revision the caller pinned is the revision that still
	// stands.
	outcome := CommandReceipt{Body: body, ETag: "\"" + input.RunID + ":v" + strconv.FormatUint(version, 10) + "\""}
	if err := a.authorizationReceipts.Record(ctx, receipt, claim, outcome); err != nil {
		return Representation{}, err
	}
	return Representation{Body: outcome.Body, ETag: outcome.ETag, Digest: input.Digest}, nil
}

// issuedRepresentation renders the canonical IssuedApplyAuthorization.
//
// The authorization document is decoded from the token's own payload rather
// than composed beside it. The contract requires the two to be byte-equivalent
// after canonicalization, and the only way to be sure of that is for there to
// be one source: anything else is two renderings that agree until one of them
// changes.
func (a *App) issuedRepresentation(ctx context.Context, issued execution.IssuedAuthorization) ([]byte, error) {
	segments := strings.Split(issued.CompactJWS, ".")
	if len(segments) != 3 {
		return nil, fmt.Errorf("issued authorization: the signed capability is not a compact JWS")
	}
	payload, err := base64.RawURLEncoding.DecodeString(segments[1])
	if err != nil {
		return nil, fmt.Errorf("issued authorization: decode signed payload: %w", err)
	}
	document, err := canonical.Bytes(payload)
	if err != nil {
		return nil, fmt.Errorf("issued authorization: canonicalize signed payload: %w", err)
	}
	body, err := json.Marshal(struct {
		Kind          string          `json:"kind"`
		Authorization json.RawMessage `json:"authorization"`
		CompactJWS    string          `json:"compactJws"`
	}{IssuedApplyAuthorizationKind, document, issued.CompactJWS})
	if err != nil {
		return nil, fmt.Errorf("issued authorization: render representation: %w", err)
	}
	canonicalBody, err := canonical.Bytes(body)
	if err != nil {
		return nil, fmt.Errorf("issued authorization: canonicalize representation: %w", err)
	}
	// The representation is proved against its pinned contract before it
	// leaves. A capability served in a shape no consumer's generated client
	// accepts is a capability nobody can redeem.
	if err := a.guard.Require(ctx, contractguard.AuthorizationOut, issuedApplyAuthorizationSchema, canonicalBody); err != nil {
		return nil, fmt.Errorf("issued authorization violates the canonical IssuedApplyAuthorization contract: %w", err)
	}
	return canonicalBody, nil
}
