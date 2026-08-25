package execution

import (
	"context"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/artifacts"
	"github.com/ancyloce/anvilkit-agent-service/internal/authority"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/runs"
	"github.com/ancyloce/anvilkit-agent-service/internal/securityaudit"
)

// ArtifactContentGrantIssuer signs bounded read access to one artifact's bytes.
//
// The artifact service already owns this: it knows the record, its security
// generation, and how to sign and later revoke what it signed. This port names
// the one capability the content surface needs rather than handing the whole
// service to it.
type ArtifactContentGrantIssuer interface {
	Grant(ctx context.Context, workspace, project string, id artifacts.ID, purpose artifacts.Purpose, actor string, now time.Time) (artifacts.Grant, error)
}

// GovernedContentGrant is a grant that has been decided and recorded.
type GovernedContentGrant struct {
	Grant artifacts.Grant
}

const (
	artifactContentAction   = "artifact-content-grant"
	artifactContentWorkload = "agent-service"
	artifactContentTicket   = "governed-artifact-content"
)

// IssueArtifactContentGrant decides whether one accessor may read one
// artifact's bytes, records the decision, and signs the access.
//
// Content is deliberately not reachable from the metadata surface. Metadata
// describes an artifact and changes nothing; bytes are the artifact, and
// handing them over is a disclosure that has to be decided, attributed, and
// bounded in time. Keeping them on separate routes keeps that difference
// visible instead of making it a flag on a read.
//
// The shape mirrors metadata disclosure on purpose: authority is proved before
// anything is read, and the grant and its account are one thing — a grant whose
// audit could not close is not returned, even when signing it succeeded.
func (e *Executor) IssueArtifactContentGrant(
	ctx context.Context,
	scope runs.Scope,
	id artifacts.ID,
	disclosure ArtifactDisclosure,
	now time.Time,
) (GovernedContentGrant, error) {
	if scope.WorkspaceID == "" || scope.ProjectID == "" || scope.ActorID == "" || id == "" {
		return GovernedContentGrant{}, problem.New(problem.CodeRequestInvalid, "")
	}
	if !artifacts.ValidPurpose(artifacts.Purpose(disclosure.Purpose)) || disclosure.Traceparent == "" {
		return GovernedContentGrant{}, problem.New(problem.CodeRequestInvalid, "")
	}
	if e.cfg.ArtifactContentGrants == nil || e.cfg.DisclosureAudit == nil {
		return GovernedContentGrant{}, problem.New(problem.CodeInfrastructureUnavailable, "")
	}
	if now.IsZero() {
		return GovernedContentGrant{}, problem.New(problem.CodeInfrastructureUnavailable, "")
	}

	requestDigest, err := deterministicDigest(struct {
		Workspace string `json:"workspace"`
		Project   string `json:"project"`
		Actor     string `json:"actor"`
		Artifact  string `json:"artifact"`
		Purpose   string `json:"purpose"`
		Kind      string `json:"kind"`
	}{scope.WorkspaceID, scope.ProjectID, scope.ActorID, string(id), disclosure.Purpose, artifactContentAction})
	if err != nil {
		return GovernedContentGrant{}, err
	}

	decision := securityaudit.Record{
		ID:     artifactDisclosureIdentity(requestDigest, disclosure.Traceparent),
		Action: artifactContentAction,
		// The accessor is the actor verified authority projected, never a name
		// the request carried.
		Actor:       scope.ActorID,
		Workload:    artifactContentWorkload,
		Reason:      "artifact content access granted for the declared purpose " + disclosure.Purpose,
		Ticket:      artifactContentTicket,
		Purpose:     disclosure.Purpose,
		NewDigest:   requestDigest,
		Traceparent: disclosure.Traceparent,
		Scope:       securityaudit.Scope{WorkspaceID: scope.WorkspaceID, ProjectID: scope.ProjectID, ResourceID: string(id)},
	}

	var governed GovernedContentGrant
	issue := func(ctx context.Context) error {
		// Proving authority before the record is touched keeps an unauthorized
		// caller from telling an artifact that exists from one that does not.
		current, err := e.cfg.Authority.Current(ctx, authority.Scope{
			WorkspaceID: scope.WorkspaceID, ProjectID: scope.ProjectID, ActorID: scope.ActorID,
		})
		if err != nil || !current.MaterialComplete() || !current.Active() {
			return problem.New(problem.CodeArtifactAccessDenied, "")
		}
		if current.TargetRevoked(string(id)) {
			return problem.New(problem.CodeArtifactAccessDenied, "")
		}
		grant, err := e.cfg.ArtifactContentGrants.Grant(
			ctx, scope.WorkspaceID, scope.ProjectID, id, artifacts.Purpose(disclosure.Purpose), scope.ActorID, now)
		if err != nil {
			return err
		}
		governed = GovernedContentGrant{Grant: grant}
		return nil
	}

	if err := e.cfg.DisclosureAudit.PrivilegedMutation(ctx, decision, issue); err != nil {
		return GovernedContentGrant{}, err
	}
	if governed.Grant.URL == "" {
		// The audit converged: this exact request under this exact trace was
		// already decided. The caller still needs an answer, and it is re-taken
		// rather than remembered — a caller whose authority has since been
		// withdrawn is refused instead of being handed a capability from a
		// decision that is no longer true. Re-issuing also means the returned
		// grant carries a fresh expiry rather than a stale one.
		if err := issue(ctx); err != nil {
			return GovernedContentGrant{}, err
		}
	}
	return governed, nil
}
