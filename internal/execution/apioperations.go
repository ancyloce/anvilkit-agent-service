package execution

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/artifacts"
	"github.com/ancyloce/anvilkit-agent-service/internal/authority"
	"github.com/ancyloce/anvilkit-agent-service/internal/interrupts"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/runs"
	"github.com/ancyloce/anvilkit-agent-service/internal/securityaudit"
	"github.com/ancyloce/anvilkit-agent-service/internal/workflow"
)

// ApplyAuthorizationIntent is one caller's request for a signed capability,
// resolved from the canonical command and carrying no server-owned field.
//
// Everything the signed authorization ends up asserting — issuer, subject,
// audience, key identity, validity window, and the bindings themselves — is
// resolved here from the run, the approval, and current authority. The intent
// states which run, which action, which artifact, which target, which base
// revision, and which approval it believes it is acting on, and every one of
// those is checked against what the service already knows rather than
// accepted.
type ApplyAuthorizationIntent struct {
	RunID           string
	ActionDigest    string
	ArtifactID      string
	ArtifactDigest  string
	ArtifactMedia   string
	ArtifactSize    int64
	TargetType      string
	TargetID        string
	TargetWorkspace string
	TargetProject   string
	BaseRevision    string
	// ApprovalRequestID and ApprovalDecisionVersion name the accepted
	// approval this authorization must bind. Both are re-proved.
	ApprovalRequestID       string
	ApprovalDecisionVersion uint64
	// ExpectedRunRevision is the run revision the caller observed. It is a
	// precondition, not a hint: a caller acting on a run that has moved is
	// acting on facts that may no longer hold.
	ExpectedRunRevision uint64
}

// IssueApplyAuthorization issues one signed apply authorization for a run,
// against facts re-proved on this request.
//
// The pipeline already issues authorizations on the commit path, where the
// workflow supplies its own durable operation identity. This is the same
// issuance reached from the API: a caller that has approved a candidate asks
// for the capability that lets the domain apply it. Nothing about the
// resulting capability comes from the caller — the caller only says which
// decision it means, and is refused if that is not the decision the service
// holds.
//
// The durable operation identity is derived from the intent rather than taken
// from the caller, so two identical requests converge on one issuance and one
// audited token. A caller's idempotency key governs the HTTP response replay
// above this boundary; this identity governs how many capabilities exist.
func (e *Executor) IssueApplyAuthorization(ctx context.Context, scope runs.Scope, intent ApplyAuthorizationIntent) (IssuedAuthorization, error) {
	if scope.WorkspaceID == "" || scope.ProjectID == "" || intent.RunID == "" {
		return IssuedAuthorization{}, problem.New(problem.CodeRequestInvalid, "")
	}
	// The run is read in the caller's own scope. A run in another workspace
	// or another project is not found here at all, so the surface cannot be
	// used to learn which run identities exist elsewhere.
	snapshot, err := e.cfg.Runs.Get(ctx, runs.Scope{WorkspaceID: scope.WorkspaceID, ProjectID: scope.ProjectID}, runs.ID(intent.RunID))
	if err != nil {
		return IssuedAuthorization{}, err
	}
	if snapshot.WorkspaceID != scope.WorkspaceID || snapshot.Target.ProjectID != scope.ProjectID {
		return IssuedAuthorization{}, problem.New(problem.CodeResourceNotFound, "")
	}
	if intent.ExpectedRunRevision != snapshot.Version {
		return IssuedAuthorization{}, problem.New(problem.CodeVersionConflict, "")
	}
	// The target the caller named must be the run's own target, in the
	// caller's own tenant. A capability is a permission to act on one thing;
	// naming a different thing than the run governs is not a request this
	// service can answer.
	if intent.TargetType != snapshot.Target.Type || intent.TargetID != snapshot.Target.ID ||
		intent.TargetWorkspace != snapshot.Target.WorkspaceID || intent.TargetProject != snapshot.Target.ProjectID {
		denied := problem.New(problem.CodeApplyAuthorizationDenied, "")
		denied.Detail = "the declared target is not the target this run governs"
		return IssuedAuthorization{}, denied
	}
	current, stale := e.currentAuthority(ctx, runs.Scope{WorkspaceID: snapshot.WorkspaceID, ProjectID: snapshot.Target.ProjectID, ActorID: snapshot.ActorID}, snapshot)
	if stale != nil {
		return IssuedAuthorization{}, *stale
	}
	if current.TargetRevoked(snapshot.Target.ID) {
		denied := problem.New(problem.CodeAuthorityStale, "")
		denied.Detail = "authority over this run's target is revoked"
		return IssuedAuthorization{}, denied
	}
	if current.ApprovalRevoked(intent.ApprovalRequestID) {
		denied := problem.New(problem.CodeAuthorityStale, "")
		denied.Detail = "the approval this authorization would bind is revoked"
		return IssuedAuthorization{}, denied
	}
	// The approval is re-read rather than trusted. The caller says which
	// approval it means; whether that approval was accepted, at which
	// decision version, and for which action digest are facts the service
	// holds.
	approval, err := e.cfg.InterruptReader.Approval(ctx, runs.Scope{WorkspaceID: snapshot.WorkspaceID, ProjectID: snapshot.Target.ProjectID, ActorID: snapshot.ActorID}, runs.ID(intent.RunID), interrupts.RequestID(intent.ApprovalRequestID))
	if err != nil {
		return IssuedAuthorization{}, problem.New(problem.CodeResourceNotFound, "")
	}
	if approval.Decision == nil || approval.Decision.Kind != interrupts.DecisionApprove || approval.ExpiredAt != nil {
		denied := problem.New(problem.CodeApplyAuthorizationDenied, "")
		denied.Detail = "the named approval carries no standing acceptance"
		return IssuedAuthorization{}, denied
	}
	if intent.ApprovalDecisionVersion != approval.Decision.RequestVersion {
		return IssuedAuthorization{}, problem.New(problem.CodeApprovalRequestStale, "")
	}
	if intent.ActionDigest != approval.ActionDigest {
		denied := problem.New(problem.CodeApplyAuthorizationDenied, "")
		denied.Detail = "the declared action is not the action that was approved"
		return IssuedAuthorization{}, denied
	}
	// The kernel's base revision is the durable approval checkpoint identity,
	// the same one the issuer's resolver derives. A caller that observed a
	// different one observed a different approval.
	if intent.BaseRevision != "rev:"+string(approval.ID) {
		return IssuedAuthorization{}, problem.New(problem.CodeVersionConflict, "")
	}
	// The artifact must be the run's own, eligible, and exactly the content
	// that was approved.
	if intent.ArtifactDigest != approval.ActionDigest {
		denied := problem.New(problem.CodeApplyAuthorizationDenied, "")
		denied.Detail = "the declared artifact is not the artifact that was approved"
		return IssuedAuthorization{}, denied
	}
	if err := e.verifyAuthorizedArtifact(ctx, snapshot, intent); err != nil {
		return IssuedAuthorization{}, err
	}
	operationKey := applyAuthorizationOperationKey(snapshot, intent)
	issued, err := e.cfg.CommitAuthority.Issue(ctx, AuthorizationRequest{
		IdempotencyKey:    operationKey,
		WorkspaceID:       snapshot.WorkspaceID,
		ProjectID:         snapshot.Target.ProjectID,
		RunID:             string(snapshot.RunID),
		ArtifactDigest:    intent.ArtifactDigest,
		ActionDigest:      approval.ActionDigest,
		ApprovalRequestID: intent.ApprovalRequestID,
	})
	if err != nil {
		return IssuedAuthorization{}, err
	}
	// The issuance is on the run's evidence stream before it is answered. A
	// signed capability that left the service with no internal account of who
	// obtained it and against which approval is exactly what an incident
	// needs and cannot reconstruct afterwards.
	if err := e.recordApplyAuthorizationEvidence(ctx, snapshot, operationKey, intent, issued); err != nil {
		return IssuedAuthorization{}, err
	}
	return issued, nil
}

// verifyAuthorizedArtifact re-reads the durable artifact record a caller named
// and proves the complete reference it declared against it.
//
// A caller states a whole artifact reference — identity, digest, media type,
// and size — and a signed capability is minted for it. Only the digest was
// ever checked, against the approval, and the identity was recomputed from the
// run and that digest; the media type and the size travelled from the request
// into the issuance untouched. That is a capability asserting facts the
// service never established, and a consumer that dispatches on media type or
// budgets on size is then being told what to do by the caller rather than by
// the artifact.
//
// So the record is read, in the caller's own tenant, and every field of the
// reference is answered from it. Which run produced the artifact, which
// workspace and project hold it, what lifecycle state it is in, and what was
// proved about its content are facts the service holds; a reference that
// disagrees with any of them is naming something other than the artifact this
// run had approved.
func (e *Executor) verifyAuthorizedArtifact(ctx context.Context, snapshot runs.Snapshot, intent ApplyAuthorizationIntent) error {
	deny := func(detail string) error {
		denied := problem.New(problem.CodeApplyAuthorizationDenied, "")
		denied.Detail = detail
		return denied
	}
	if intent.ArtifactID != string(ArtifactRecordID(string(snapshot.RunID), intent.ArtifactDigest)) {
		return deny("the declared artifact identity does not name this run's approved artifact")
	}
	// Read in the run's own workspace and project. An artifact held elsewhere
	// is absent here, so this cannot be used to learn which artifact
	// identities exist in another tenant.
	record, err := e.cfg.ArtifactMetadata.Get(ctx, snapshot.WorkspaceID, snapshot.Target.ProjectID, artifacts.ID(intent.ArtifactID))
	if err != nil {
		return err
	}
	if string(record.ID) != intent.ArtifactID || record.Digest != intent.ArtifactDigest {
		return deny("the durable artifact record does not attest the declared identity and digest")
	}
	if record.WorkspaceID != snapshot.WorkspaceID || record.ProjectID != snapshot.Target.ProjectID || record.RunID != string(snapshot.RunID) {
		return deny("the durable artifact record belongs to a different run, project, or workspace")
	}
	if record.Reference.MediaType != intent.ArtifactMedia {
		return deny("the declared artifact media type is not the media type the record attests")
	}
	if record.Reference.SizeBytes != intent.ArtifactSize {
		return deny("the declared artifact size is not the size the record attests")
	}
	// What was proved about the content, and that all of it passed. A record
	// whose validation is absent, malformed, or carries a failed check is not
	// something a capability to apply it can stand on.
	if !record.Validation.Valid() {
		return deny("the durable artifact record carries no validation a capability could stand on")
	}
	for _, check := range record.Validation.Checks {
		if check.Result != "passed" {
			return deny("the durable artifact record carries a validation check that did not pass")
		}
	}
	// Lifecycle eligibility is the artifact module's own answer rather than a
	// second reading of the state field here. Eligibility for a governed
	// effect is its decision, and two places deciding it is one place too
	// many: they drift, and the one that drifts is the one nobody is looking
	// at.
	eligibility, err := e.cfg.Artifacts.Eligible(ctx, ArtifactQuery{
		WorkspaceID:    snapshot.WorkspaceID,
		ProjectID:      snapshot.Target.ProjectID,
		RunID:          string(snapshot.RunID),
		ArtifactDigest: intent.ArtifactDigest,
	})
	if err != nil {
		return err
	}
	if !eligibility.Eligible {
		return deny("the artifact is not eligible for a governed effect: " + eligibility.Reason)
	}
	return nil
}

// applyAuthorizationOperationKey derives the durable operation identity one
// issuance is recorded under.
//
// It covers every field of the canonical command, so two requests that mean
// the same decision converge on one capability and a request that differs in
// any declared fact is a different operation. The media type, the size, and
// the target's own workspace and project used to be left out — they were
// carried into the issuance but not into its identity, which meant two
// requests differing only in those fields collided on one durable operation
// and the second silently received a capability minted for the first.
func applyAuthorizationOperationKey(snapshot runs.Snapshot, intent ApplyAuthorizationIntent) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		snapshot.WorkspaceID, snapshot.Target.ProjectID, string(snapshot.RunID),
		intent.RunID,
		intent.ApprovalRequestID, strconv.FormatUint(intent.ApprovalDecisionVersion, 10),
		intent.ActionDigest,
		intent.ArtifactID, intent.ArtifactDigest, intent.ArtifactMedia, strconv.FormatInt(intent.ArtifactSize, 10),
		intent.TargetType, intent.TargetID, intent.TargetWorkspace, intent.TargetProject,
		intent.BaseRevision,
		strconv.FormatUint(intent.ExpectedRunRevision, 10),
	}, "\x00")))
	return "apply-authorization." + hex.EncodeToString(sum[:16])
}

// recordApplyAuthorizationEvidence appends the internal account of one
// issuance. The evidence carries identities and digests, never the signed
// token: evidence is disclosed under its own clearance, and a capability
// readable from it would be a capability disclosed by reading about it.
//
// The evidence is correlated to the run's current durable execution, taken
// from the snapshot. It used to be built against an empty run input, which
// made the correlation identity ":g0" — not a bounded identifier — so the
// evidence failed its own contract and the issuance failed with it. This
// issuance is reached from the API rather than from inside the workflow, so
// the correlation has to be composed here; there is no ambient run input to
// inherit it from.
func (e *Executor) recordApplyAuthorizationEvidence(ctx context.Context, snapshot runs.Snapshot, operationKey string, intent ApplyAuthorizationIntent, issued IssuedAuthorization) error {
	occurredAt := e.cfg.Clock.Now()
	if occurredAt.IsZero() {
		return problem.New(problem.CodeInfrastructureUnavailable, "")
	}
	run := workflow.RunInput{
		Key:   workflow.RunKey{RunID: string(snapshot.RunID), Generation: snapshot.ExecutionGeneration},
		Scope: workflow.Scope{WorkspaceID: snapshot.WorkspaceID, ProjectID: snapshot.Target.ProjectID, ActorID: snapshot.ActorID},
	}
	payload := map[string]string{
		"authorizationId":   issued.AuthorizationID,
		"approvalRequestId": intent.ApprovalRequestID,
		"artifactId":        intent.ArtifactID,
		"actionDigest":      intent.ActionDigest,
		"expiresAt":         issued.ExpiresAt.UTC().Format(time.RFC3339Nano),
	}
	// The evidence identity is the durable operation identity, so a repeated
	// request that converges on one capability converges on one account of it
	// rather than stamping a second.
	// The registered evidence vocabulary already names this fact: a signed
	// commit authorization was issued. It is recorded under that type rather
	// than a second one of its own, because an incident reading the stream for
	// issued capabilities should find every one of them in one place — and
	// because a type outside the registered namespaces is refused by the
	// evidence contract, which is exactly what used to happen here.
	evidence, err := e.buildEvidence(workflow.OpID{WorkflowID: run.Key.WorkflowID(), Step: operationKey}, run, snapshot, "commit.authorization-issued", "audit", occurredAt, payload)
	if err != nil {
		return err
	}
	if _, err := e.cfg.Evidence.AppendEvidence(ctx, evidence); err != nil {
		return fmt.Errorf("record apply authorization evidence: %w", err)
	}
	return nil
}

// GovernedArtifact is one artifact as the governed metadata surface serves it.
type GovernedArtifact struct {
	Record artifacts.Record
}

// ArtifactDisclosure is what an accessor states about why they are reading an
// artifact, and the trace the reading belongs to. Both are recorded before
// anything is disclosed.
type ArtifactDisclosure struct {
	// Purpose is the governed access purpose the caller declared. It is
	// validated against the vocabulary at the transport boundary and recorded
	// verbatim here; this boundary does not infer one, because a purpose the
	// service invented is not a purpose anybody declared.
	Purpose string
	// Traceparent is the caller's trace. It is required: an audited
	// disclosure that cannot be tied back to the request that caused it is
	// half an account.
	Traceparent string
}

// artifactDisclosureAction, artifactDisclosureWorkload, and
// artifactDisclosureTicket are the server-owned terms every governed metadata
// disclosure is recorded under. The caller states what it is reading and why;
// it never states what it is acting through or under which record.
const (
	artifactDisclosureAction   = "artifact-metadata-disclosed"
	artifactDisclosureWorkload = "agent-service.artifact-metadata"
	artifactDisclosureTicket   = "artifact-metadata-disclosure"
)

// ArtifactMetadata reads one artifact's governed metadata in the caller's own
// tenant, against current authority re-read on this request, and records the
// disclosure in the protected audit before making it.
//
// Reading an artifact's metadata is a disclosure. It names what a tenant's
// agent produced, where its bytes live, what was checked about them, and what
// produced it — so it is answered under the same current-authority read the
// rest of the artifact lifecycle uses, and a caller whose authority no longer
// stands learns nothing about whether the artifact exists.
//
// Every part of the decision is taken inside the audited record: the accessor
// as the verified authority projected them, the purpose they declared, the
// tenant, the artifact, the outcome, and the trace. That ordering is the
// point. The record is written before the decision runs and its outcome after,
// so a disclosure that could not be recorded does not happen — an audit that is
// written afterwards is an audit that is missing exactly the reads that
// mattered, because the ones worth hiding are the ones where something went
// wrong between the read and the write.
//
// A refusal is recorded too, with the governed code it reached. Withdrawn
// authority is precisely the case an incident asks about afterwards, and a
// refusal that leaves no trace answers nothing.
//
// A destroyed artifact is answered as absent. Its record survives as a
// tombstone so the lifecycle can reason about it, but a tombstone is
// bookkeeping rather than a representation of content, and serving one would
// disclose that a workspace once held an artifact whose bytes are gone.
func (e *Executor) ArtifactMetadata(ctx context.Context, scope runs.Scope, id artifacts.ID, disclosure ArtifactDisclosure) (GovernedArtifact, error) {
	if scope.WorkspaceID == "" || scope.ProjectID == "" || scope.ActorID == "" || id == "" {
		return GovernedArtifact{}, problem.New(problem.CodeRequestInvalid, "")
	}
	if !artifacts.ValidPurpose(artifacts.Purpose(disclosure.Purpose)) || disclosure.Traceparent == "" {
		return GovernedArtifact{}, problem.New(problem.CodeRequestInvalid, "")
	}
	if e.cfg.ArtifactMetadata == nil || e.cfg.DisclosureAudit == nil {
		return GovernedArtifact{}, problem.New(problem.CodeInfrastructureUnavailable, "")
	}
	// The request digest names the exact disclosure being decided, so the
	// audited record is bound to one request rather than to a class of them.
	requestDigest, err := deterministicDigest(struct {
		Workspace string `json:"workspace"`
		Project   string `json:"project"`
		Actor     string `json:"actor"`
		Artifact  string `json:"artifact"`
		Purpose   string `json:"purpose"`
	}{scope.WorkspaceID, scope.ProjectID, scope.ActorID, string(id), disclosure.Purpose})
	if err != nil {
		return GovernedArtifact{}, err
	}
	decision := securityaudit.Record{
		ID:     artifactDisclosureIdentity(requestDigest, disclosure.Traceparent),
		Action: artifactDisclosureAction,
		// The accessor is the actor the verified authority projected, never a
		// name the request carried.
		Actor:    scope.ActorID,
		Workload: artifactDisclosureWorkload,
		Reason:   "governed artifact metadata disclosed for the declared purpose " + disclosure.Purpose,
		Ticket:   artifactDisclosureTicket,
		Purpose:  disclosure.Purpose,
		// The disclosure changes nothing, so what is digested is the request
		// it answers rather than a before-and-after of state that does not
		// move.
		NewDigest:   requestDigest,
		Traceparent: disclosure.Traceparent,
		Scope:       securityaudit.Scope{WorkspaceID: scope.WorkspaceID, ProjectID: scope.ProjectID, ResourceID: string(id)},
	}
	var governed GovernedArtifact
	disclose := func(ctx context.Context) error {
		// Authority is proved before the record is read, so an unauthorized
		// caller cannot tell an artifact that exists from one that does not.
		current, err := e.cfg.Authority.Current(ctx, authority.Scope{WorkspaceID: scope.WorkspaceID, ProjectID: scope.ProjectID, ActorID: scope.ActorID})
		if err != nil || !current.MaterialComplete() || !current.Active() {
			return problem.New(problem.CodeArtifactAccessDenied, "")
		}
		if current.TargetRevoked(string(id)) {
			return problem.New(problem.CodeArtifactAccessDenied, "")
		}
		record, err := e.cfg.ArtifactMetadata.Get(ctx, scope.WorkspaceID, scope.ProjectID, id)
		if err != nil {
			return err
		}
		if record.State == artifacts.Deleted {
			return problem.New(problem.CodeResourceNotFound, "")
		}
		governed = GovernedArtifact{Record: record}
		return nil
	}
	if err := e.cfg.DisclosureAudit.PrivilegedMutation(ctx, decision, disclose); err != nil {
		// Nothing is returned when the audit could not close, even if the
		// read itself succeeded inside it: the disclosure and its account are
		// one thing.
		return GovernedArtifact{}, err
	}
	if governed.Record.ID == "" {
		// The audit converged: this exact request, under this exact trace,
		// was already decided and recorded as disclosed, so the decision was
		// not taken a second time. The caller still has to be answered, and
		// the answer is the same disclosure the recorded decision authorized —
		// re-taken here rather than remembered, so a caller whose authority
		// has since been withdrawn is refused instead of being served from a
		// decision that is no longer true.
		if err := disclose(ctx); err != nil {
			return GovernedArtifact{}, err
		}
	}
	return governed, nil
}

// artifactDisclosureIdentity is the durable identity of one disclosure
// decision. Two attempts at the same read, under the same trace, are the same
// decision and converge on one record; a genuinely new request carries a new
// trace and is a new decision. Without the trace in the identity a caller
// reading the same artifact all day would leave one record, which is the
// opposite of an access log.
func artifactDisclosureIdentity(requestDigest, traceparent string) string {
	sum := sha256.Sum256([]byte(requestDigest + "\x00" + traceparent))
	return "artifact-disclosure." + hex.EncodeToString(sum[:16])
}

// ArtifactMetadataReader is the governed artifact metadata surface. The
// artifact service satisfies it.
type ArtifactMetadataReader interface {
	Get(ctx context.Context, workspace, project string, id artifacts.ID) (artifacts.Record, error)
}

// DisclosureAudit is the protected audit a governed disclosure is decided
// inside: the decision is recorded, then made, then its outcome recorded. The
// security audit service satisfies it, and it is the same one the artifact
// lifecycle records authorization changes through.
type DisclosureAudit interface {
	PrivilegedMutation(ctx context.Context, record securityaudit.Record, mutation securityaudit.Mutation) error
}
