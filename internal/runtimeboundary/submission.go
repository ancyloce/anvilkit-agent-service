package runtimeboundary

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/ancyloce/anvilkit-agent-service/contracts/generated/schema"
	"github.com/ancyloce/anvilkit-agent-service/internal/canonical"
	"github.com/ancyloce/anvilkit-agent-service/internal/execution"
)

// serveArtifactSubmission is the controlled artifact write: one governed
// candidate submission per attempt, answered with the immutable record the
// control plane holds for it.
//
// The submission is idempotent twice over, on purpose. The same attempt
// re-submitting the same bytes replays the recorded outcome — that is a
// network retry. Any attempt of the same run submitting the same bytes
// resolves to the same immutable artifact identity — that is what makes "the
// same result submitted repeatedly" one artifact rather than a growing family
// of identical ones. The same attempt submitting different bytes is a
// conflict, never a replacement: an immutable record does not have versions.
func (b *Boundary) serveArtifactSubmission(response http.ResponseWriter, httpRequest *http.Request) {
	call, ok := b.admit(response, httpRequest)
	if !ok {
		return
	}
	// The bytes submitted are the artifact. They must already be canonical:
	// an artifact recorded from non-canonical bytes would carry a digest
	// nothing else can recompute.
	canonicalBytes, err := canonical.Bytes(call.body)
	if err != nil || string(canonicalBytes) != string(call.body) {
		b.refuse(response, http.StatusUnprocessableEntity, "CONTRACT_INVALID", "a submission must be the canonical bytes of its document")
		return
	}
	// The canonical schema decides the shape before anything is recorded.
	if err := b.cfg.Validator.Validate(httpRequest.Context(), b.cfg.CandidateSchema, json.RawMessage(call.body)); err != nil {
		b.refuse(response, http.StatusUnprocessableEntity, "CONTRACT_INVALID", "the submission violates the canonical candidate contract")
		return
	}
	var candidate schema.PageCandidate
	if err := decodeStrict(call.body, &candidate); err != nil {
		b.refuse(response, http.StatusUnprocessableEntity, "CONTRACT_INVALID", "the submission is not a canonical candidate")
		return
	}
	digest := digestOf(call.body)
	binding := call.credential.Binding
	submission := Submission{
		WorkspaceID:         binding.WorkspaceID,
		ProjectID:           binding.ProjectID,
		RunID:               string(call.task.RunId),
		TaskID:              string(call.task.TaskId),
		PhysicalAttemptID:   binding.PhysicalAttemptID,
		ArtifactID:          string(execution.ArtifactRecordID(string(call.task.RunId), digest)),
		Digest:              digest,
		MediaType:           "application/json",
		SizeBytes:           len(call.body),
		Content:             call.body,
		SubmittedAt:         b.cfg.Now(),
		ExecutionGeneration: call.task.ExecutionGeneration,
		AttemptNumber:       call.task.AttemptNumber,
		LeaseEpoch:          call.task.LeaseEpoch,
	}
	recorded, replayed, err := b.cfg.Submissions.Record(httpRequest.Context(), submission)
	if err != nil {
		var conflict SubmissionConflictError
		if errors.As(err, &conflict) {
			b.refuse(response, http.StatusConflict, "IDEMPOTENCY_KEY_REUSED", "this attempt already submitted a different document")
			return
		}
		b.refuse(response, http.StatusInternalServerError, "INTERNAL", "the submission could not be recorded")
		return
	}
	status := http.StatusCreated
	if replayed {
		status = http.StatusOK
	}
	b.answerJSON(response, status, b.recordedArtifact(recorded))
}

// SubmissionConflictError reports a submission whose attempt identity already
// recorded a different document. It is typed so stores can report it without
// this package holding sentinel state.
type SubmissionConflictError struct{}

func (SubmissionConflictError) Error() string {
	return "the attempt already recorded a different submission"
}

// recordedArtifact renders the canonical account of one recorded submission.
//
// The kind is what the boundary just admitted: a canonical page candidate. The
// schema enum mirrors the artifact-kind registry (plan 0009 C4-04), so the
// registry's own value is recorded rather than a stand-in.
func (b *Boundary) recordedArtifact(submission Submission) schema.AgentArtifact {
	recordedAt := schema.SharedPrimitivesTimestamp(submission.SubmittedAt.UTC())
	return schema.AgentArtifact{
		Kind:         schema.AgentArtifactKindPageCandidate,
		ArtifactId:   schema.SharedPrimitivesOpaqueId(submission.ArtifactID),
		ContractType: "AgentArtifact",
		CreatedAt:    recordedAt,
		Digest:       schema.SharedPrimitivesDigest(submission.Digest),
		Lifecycle:    schema.AgentArtifactLifecyclePending,
		Lineage:      []schema.SharedPrimitivesArtifactReference{},
		Producer: schema.AgentArtifactProducer{
			TaskId:              schema.SharedPrimitivesOpaqueId(submission.TaskID),
			PhysicalAttemptId:   schema.SharedPrimitivesOpaqueId(submission.PhysicalAttemptID),
			ExecutionGeneration: submission.ExecutionGeneration,
			LeaseEpoch:          submission.LeaseEpoch,
			RecoveryEpoch:       0,
		},
		Reference: schema.AgentArtifactReference{
			Bucket: "anvilkit-agent-artifacts",
			// The object key is content-addressed under the run; the digest's
			// hex is the key's tail because the canonical key vocabulary does
			// not carry the algorithm prefix.
			ObjectKey: submission.RunID + "/" + strings.TrimPrefix(submission.Digest, "sha256:"),
			MediaType: submission.MediaType,
			SizeBytes: submission.SizeBytes,
		},
		Schema: schema.SharedPrimitivesSchemaReference{
			ComponentName: b.cfg.CandidateSchema.ComponentName,
			Digest:        schema.SharedPrimitivesDigest(b.cfg.CandidateSchema.Digest),
		},
		Validation: schema.AgentArtifactValidation{
			// The one validation this boundary performed before recording:
			// the canonical candidate schema over the exact submitted bytes.
			Checks: []schema.AgentArtifactValidationChecksElem{{
				Name:           "canonical-candidate-schema",
				Result:         schema.AgentArtifactValidationChecksElemResultPassed,
				EvidenceDigest: schema.SharedPrimitivesDigest(submission.Digest),
			}},
			ValidatedAt: recordedAt,
		},
	}
}
