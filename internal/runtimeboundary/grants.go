package runtimeboundary

import (
	"net/http"

	"github.com/ancyloce/anvilkit-agent-service/contracts/generated/schema"
)

// serveContentGrant issues one artifact content grant to a dispatched attempt.
//
// The grant is scoped twice: the credential must bind a dispatched task, and
// the artifact must be material that task legitimately reaches — one of its
// own pinned artifact inputs, or a submission recorded under its run. An
// attempt cannot be granted content the dispatch never gave it a reason to
// hold.
func (b *Boundary) serveContentGrant(response http.ResponseWriter, httpRequest *http.Request) {
	call, ok := b.admit(response, httpRequest)
	if !ok {
		return
	}
	var request schema.IssueArtifactContentGrantRequest
	if err := decodeStrict(call.body, &request); err != nil {
		b.refuse(response, http.StatusUnprocessableEntity, "CONTRACT_INVALID", "the request is not a canonical content grant request")
		return
	}
	if !taskReaches(call.task, request.ArtifactId) {
		b.refuse(response, http.StatusForbidden, "NOT_AUTHORIZED", "the dispatched attempt does not reach this artifact")
		return
	}
	if b.cfg.Grants == nil {
		// This deployment stores no artifact objects a grant could be honoured
		// against (the candidate pipeline carries content-addressed pins, not
		// stored objects). The refusal is governed and truthful rather than a
		// grant to nothing.
		b.refuse(response, http.StatusConflict, "STATE_CONFLICT", "no stored content exists for this artifact in this deployment")
		return
	}
	binding := call.credential.Binding
	grant, err := b.cfg.Grants.Issue(httpRequest.Context(), binding.WorkspaceID, binding.ProjectID, request.ArtifactId, string(request.Purpose), binding.RuntimeUnitID)
	if err != nil {
		b.refuse(response, http.StatusConflict, "STATE_CONFLICT", "the grant could not be issued for this artifact")
		return
	}
	b.answerJSON(response, http.StatusCreated, grant)
}

// taskReaches reports whether the artifact is material the dispatched task was
// given: one of its pinned artifact inputs.
func taskReaches(task schema.AgentTask, artifactID string) bool {
	for _, input := range task.ArtifactInputs {
		if string(input.ArtifactId) == artifactID {
			return true
		}
	}
	return false
}
