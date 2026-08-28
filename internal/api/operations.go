package api

import "strings"

// ServedPrefix is the path prefix the authenticated agent API is served under.
//
// The canonical description declares its paths without it and names the server
// separately, so the prefix belongs to the deployment rather than to the
// contract. It is stated here because the conformance gate has to compare a
// routed template against a described path, and a comparison that silently
// assumed one shape or the other would pass whichever way the two drifted.
const ServedPrefix = "/v1"

// Operation names one routed production operation: the canonical operation
// identity the description declares, and the method and path template the
// router answers it on.
type Operation struct {
	ID       string `json:"operationId"`
	Method   string `json:"method"`
	Template string `json:"template"`
}

// operations is the production routing table. It is the router's own account
// of what it serves, not a description beside it: every request is resolved
// against this table before it is dispatched, so a path the table does not
// name is not served at all.
//
// The table exists because "the contract declares an operation" and "the
// service answers it" were separate facts with nothing holding them together.
// Two governed operations were declared, generated, and documented while no
// production handler existed for either, and nothing failed — the description
// said they were there and every gate agreed with the description. The table
// is what a gate can check the router against.
//
// It is a function rather than a package-level slice because a slice would be
// modifiable at runtime by anything in the package, and a routing table that
// can be changed while the service is serving is not a table — it is state.
func operations() []Operation {
	return []Operation{
		{ID: "listAgentRuns", Method: "GET", Template: "/workspaces/{workspaceId}/agent-runs"},
		{ID: "createAgentRun", Method: "POST", Template: "/workspaces/{workspaceId}/agent-runs"},
		{ID: "getAgentRun", Method: "GET", Template: "/workspaces/{workspaceId}/agent-runs/{runId}"},
		{ID: "getAgentRunSnapshot", Method: "GET", Template: "/workspaces/{workspaceId}/agent-runs/{runId}/snapshot"},
		{ID: "streamAgentRunEvents", Method: "GET", Template: "/workspaces/{workspaceId}/agent-runs/{runId}/events"},
		{ID: "cancelAgentRun", Method: "POST", Template: "/workspaces/{workspaceId}/agent-runs/{runId}/cancel"},
		{ID: "retryAgentRun", Method: "POST", Template: "/workspaces/{workspaceId}/agent-runs/{runId}/retry"},
		{ID: "discardAgentRun", Method: "POST", Template: "/workspaces/{workspaceId}/agent-runs/{runId}/discard"},
		{ID: "respondToAgentInput", Method: "POST", Template: "/workspaces/{workspaceId}/agent-runs/{runId}/inputs/{requestId}/responses"},
		{ID: "decideAgentApproval", Method: "POST", Template: "/workspaces/{workspaceId}/agent-runs/{runId}/approvals/{requestId}/decisions"},
		{ID: "resolveAgentDomainOperation", Method: "POST", Template: "/workspaces/{workspaceId}/agent-runs/{runId}/domain-operations/{operationId}/resolution"},
		{ID: "issueApplyAuthorization", Method: "POST", Template: "/workspaces/{workspaceId}/agent-runs/{runId}/apply-authorizations"},
		{ID: "getAgentArtifact", Method: "GET", Template: "/workspaces/{workspaceId}/artifacts/{artifactId}"},
		{ID: "decideAgentArtifactCustody", Method: "POST", Template: "/workspaces/{workspaceId}/artifacts/{artifactId}/custody"},
		{ID: "issueAgentArtifactContentGrant", Method: "POST", Template: "/workspaces/{workspaceId}/artifacts/{artifactId}/content-grant"},
		// The runtime boundary: the internal operations a dispatched runtime
		// unit calls back on. Declared in the canonical runtime boundary
		// description (agent-runtime.openapi.json) rather than the public
		// service description, and served under task-credential admission.
		{ID: "invokeGovernedModel", Method: "POST", Template: "/internal/runtime/model-invocations"},
		{ID: "invokeGovernedContractRuntime", Method: "POST", Template: "/internal/runtime/contract-runtime-invocations"},
		{ID: "issueRuntimeArtifactContentGrant", Method: "POST", Template: "/internal/runtime/artifact-content-grants"},
		{ID: "submitRuntimeArtifact", Method: "POST", Template: "/internal/runtime/artifacts"},
	}
}

// Operations returns the production routing table.
func Operations() []Operation { return operations() }

// routedOperation answers which canonical operation a request addresses, or
// reports that the router serves nothing at that method and path.
//
// The path arrives already split, with the served prefix as its first segment.
// Matching is segment-wise against the template, and a template placeholder
// accepts exactly one non-empty segment — so a path with a segment too many or
// too few matches nothing rather than falling into the nearest branch.
func routedOperation(method string, parts []string) (Operation, bool) {
	if len(parts) == 0 || "/"+parts[0] != ServedPrefix {
		return Operation{}, false
	}
	addressed := parts[1:]
	for _, candidate := range operations() {
		if candidate.Method != method {
			continue
		}
		if matchesTemplate(candidate.Template, addressed) {
			return candidate, true
		}
	}
	return Operation{}, false
}

func matchesTemplate(template string, parts []string) bool {
	segments := strings.Split(strings.TrimPrefix(template, "/"), "/")
	if len(segments) != len(parts) {
		return false
	}
	for index, segment := range segments {
		if parts[index] == "" {
			return false
		}
		if strings.HasPrefix(segment, "{") && strings.HasSuffix(segment, "}") {
			continue
		}
		if segment != parts[index] {
			return false
		}
	}
	return true
}
