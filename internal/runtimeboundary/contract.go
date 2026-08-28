package runtimeboundary

import (
	"net/http"

	"github.com/ancyloce/anvilkit-agent-service/contracts/generated/schema"
)

// serveContractInvocation is the governed contract-runtime path: one bounded
// validation of one canonical input, for a dispatched attempt that presents
// its task-scoped credential.
func (b *Boundary) serveContractInvocation(response http.ResponseWriter, httpRequest *http.Request) {
	call, ok := b.admit(response, httpRequest)
	if !ok {
		return
	}
	var request schema.ContractRuntimeRequest
	if err := decodeStrict(call.body, &request); err != nil {
		b.refuse(response, http.StatusUnprocessableEntity, "CONTRACT_INVALID", "the request is not a canonical contract-runtime invocation")
		return
	}
	if request.Operation != schema.ContractRuntimeRequestOperationValidate {
		b.refuse(response, http.StatusUnprocessableEntity, "CONTRACT_INVALID", "this boundary serves validation invocations only")
		return
	}
	if b.cfg.Contracts == nil {
		b.refuse(response, http.StatusConflict, "STATE_CONFLICT", "no governed contract runtime is composed in this deployment")
		return
	}
	result, err := b.cfg.Contracts.Validate(httpRequest.Context(), request)
	if err != nil {
		b.refuse(response, http.StatusInternalServerError, "INTERNAL", "the governed contract runtime could not serve this invocation")
		return
	}
	b.answerJSON(response, http.StatusOK, result)
}
