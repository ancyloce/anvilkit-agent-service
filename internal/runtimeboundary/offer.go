package runtimeboundary

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/ancyloce/anvilkit-agent-service/contracts/generated/schema"
)

// Offered is the task document a register keeps for a dispatched attempt: the
// canonical task exactly as dispatched, with its fence token replaced by the
// token's digest.
//
// The fence token is a commit capability. It travels with the task and comes
// back in the signed result, and the dispatch record persists only its digest
// so that no reader of a durable record is handed the ability to commit an
// attempt it never ran. The offer is a durable record too, and nothing that
// reads it needs the token: a callback is bound to the offer by the identities
// the credential carries and by the task's own expiry and currency, never by
// the fence. The digest is kept in the token's place — it has the token's
// shape, so the stored document remains a canonical task, and it lets a reader
// prove which fence the task carried without being able to present it.
func Offered(task schema.AgentTask) schema.AgentTask {
	sum := sha256.Sum256([]byte(task.FenceToken))
	task.FenceToken = hex.EncodeToString(sum[:])
	return task
}
