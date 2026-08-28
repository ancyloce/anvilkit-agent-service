package runtimes

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/ancyloce/anvilkit-agent-service/contracts/generated/schema"
	"github.com/ancyloce/anvilkit-agent-service/internal/canonical"
)

// StatementPayloadType is the DSSE payload type the canonical profile assigns
// to a signed AgentRuntimeResult statement. It is bound into the signed bytes,
// so a statement cannot be replayed as a different kind of document.
const StatementPayloadType = "application/vnd.anvilkit.agent-runtime-result+json"

// StatementBytes is the canonical byte sequence a result's signature is taken
// over: the result document with the signature envelope removed, encoded as
// RFC 8785 canonical bytes.
func StatementBytes(result schema.AgentRuntimeResult) ([]byte, error) {
	encoded, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("runtime result statement: encode result: %w", err)
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &document); err != nil {
		return nil, fmt.Errorf("runtime result statement: decode result: %w", err)
	}
	delete(document, "signature")
	withoutEnvelope, err := json.Marshal(document)
	if err != nil {
		return nil, fmt.Errorf("runtime result statement: encode statement: %w", err)
	}
	canonicalBytes, err := canonical.Bytes(withoutEnvelope)
	if err != nil {
		return nil, fmt.Errorf("runtime result statement: %w", err)
	}
	return canonicalBytes, nil
}

// StatementDigest is the identity of the statement a runtime signed.
//
// The canonical profile defines that statement as the result document with the
// signature envelope removed — an envelope cannot be inside the bytes it signs
// — encoded as RFC 8785 canonical bytes. Recomputing it here rather than
// reading the digest the result carries is the point: the digest is what makes
// redelivery of the same result idempotent, and a value the sender chose could
// make two different results interchangeable.
//
// The runtime computes the same bytes with a different implementation. Only a
// canonical form makes the two agree.
func StatementDigest(result schema.AgentRuntimeResult) (string, error) {
	statement, err := StatementBytes(result)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(statement)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
