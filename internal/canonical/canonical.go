// Package canonical provides the approved strict RFC 8785 request identity.
package canonical

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/lattice-substrate/json-canon/jcs"

	"github.com/ancyloce/anvilkit-agent-service/contracts/validator"
)

func Bytes(raw []byte) ([]byte, error) {
	if _, err := validator.Admit(raw); err != nil {
		return nil, fmt.Errorf("strict JSON admission: %w", err)
	}
	canonical, err := jcs.Canonicalize(raw)
	if err != nil {
		return nil, fmt.Errorf("RFC 8785 canonicalization: %w", err)
	}
	return canonical, nil
}
func Digest(raw []byte) (string, error) {
	canonical, err := Bytes(raw)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}
