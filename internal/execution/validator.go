package execution

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	contractvalidator "github.com/ancyloce/anvilkit-agent-service/contracts/validator"
	"github.com/ancyloce/anvilkit-agent-service/internal/agent"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
)

// PinnedSchemaValidator resolves schema references of the form
// anvilkit.contract.schema.<name> against the service's pinned canonical
// schema material and validates candidates with the strict runtime
// validator. Unknown components and digest mismatches fail closed.
type PinnedSchemaValidator struct {
	adapter *contractvalidator.Adapter
	pins    map[string]pinnedSchema
}

type pinnedSchema struct {
	uri    string
	digest string
}

const schemaComponentPrefix = "anvilkit.contract.schema."

func NewPinnedSchemaValidator(repositoryRoot string) (*PinnedSchemaValidator, error) {
	adapter, err := contractvalidator.New(repositoryRoot)
	if err != nil {
		return nil, fmt.Errorf("pinned schema validator: %w", err)
	}
	directory := filepath.Join(repositoryRoot, "contracts", "agent", "schemas")
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, fmt.Errorf("pinned schema validator: %w", err)
	}
	pins := make(map[string]pinnedSchema, len(entries))
	for _, entry := range entries {
		name, isSchema := strings.CutSuffix(entry.Name(), ".schema.json")
		if entry.IsDir() || !isSchema {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("pinned schema validator: %w", err)
		}
		digest := sha256.Sum256(raw)
		hexDigest := hex.EncodeToString(digest[:])
		pins[schemaComponentPrefix+name] = pinnedSchema{
			uri:    "anvilkit://schema/" + name + "?digest=sha256:" + hexDigest,
			digest: "sha256:" + hexDigest,
		}
	}
	if len(pins) == 0 {
		return nil, fmt.Errorf("pinned schema validator: no pinned canonical schemas found")
	}
	return &PinnedSchemaValidator{adapter: adapter, pins: pins}, nil
}

// Validate checks the candidate against the referenced pinned schema. The
// reference digest must match the pinned schema bytes exactly.
func (v *PinnedSchemaValidator) Validate(_ context.Context, reference agent.SchemaReference, candidate json.RawMessage) error {
	pin, known := v.pins[reference.ComponentName]
	if !known {
		details := problem.New(problem.CodeContractInvalid, "")
		details.Detail = "schema reference is not a pinned canonical component"
		return details
	}
	if pin.digest != reference.Digest {
		details := problem.New(problem.CodeContractInvalid, "")
		details.Detail = "schema reference digest does not match the pinned canonical schema"
		return details
	}
	if findings := v.adapter.Validate(pin.uri, candidate); len(findings) != 0 {
		details := problem.New(problem.CodeContractInvalid, "")
		details.Detail = fmt.Sprintf("candidate violates the pinned schema: %d findings", len(findings))
		return details
	}
	return nil
}
