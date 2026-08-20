package agent

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
)

// Approval is the verified pinned contract identity an approved definition
// catalog must be bound to: the canonical Profile, the canonical lock, and
// the digest of every governed schema. It is produced by verifying the
// service's pinned contract intake, never asserted by the catalog itself.
type Approval struct {
	ProfileDigest string
	LockDigest    string
	SchemaDigests map[string]string
}

func (a Approval) valid() bool {
	return validDigest(a.ProfileDigest) && validDigest(a.LockDigest) && len(a.SchemaDigests) != 0
}

// CatalogApproval is the binding a catalog claims to the approved boundary.
type CatalogApproval struct {
	ProfileDigest string `json:"profileDigest"`
	LockDigest    string `json:"lockDigest"`
}

// CatalogDefinition binds one Agent definition document, its instruction
// bytes, and its frozen identity digest.
type CatalogDefinition struct {
	DefinitionID      string `json:"definitionId"`
	DefinitionDigest  string `json:"definitionDigest"`
	Document          string `json:"document"`
	DocumentDigest    string `json:"documentDigest"`
	Instruction       string `json:"instruction"`
	InstructionDigest string `json:"instructionDigest"`
}

// CatalogPolicy binds one model, memory, or Guardrail policy document.
type CatalogPolicy struct {
	PolicyID       string `json:"policyId"`
	Version        string `json:"version"`
	Kind           string `json:"kind"`
	Document       string `json:"document"`
	DocumentDigest string `json:"documentDigest"`
}

// ToolBinding is the complete ToolDefinition the catalog approves for one
// Tool component. The argument-schema digest alone leaves capability, side
// effects, risk, approval requirements, and the timeout and retry policy
// unattested, which lets a process dispatch a tool whose authority and blast
// radius are not the ones the definition froze. Everything a dispatch
// decision depends on is therefore part of the signed binding.
type ToolBinding struct {
	ToolID              string          `json:"toolId"`
	Capability          string          `json:"capability"`
	SideEffectClass     string          `json:"sideEffectClass"`
	RiskClass           string          `json:"riskClass"`
	ApprovalPolicy      PolicyReference `json:"approvalPolicy"`
	TimeoutMilliseconds int             `json:"timeoutMilliseconds"`
	MaximumAttempts     int             `json:"maximumAttempts"`
	BackoffMilliseconds int             `json:"backoffMilliseconds"`
	Retryability        []string        `json:"retryability"`
	AcceptedDataClasses []string        `json:"acceptedDataClasses"`
}

// validate enforces every bound the frozen ToolDefinition vocabulary carries.
func (b ToolBinding) validate(componentName string) error {
	if b.ToolID != componentName {
		return fmt.Errorf("tool definition identity %q is not the approved component %q", b.ToolID, componentName)
	}
	if b.Capability == "" || len(b.Capability) > 128 {
		return fmt.Errorf("tool %s declares no bounded capability", componentName)
	}
	switch b.SideEffectClass {
	case "read", "write", "domain-effect":
	default:
		return fmt.Errorf("tool %s side effect class %q is outside the frozen vocabulary", componentName, b.SideEffectClass)
	}
	switch b.RiskClass {
	case "low", "medium", "high":
	default:
		return fmt.Errorf("tool %s risk class %q is outside the frozen vocabulary", componentName, b.RiskClass)
	}
	if !validPolicyReference(b.ApprovalPolicy) {
		return fmt.Errorf("tool %s approval policy reference is incomplete", componentName)
	}
	if b.TimeoutMilliseconds < 1 || b.TimeoutMilliseconds > 600000 {
		return fmt.Errorf("tool %s timeout is outside the frozen bound", componentName)
	}
	if b.MaximumAttempts < 1 || b.MaximumAttempts > 8 {
		return fmt.Errorf("tool %s attempt bound is outside the frozen bound", componentName)
	}
	if b.BackoffMilliseconds < 0 || b.BackoffMilliseconds > 60000 {
		return fmt.Errorf("tool %s backoff is outside the frozen bound", componentName)
	}
	if len(b.Retryability) < 1 || len(b.Retryability) > 4 {
		return fmt.Errorf("tool %s declares no bounded retryability", componentName)
	}
	for _, value := range b.Retryability {
		switch value {
		case "safe-immediate", "safe-after-backoff", "operator-action", "never":
		default:
			return fmt.Errorf("tool %s retryability %q is outside the frozen vocabulary", componentName, value)
		}
	}
	if len(b.AcceptedDataClasses) < 1 || len(b.AcceptedDataClasses) > 4 {
		return fmt.Errorf("tool %s declares no bounded accepted data classes", componentName)
	}
	for _, value := range b.AcceptedDataClasses {
		switch value {
		case "public", "internal", "confidential", "restricted":
		default:
			return fmt.Errorf("tool %s data class %q is outside the frozen vocabulary", componentName, value)
		}
	}
	return nil
}

// clone returns an independent copy so a caller can never mutate approved
// material through a returned binding.
func (b ToolBinding) clone() ToolBinding {
	b.Retryability = append([]string(nil), b.Retryability...)
	b.AcceptedDataClasses = append([]string(nil), b.AcceptedDataClasses...)
	return b
}

// CatalogToolSchema approves one Tool component: its argument schema digest
// and the complete ToolDefinition the process is allowed to dispatch. The
// schema bytes live with the Tool implementation, so the catalog approves the
// identity and the running Tool material is checked against it at run time.
type CatalogToolSchema struct {
	ComponentName string      `json:"componentName"`
	Digest        string      `json:"digest"`
	Definition    ToolBinding `json:"definition"`
}

// Catalog is the approved Agent definition catalog: the authenticated list of
// every definition, instruction, policy, and Tool schema the service is
// allowed to run, bound to the approved contract boundary. A definition that
// is not in the catalog, or whose bytes do not match it, is not an approved
// definition no matter how self-consistent it is.
type Catalog struct {
	Kind           string              `json:"kind"`
	CatalogVersion int                 `json:"catalogVersion"`
	Approval       CatalogApproval     `json:"approval"`
	Definitions    []CatalogDefinition `json:"definitions"`
	Policies       []CatalogPolicy     `json:"policies"`
	ToolSchemas    []CatalogToolSchema `json:"toolSchemas"`
}

const (
	maximumCatalogBytes    = 262144
	maximumCatalogEntries  = 64
	maximumDocumentNameLen = 128
)

// ParseCatalog strictly decodes and bounds-checks one catalog document.
func ParseCatalog(raw []byte) (Catalog, error) {
	if len(raw) == 0 || len(raw) > maximumCatalogBytes {
		return Catalog{}, fmt.Errorf("agent catalog: document exceeds the bounded contract")
	}
	var catalog Catalog
	if err := strictDecode(raw, &catalog); err != nil {
		return Catalog{}, fmt.Errorf("agent catalog: %w", err)
	}
	if catalog.Kind != "AgentDefinitionCatalog" || catalog.CatalogVersion != 1 {
		return Catalog{}, fmt.Errorf("agent catalog: kind and catalog version are outside the frozen contract")
	}
	if !validDigest(catalog.Approval.ProfileDigest) || !validDigest(catalog.Approval.LockDigest) {
		return Catalog{}, fmt.Errorf("agent catalog: the approval binding is missing or malformed")
	}
	if len(catalog.Definitions) < 1 || len(catalog.Definitions) > maximumCatalogEntries {
		return Catalog{}, fmt.Errorf("agent catalog: the definition set is empty or unbounded")
	}
	if len(catalog.Policies) > maximumCatalogEntries || len(catalog.ToolSchemas) > maximumCatalogEntries {
		return Catalog{}, fmt.Errorf("agent catalog: the policy or tool schema set is unbounded")
	}
	seenDefinitions := make(map[string]struct{}, len(catalog.Definitions))
	for _, entry := range catalog.Definitions {
		if !validComponentID(entry.DefinitionID) || !validDigest(entry.DefinitionDigest) || !validDigest(entry.DocumentDigest) || !validDigest(entry.InstructionDigest) || !validDocumentName(entry.Document) || !validDocumentName(entry.Instruction) {
			return Catalog{}, fmt.Errorf("agent catalog: definition entry %q is malformed", entry.DefinitionID)
		}
		if _, duplicate := seenDefinitions[entry.DefinitionID]; duplicate {
			return Catalog{}, fmt.Errorf("agent catalog: duplicate definition entry %q", entry.DefinitionID)
		}
		seenDefinitions[entry.DefinitionID] = struct{}{}
	}
	seenPolicies := make(map[string]struct{}, len(catalog.Policies))
	for _, entry := range catalog.Policies {
		if entry.PolicyID == "" || len(entry.PolicyID) > 128 || entry.Version == "" || len(entry.Version) > 64 || entry.Kind == "" || !validDigest(entry.DocumentDigest) || !validDocumentName(entry.Document) {
			return Catalog{}, fmt.Errorf("agent catalog: policy entry %q is malformed", entry.PolicyID)
		}
		key := entry.PolicyID + "\x00" + entry.Version
		if _, duplicate := seenPolicies[key]; duplicate {
			return Catalog{}, fmt.Errorf("agent catalog: duplicate policy entry %q", entry.PolicyID)
		}
		seenPolicies[key] = struct{}{}
	}
	seenTools := make(map[string]struct{}, len(catalog.ToolSchemas))
	for _, entry := range catalog.ToolSchemas {
		if entry.ComponentName == "" || len(entry.ComponentName) > 160 || !validDigest(entry.Digest) {
			return Catalog{}, fmt.Errorf("agent catalog: tool schema entry %q is malformed", entry.ComponentName)
		}
		if err := entry.Definition.validate(entry.ComponentName); err != nil {
			return Catalog{}, fmt.Errorf("agent catalog: %w", err)
		}
		if _, duplicate := seenTools[entry.ComponentName]; duplicate {
			return Catalog{}, fmt.Errorf("agent catalog: duplicate tool schema entry %q", entry.ComponentName)
		}
		seenTools[entry.ComponentName] = struct{}{}
	}
	return catalog, nil
}

// Authenticate proves the catalog is bound to the approved contract boundary
// this service actually verified at startup. A catalog produced against a
// different Profile or lock is refused rather than trusted.
func (c Catalog) Authenticate(approval Approval) error {
	if !approval.valid() {
		return fmt.Errorf("agent catalog: the approved contract identity is unavailable")
	}
	if !equalDigest(c.Approval.ProfileDigest, approval.ProfileDigest) {
		return fmt.Errorf("agent catalog: the catalog is not bound to the approved canonical profile")
	}
	if !equalDigest(c.Approval.LockDigest, approval.LockDigest) {
		return fmt.Errorf("agent catalog: the catalog is not bound to the approved canonical lock")
	}
	return nil
}

// validDocumentName bounds a catalog document reference to a plain file name
// inside the definition store. Path traversal and absolute names are refused.
func validDocumentName(value string) bool {
	if value == "" || len(value) > maximumDocumentNameLen {
		return false
	}
	if bytes.ContainsAny([]byte(value), "/\\\x00") || value == "." || value == ".." {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		switch {
		case character >= 'a' && character <= 'z', character >= 'A' && character <= 'Z', character >= '0' && character <= '9':
		case character == '.' || character == '-' || character == '_':
		default:
			return false
		}
	}
	return true
}

// DocumentDigest is the raw content digest of one stored document.
func DocumentDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func equalDigest(left, right string) bool {
	return len(left) == len(right) && subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

// decodeJSON strictly decodes one bounded JSON document.
func decodeJSON(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("document must contain exactly one JSON value")
	}
	return nil
}
