package main

// verify.go proves a release store is the one the control plane would accept:
// the same schema validation, releasability rules, approval binding, and
// selection the service runs at startup, plus the attestation checks, the
// definition rebinding checks, and the deployment-material scan release CI
// gates on.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	contractvalidator "github.com/ancyloce/anvilkit-agent-service/contracts/validator"
	"github.com/ancyloce/anvilkit-agent-service/internal/agent"
	contractguard "github.com/ancyloce/anvilkit-agent-service/internal/contracts"
	"github.com/ancyloce/anvilkit-agent-service/internal/runtimes"
)

// verifyRequest is one verification run.
type verifyRequest struct {
	contractRoot   string
	releasesDir    string
	definitionsDir string

	trustRootPath             string
	attestationPath           string
	definitionAttestationPath string

	deployments []string
	now         time.Time
}

// directorySource serves a release store from a directory, with the same
// bounded document names the embedded store enforces.
type directorySource struct {
	dir string
}

func (s directorySource) Catalog(context.Context) ([]byte, error) {
	return os.ReadFile(filepath.Join(s.dir, "catalog.json"))
}

func (s directorySource) Document(_ context.Context, name string) ([]byte, error) {
	if err := boundedDocumentName(name); err != nil {
		return nil, err
	}
	return os.ReadFile(filepath.Join(s.dir, name))
}

// definitionCatalogFile mirrors the approved definition catalog exactly; an
// unknown member fails the strict decode.
type definitionCatalogFile struct {
	Approval struct {
		LockDigest    string `json:"lockDigest"`
		ProfileDigest string `json:"profileDigest"`
	} `json:"approval"`
	CatalogVersion int    `json:"catalogVersion"`
	Kind           string `json:"kind"`
	Definitions    []struct {
		DefinitionDigest  string `json:"definitionDigest"`
		DefinitionID      string `json:"definitionId"`
		Document          string `json:"document"`
		DocumentDigest    string `json:"documentDigest"`
		Instruction       string `json:"instruction"`
		InstructionDigest string `json:"instructionDigest"`
	} `json:"definitions"`
	Policies    []json.RawMessage `json:"policies"`
	ToolSchemas []json.RawMessage `json:"toolSchemas"`
}

func runVerify(request verifyRequest) error {
	identity, err := contractguard.PinnedIdentity(request.contractRoot)
	if err != nil {
		return fmt.Errorf("verify pinned contract material: %w", err)
	}
	validator, err := contractvalidator.New(request.contractRoot)
	if err != nil {
		return fmt.Errorf("load pinned schema validator: %w", err)
	}
	manifestSchema, err := os.ReadFile(filepath.Join(request.contractRoot, "contracts", "agent", "schemas", "agent-runtime-manifest.schema.json"))
	if err != nil {
		return fmt.Errorf("read pinned runtime manifest schema: %w", err)
	}
	description, err := os.ReadFile(filepath.Join(request.contractRoot, "contracts", "agent", "openapi", "agent-runtime.openapi.json"))
	if err != nil {
		return fmt.Errorf("read pinned runtime boundary description: %w", err)
	}
	registry, err := runtimes.NewRegistry(context.Background(), runtimes.RegistryConfig{
		Source:            directorySource{dir: request.releasesDir},
		Validator:         validator,
		ManifestSchemaURI: runtimes.ManifestSchemaURI(manifestSchema),
		Approval:          runtimes.Approval{ProfileDigest: identity.ProfileDigest, LockDigest: identity.LockDigest},
		Policy:            runtimes.SelectionPolicy{InvocationProtocolDigest: runtimes.DocumentDigest(description)},
	})
	if err != nil {
		return err
	}

	if (request.trustRootPath == "") != (request.attestationPath == "") {
		return fmt.Errorf("attestation verification requires both a trust root and a signature statement")
	}
	if request.trustRootPath != "" {
		trustRoot, err := os.ReadFile(request.trustRootPath)
		if err != nil {
			return fmt.Errorf("read trust root: %w", err)
		}
		envelope, err := os.ReadFile(request.attestationPath)
		if err != nil {
			return fmt.Errorf("read release catalog attestation: %w", err)
		}
		if err := runtimes.VerifyCatalogAttestation(trustRoot, envelope, registry.CatalogDigest(), request.now); err != nil {
			return err
		}
	}

	if err := verifyDefinitions(request, registry, identity); err != nil {
		return err
	}
	if request.definitionAttestationPath != "" {
		if request.trustRootPath == "" {
			return fmt.Errorf("definition attestation verification requires a trust root")
		}
		trustRoot, err := os.ReadFile(request.trustRootPath)
		if err != nil {
			return fmt.Errorf("read trust root: %w", err)
		}
		envelope, err := os.ReadFile(request.definitionAttestationPath)
		if err != nil {
			return fmt.Errorf("read definition catalog attestation: %w", err)
		}
		catalogBytes, err := os.ReadFile(filepath.Join(request.definitionsDir, "catalog.json"))
		if err != nil {
			return fmt.Errorf("read definition catalog: %w", err)
		}
		if err := agent.VerifyCatalogAttestation(trustRoot, envelope, runtimes.DocumentDigest(catalogBytes), request.now); err != nil {
			return err
		}
	}

	for _, deployment := range request.deployments {
		if err := scanDeploymentMaterial(deployment); err != nil {
			return err
		}
	}
	return nil
}

// verifyDefinitions holds the definition store to the release catalog: every
// definition's pinned binding names exactly the approved release, every digest
// matches the bytes it claims, and lifecycle decisions have the selection
// consequence they exist for.
func verifyDefinitions(request verifyRequest, registry *runtimes.Registry, identity contractguard.Identity) error {
	catalogBytes, err := os.ReadFile(filepath.Join(request.definitionsDir, "catalog.json"))
	if err != nil {
		return fmt.Errorf("read definition catalog: %w", err)
	}
	var catalog definitionCatalogFile
	decoder := json.NewDecoder(strings.NewReader(string(catalogBytes)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&catalog); err != nil {
		return fmt.Errorf("decode definition catalog: %w", err)
	}
	if catalog.Approval.ProfileDigest != identity.ProfileDigest || catalog.Approval.LockDigest != identity.LockDigest {
		return fmt.Errorf("definition catalog: not bound to the verified canonical profile and lock")
	}

	releaseByDefinition := map[string]runtimes.Release{}
	for _, release := range registry.Releases() {
		releaseByDefinition[release.DefinitionID] = release
	}
	for _, entry := range catalog.Definitions {
		if err := boundedDocumentName(entry.Document); err != nil {
			return fmt.Errorf("definition catalog: %w", err)
		}
		raw, err := os.ReadFile(filepath.Join(request.definitionsDir, entry.Document))
		if err != nil {
			return fmt.Errorf("read definition %s: %w", entry.Document, err)
		}
		if runtimes.DocumentDigest(raw) != entry.DocumentDigest {
			return fmt.Errorf("definition %s does not match the approved catalog", entry.Document)
		}
		definition, err := agent.ParseDefinition(raw)
		if err != nil {
			return fmt.Errorf("definition %s: %w", entry.Document, err)
		}
		identityDigest, err := definition.IdentityDigest()
		if err != nil {
			return fmt.Errorf("definition %s: %w", entry.Document, err)
		}
		if identityDigest != definition.DefinitionDigest || identityDigest != entry.DefinitionDigest {
			return fmt.Errorf("definition %s carries a digest its identity does not produce", entry.Document)
		}
		if err := boundedDocumentName(entry.Instruction); err != nil {
			return fmt.Errorf("definition catalog: %w", err)
		}
		instruction, err := os.ReadFile(filepath.Join(request.definitionsDir, entry.Instruction))
		if err != nil {
			return fmt.Errorf("read instruction %s: %w", entry.Instruction, err)
		}
		if runtimes.DocumentDigest(instruction) != entry.InstructionDigest {
			return fmt.Errorf("instruction %s does not match the approved catalog", entry.Instruction)
		}

		release, pinned := releaseByDefinition[entry.DefinitionID]
		if !pinned {
			continue
		}
		if definition.RuntimeBinding != release.Binding {
			return fmt.Errorf("definition %s pins a runtime release the catalog does not approve", entry.DefinitionID)
		}
		selected, err := registry.Select(runtimes.Request{Definition: definition})
		if release.Lifecycle == "active" {
			if err != nil {
				return fmt.Errorf("definition %s: selection of the active release failed: %w", entry.DefinitionID, err)
			}
			if selected.ManifestDigest != release.ManifestDigest {
				return fmt.Errorf("definition %s: selection returned a release other than the approved one", entry.DefinitionID)
			}
		} else if err == nil {
			return fmt.Errorf("definition %s: a %s release must not be selectable", entry.DefinitionID, release.Lifecycle)
		}
	}
	return nil
}

// scanDeploymentMaterial gates rendered deployment material: no unresolved
// digest placeholder survives, and every image reference is pinned by digest —
// a tag, mutable or not, is refused.
func scanDeploymentMaterial(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read deployment material: %w", err)
	}
	text := string(raw)
	if strings.Contains(text, "REPLACED_AT_RELEASE_BY_DIGEST") {
		return fmt.Errorf("%s: an unresolved digest placeholder cannot be released", path)
	}
	imageLine := regexp.MustCompile(`^\s*(?:-\s*)?image:\s*(.+?)\s*$`)
	digestReference := regexp.MustCompile(`@sha256:[0-9a-f]{64}$`)
	for index, line := range strings.Split(text, "\n") {
		match := imageLine.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		reference := strings.Trim(match[1], `"'`)
		if !digestReference.MatchString(reference) {
			return fmt.Errorf("%s:%d: image %q is not pinned by digest; a mutable reference cannot be released", path, index+1, reference)
		}
	}
	return nil
}
