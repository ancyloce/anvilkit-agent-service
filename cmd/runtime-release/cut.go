package main

// cut.go is the release cut: the one pipeline that takes a built image (or a
// lifecycle decision) and produces the complete, internally consistent set of
// approved material the control plane verifies — release manifests, the
// release catalog, the definitions that pin each release, the definition
// catalog, provenance and image-signature evidence, and the signed catalog
// attestations.
//
// Everything cascades from one change on purpose. A manifest byte changes its
// digest; the digest changes the catalog; the definitions pin the manifest
// digest, so they change too, and their catalog with them; and both catalogs
// must be re-attested. Doing the cascade by hand is how half-cut material gets
// deployed, so the tool owns the whole of it and then re-verifies the result
// with the same ingestion the service runs at startup.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/canonical"
	contractguard "github.com/ancyloce/anvilkit-agent-service/internal/contracts"
	"github.com/ancyloce/anvilkit-agent-service/internal/runtimes"
)

// lifecycleChange is a revoke, emergency-disable, or reactivation decision for
// one runtime unit.
type lifecycleChange struct {
	unit       string
	state      string
	reasonCode string
}

// cutRequest is everything one cut needs.
type cutRequest struct {
	contractRoot   string
	releasesDir    string
	definitionsDir string
	outDir         string
	inPlace        bool

	images       map[string]string
	sourceCommit string
	builder      string
	lifecycle    *lifecycleChange

	release    signingAuthority
	definition signingAuthority
	// ephemeralSeed, when set, is written under the output directory so the
	// pipeline that generated it can reuse it inside the same build.
	ephemeralSeed []byte

	now      time.Time
	validity time.Duration
}

// imageProvenance is the build provenance document a cut generates per runtime
// unit. Its digest is what the runtime manifest records as its provenance
// reference.
type imageProvenance struct {
	Kind              string `json:"kind"`
	RuntimeUnitID     string `json:"runtimeUnitId"`
	ImageDigest       string `json:"imageDigest"`
	SourceCommit      string `json:"sourceCommit"`
	Builder           string `json:"builder"`
	BuiltAt           string `json:"builtAt"`
	ContractBomDigest string `json:"contractBomDigest"`
}

func runCut(request cutRequest) error {
	if err := validateCutRequest(&request); err != nil {
		return err
	}
	identity, err := contractguard.PinnedIdentity(request.contractRoot)
	if err != nil {
		return fmt.Errorf("verify pinned contract material: %w", err)
	}
	protocolDigest, err := fileDigest(filepath.Join(request.contractRoot, "contracts", "agent", "openapi", "agent-runtime.openapi.json"))
	if err != nil {
		return fmt.Errorf("read runtime boundary description: %w", err)
	}
	store, err := loadStore(request.releasesDir, request.definitionsDir)
	if err != nil {
		return err
	}

	touchedUnits := map[string]bool{}
	for unit := range request.images {
		touchedUnits[unit] = true
	}
	if request.lifecycle != nil {
		touchedUnits[request.lifecycle.unit] = true
	}
	for unit := range touchedUnits {
		if !storeHasUnit(store, unit) {
			return fmt.Errorf("runtime unit %s has no release in the approved catalog", unit)
		}
	}

	evidenceDir := filepath.Join(request.outDir, "evidence")
	provenanceByUnit := map[string]string{}
	signatureByUnit := map[string]string{}
	for unit, imageDigest := range request.images {
		provenanceDigest, signatureDigest, err := buildImageEvidence(request, store, unit, imageDigest, evidenceDir)
		if err != nil {
			return err
		}
		provenanceByUnit[unit] = provenanceDigest
		signatureByUnit[unit] = signatureDigest
	}

	// Apply the mutations to every release document of each touched unit.
	for _, entry := range store.entries {
		document := store.releaseDocs[entry.document]
		// The invocation protocol is contract material, not a build input: every
		// release speaks the protocol the pinned runtime boundary description
		// declares, so a description change moves all of them in the same cut.
		if err := document.setString(protocolDigest, "protocol", "invocationProtocolDigest"); err != nil {
			return fmt.Errorf("release %s: %w", entry.document, err)
		}
		if imageDigest, changed := request.images[entry.runtimeUnitID]; changed {
			previous, err := document.stringAt("image", "imageDigest")
			if err != nil {
				return fmt.Errorf("release %s: %w", entry.document, err)
			}
			for path, value := range map[string]string{
				"imageDigest":      imageDigest,
				"sourceCommit":     request.sourceCommit,
				"provenanceDigest": provenanceByUnit[entry.runtimeUnitID],
				"signatureDigest":  signatureByUnit[entry.runtimeUnitID],
			} {
				if err := document.setString(value, "image", path); err != nil {
					return fmt.Errorf("release %s: %w", entry.document, err)
				}
			}
			// The release being replaced is the release a rollback returns to.
			if err := document.setString(previous, "release", "rollbackTarget"); err != nil {
				return fmt.Errorf("release %s: %w", entry.document, err)
			}
			if err := document.setString("active", "lifecycle", "state"); err != nil {
				return fmt.Errorf("release %s: %w", entry.document, err)
			}
			if err := document.setString(request.now.UTC().Format(timestampLayout), "lifecycle", "effectiveAt"); err != nil {
				return fmt.Errorf("release %s: %w", entry.document, err)
			}
			if err := document.removeMember("reasonCode", "lifecycle"); err != nil {
				return fmt.Errorf("release %s: %w", entry.document, err)
			}
		}
		if request.lifecycle != nil && request.lifecycle.unit == entry.runtimeUnitID {
			if err := document.setString(request.lifecycle.state, "lifecycle", "state"); err != nil {
				return fmt.Errorf("release %s: %w", entry.document, err)
			}
			if err := document.setString(request.now.UTC().Format(timestampLayout), "lifecycle", "effectiveAt"); err != nil {
				return fmt.Errorf("release %s: %w", entry.document, err)
			}
			if request.lifecycle.reasonCode != "" {
				if err := document.upsertString("reasonCode", request.lifecycle.reasonCode, "lifecycle"); err != nil {
					return fmt.Errorf("release %s: %w", entry.document, err)
				}
			} else if err := document.removeMember("reasonCode", "lifecycle"); err != nil {
				return fmt.Errorf("release %s: %w", entry.document, err)
			}
		}
	}

	// Rebind the release catalog to the rewritten documents and to the
	// verified contract identity.
	releaseList, err := store.releaseCatalog.child("releases")
	if err != nil {
		return fmt.Errorf("release catalog: %w", err)
	}
	manifestDigests := map[string]string{}
	for _, item := range releaseList.items {
		name, err := item.stringAt("document")
		if err != nil {
			return fmt.Errorf("release catalog: %w", err)
		}
		digest := runtimes.DocumentDigest(store.releaseDocs[name].encodedBytes())
		manifestDigests[name] = digest
		if err := item.setString(digest, "documentDigest"); err != nil {
			return fmt.Errorf("release catalog: %w", err)
		}
	}
	if err := store.releaseCatalog.setString(identity.ProfileDigest, "approval", "profileDigest"); err != nil {
		return fmt.Errorf("release catalog: %w", err)
	}
	if err := store.releaseCatalog.setString(identity.LockDigest, "approval", "lockDigest"); err != nil {
		return fmt.Errorf("release catalog: %w", err)
	}

	// Rebind every definition that pins a release to the release the catalog
	// now approves for it. The definition digest covers the binding, so the
	// definitions and their catalog are regenerated in the same cut.
	documentByDefinition := map[string]string{}
	unitByDefinition := map[string]string{}
	for _, entry := range store.entries {
		documentByDefinition[entry.definitionID] = entry.document
		unitByDefinition[entry.definitionID] = entry.runtimeUnitID
	}
	definitionList, err := store.definitionCatalog.child("definitions")
	if err != nil {
		return fmt.Errorf("definition catalog: %w", err)
	}
	for _, item := range definitionList.items {
		definitionID, err := item.stringAt("definitionId")
		if err != nil {
			return fmt.Errorf("definition catalog: %w", err)
		}
		releaseDocument, pinned := documentByDefinition[definitionID]
		if !pinned {
			continue
		}
		documentName, err := item.stringAt("document")
		if err != nil {
			return fmt.Errorf("definition catalog: %w", err)
		}
		definition := store.definitionDocs[documentName]
		release := store.releaseDocs[releaseDocument]
		imageDigest, err := release.stringAt("image", "imageDigest")
		if err != nil {
			return fmt.Errorf("release %s: %w", releaseDocument, err)
		}
		audience, err := release.stringAt("workload", "audience")
		if err != nil {
			return fmt.Errorf("release %s: %w", releaseDocument, err)
		}
		for path, value := range map[string]string{
			"runtimeUnitId":            unitByDefinition[definitionID],
			"runtimeManifestDigest":    manifestDigests[releaseDocument],
			"runtimeImageDigest":       imageDigest,
			"invocationProtocolDigest": protocolDigest,
			"runtimeAudience":          audience,
		} {
			if err := definition.setString(value, "runtimeBinding", path); err != nil {
				return fmt.Errorf("definition %s: %w", documentName, err)
			}
		}
		identityDigest, err := definitionIdentityDigest(definition.encodedBytes())
		if err != nil {
			return fmt.Errorf("definition %s: %w", documentName, err)
		}
		if err := definition.setString(identityDigest, "definitionDigest"); err != nil {
			return fmt.Errorf("definition %s: %w", documentName, err)
		}
		if err := item.setString(identityDigest, "definitionDigest"); err != nil {
			return fmt.Errorf("definition catalog: %w", err)
		}
		if err := item.setString(runtimes.DocumentDigest(definition.encodedBytes()), "documentDigest"); err != nil {
			return fmt.Errorf("definition catalog: %w", err)
		}
	}
	if err := store.definitionCatalog.setString(identity.ProfileDigest, "approval", "profileDigest"); err != nil {
		return fmt.Errorf("definition catalog: %w", err)
	}
	if err := store.definitionCatalog.setString(identity.LockDigest, "approval", "lockDigest"); err != nil {
		return fmt.Errorf("definition catalog: %w", err)
	}

	// Write the cut store.
	releasesOut, definitionsOut := request.releasesDir, request.definitionsDir
	if !request.inPlace {
		releasesOut = filepath.Join(request.outDir, "releases")
		definitionsOut = filepath.Join(request.outDir, "definitions")
	}
	if err := store.writeStore(releasesOut, definitionsOut); err != nil {
		return err
	}

	// Attest both catalogs and publish the trust root that resolves the
	// signatures.
	attestationsDir := filepath.Join(request.outDir, "attestations")
	releaseCatalogDigest := runtimes.DocumentDigest(store.releaseCatalog.encodedBytes())
	releaseEnvelope, err := request.release.sealStatement(
		runtimes.CatalogStatementKind, runtimes.CatalogStatementType, runtimes.CatalogMediaType,
		runtimes.CatalogAudience, releaseCatalogDigest, request.now, request.validity)
	if err != nil {
		return fmt.Errorf("attest release catalog: %w", err)
	}
	attestationPath := filepath.Join(attestationsDir, "runtime-release-catalog.attestation.json")
	if err := writeFile(attestationPath, releaseEnvelope, 0o644); err != nil {
		return err
	}
	definitionCatalogDigest := runtimes.DocumentDigest(store.definitionCatalog.encodedBytes())
	definitionEnvelope, err := request.definition.sealStatement(
		definitionStatementKind, definitionCatalogStatementType, definitionCatalogMediaType,
		runtimes.CatalogAudience, definitionCatalogDigest, request.now, request.validity)
	if err != nil {
		return fmt.Errorf("attest definition catalog: %w", err)
	}
	definitionAttestationPath := filepath.Join(attestationsDir, "agent-definition-catalog.attestation.json")
	if err := writeFile(definitionAttestationPath, definitionEnvelope, 0o644); err != nil {
		return err
	}
	trustRoot, err := trustRootDocument([]signingAuthority{request.release, request.definition}, runtimes.CatalogAudience, request.now, request.validity)
	if err != nil {
		return err
	}
	trustRootPath := filepath.Join(attestationsDir, "release-trust-root.json")
	if err := writeFile(trustRootPath, trustRoot, 0o644); err != nil {
		return err
	}
	if len(request.ephemeralSeed) != 0 {
		if err := writeFile(filepath.Join(request.outDir, "keys", "release-signing.seed"), request.ephemeralSeed, 0o600); err != nil {
			return err
		}
	}

	// A cut is not done until it verifies: run the exact ingestion and trust
	// checks the service runs, against what was just written.
	if err := runVerify(verifyRequest{
		contractRoot:              request.contractRoot,
		releasesDir:               releasesOut,
		definitionsDir:            definitionsOut,
		trustRootPath:             trustRootPath,
		attestationPath:           attestationPath,
		definitionAttestationPath: definitionAttestationPath,
		now:                       request.now,
	}); err != nil {
		return fmt.Errorf("the cut does not verify: %w", err)
	}
	fmt.Printf("cut verified: %d releases, %d definitions, catalog %s\n", len(store.entries), len(store.definitions), releaseCatalogDigest)
	return nil
}

func validateCutRequest(request *cutRequest) error {
	if request.outDir == "" {
		return fmt.Errorf("an output directory is required")
	}
	if len(request.images) == 0 && request.lifecycle == nil {
		return fmt.Errorf("a cut needs at least one image or a lifecycle change")
	}
	digestPattern := regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	for unit, imageDigest := range request.images {
		if !digestPattern.MatchString(imageDigest) {
			return fmt.Errorf("image for %s: %q is not an immutable sha256 digest; a tag cannot be released", unit, imageDigest)
		}
	}
	if len(request.images) != 0 && !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(request.sourceCommit) {
		return fmt.Errorf("a full 40-hex source commit is required when releasing an image")
	}
	if request.lifecycle != nil {
		switch request.lifecycle.state {
		case "active", "revoked", "disabled":
		default:
			return fmt.Errorf("lifecycle state %q is outside the governed vocabulary", request.lifecycle.state)
		}
		if request.lifecycle.reasonCode != "" && !regexp.MustCompile(`^[A-Z][A-Z0-9_]{2,63}$`).MatchString(request.lifecycle.reasonCode) {
			return fmt.Errorf("lifecycle reason code %q is outside the governed shape", request.lifecycle.reasonCode)
		}
	}
	if request.validity <= 0 {
		return fmt.Errorf("the attestation validity must be positive")
	}
	return nil
}

func storeHasUnit(store *releaseStore, unit string) bool {
	for _, entry := range store.entries {
		if entry.runtimeUnitID == unit {
			return true
		}
	}
	return false
}

// buildImageEvidence generates the provenance document and the sealed image
// signature for one built image, writes both as release evidence, and returns
// their digests for the manifest to record.
func buildImageEvidence(request cutRequest, store *releaseStore, unit, imageDigest, evidenceDir string) (string, string, error) {
	bomDigest := ""
	for _, entry := range store.entries {
		if entry.runtimeUnitID != unit {
			continue
		}
		digest, err := store.releaseDocs[entry.document].stringAt("protocol", "contractBomReference", "bomDigest")
		if err != nil {
			return "", "", fmt.Errorf("release %s: %w", entry.document, err)
		}
		bomDigest = digest
		break
	}
	provenance := imageProvenance{
		Kind:              "AgentRuntimeImageProvenance",
		RuntimeUnitID:     unit,
		ImageDigest:       imageDigest,
		SourceCommit:      request.sourceCommit,
		Builder:           request.builder,
		BuiltAt:           request.now.UTC().Format(timestampLayout),
		ContractBomDigest: bomDigest,
	}
	provenanceBytes, err := json.MarshalIndent(provenance, "", "  ")
	if err != nil {
		return "", "", fmt.Errorf("encode provenance: %w", err)
	}
	provenanceBytes = append(provenanceBytes, '\n')
	stem := strings.TrimPrefix(unit, "runtime.")
	if err := writeFile(filepath.Join(evidenceDir, stem+".provenance.json"), provenanceBytes, 0o644); err != nil {
		return "", "", err
	}
	signatureEnvelope, err := request.release.sealStatement(
		imageSignatureStatementKind, imageSignaturePayloadType, ociImageManifestMediaType,
		runtimes.CatalogAudience, imageDigest, request.now, request.validity)
	if err != nil {
		return "", "", fmt.Errorf("seal image signature: %w", err)
	}
	if err := writeFile(filepath.Join(evidenceDir, stem+".image-signature.json"), signatureEnvelope, 0o644); err != nil {
		return "", "", err
	}
	return runtimes.DocumentDigest(provenanceBytes), runtimes.DocumentDigest(signatureEnvelope), nil
}

// definitionIdentityDigest recomputes the digest the definition registry
// enforces: the canonical digest over every document member except kind and
// definitionDigest.
func definitionIdentityDigest(raw []byte) (string, error) {
	var document map[string]json.RawMessage
	if err := json.Unmarshal(raw, &document); err != nil {
		return "", fmt.Errorf("definition identity: %w", err)
	}
	delete(document, "kind")
	delete(document, "definitionDigest")
	identity, err := json.Marshal(document)
	if err != nil {
		return "", fmt.Errorf("definition identity: %w", err)
	}
	digest, err := canonical.Digest(identity)
	if err != nil {
		return "", fmt.Errorf("definition identity: %w", err)
	}
	return digest, nil
}

func fileDigest(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return runtimes.DocumentDigest(raw), nil
}
