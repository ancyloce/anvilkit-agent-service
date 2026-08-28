// Package runtimes is the Runtime Registry: the approved set of Agent Runtime
// releases, the verification every release passes before it can be selected,
// and the port through which a selected release is dispatched to.
//
// A release is (runtime unit, definition, image, invocation protocol). It is
// approved material, never discovery: the catalog is the list of what exists,
// and no manifest outside it is readable. Selection is a decision about
// approved material and nothing else — an Agent Service that could reach a
// runtime the registry does not know would be executing work under a release
// nobody approved.
package runtimes

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
)

// Approval is the verified pinned contract identity an approved release
// catalog must be bound to. It is produced by verifying the service's pinned
// contract intake, never asserted by the catalog itself, so a release set
// produced against a different canonical profile or lock cannot be selected.
type Approval struct {
	ProfileDigest string
	LockDigest    string
}

func (a Approval) valid() bool {
	return validDigest(a.ProfileDigest) && validDigest(a.LockDigest)
}

// CatalogApproval is the binding a catalog claims to the approved boundary.
type CatalogApproval struct {
	ProfileDigest string `json:"profileDigest"`
	LockDigest    string `json:"lockDigest"`
}

// CatalogRelease binds one runtime manifest document to the unit and
// definition it is the release of. The digest is the identity the registry
// holds the document to; the unit and definition are carried here so a
// document that silently changed what it is a release of fails against the
// catalog rather than being ingested under its new claim.
type CatalogRelease struct {
	RuntimeUnitID  string `json:"runtimeUnitId"`
	DefinitionID   string `json:"definitionId"`
	Document       string `json:"document"`
	DocumentDigest string `json:"documentDigest"`
}

// Catalog is the approved release set.
type Catalog struct {
	Approval       CatalogApproval  `json:"approval"`
	CatalogVersion int              `json:"catalogVersion"`
	Releases       []CatalogRelease `json:"releases"`
}

const maximumReleases = 64

// ParseCatalog strictly decodes the approved release catalog and enforces the
// bounds a catalog must satisfy before any document it names is read.
func ParseCatalog(raw []byte) (Catalog, error) {
	var catalog Catalog
	if err := decodeJSON(raw, &catalog); err != nil {
		return Catalog{}, fmt.Errorf("release catalog: %w", err)
	}
	if catalog.CatalogVersion != 1 {
		return Catalog{}, fmt.Errorf("release catalog: version %d is not the approved catalog version", catalog.CatalogVersion)
	}
	if len(catalog.Releases) == 0 || len(catalog.Releases) > maximumReleases {
		return Catalog{}, fmt.Errorf("release catalog: must name between 1 and %d releases", maximumReleases)
	}
	seenDocument := make(map[string]struct{}, len(catalog.Releases))
	seenDefinition := make(map[string]struct{}, len(catalog.Releases))
	for _, release := range catalog.Releases {
		if !validComponentID(release.RuntimeUnitID) || !validComponentID(release.DefinitionID) {
			return Catalog{}, fmt.Errorf("release catalog: a release names no bounded unit and definition identity")
		}
		if release.Document == "" || !validDigest(release.DocumentDigest) {
			return Catalog{}, fmt.Errorf("release catalog: release %s names no digest-bound document", release.RuntimeUnitID)
		}
		if _, duplicate := seenDocument[release.Document]; duplicate {
			return Catalog{}, fmt.Errorf("release catalog: document %s is named twice", release.Document)
		}
		seenDocument[release.Document] = struct{}{}
		// One definition resolves to exactly one release, which is what makes
		// selection deterministic without a tie-break rule nobody agreed to.
		if _, duplicate := seenDefinition[release.DefinitionID]; duplicate {
			return Catalog{}, fmt.Errorf("release catalog: definition %s has more than one approved release", release.DefinitionID)
		}
		seenDefinition[release.DefinitionID] = struct{}{}
	}
	return catalog, nil
}

// Authenticate proves the catalog is bound to the contract identity this
// process verified at startup.
func (c Catalog) Authenticate(approval Approval) error {
	if !approval.valid() {
		return fmt.Errorf("release catalog: the verified contract identity is incomplete")
	}
	if !equalDigest(c.Approval.ProfileDigest, approval.ProfileDigest) || !equalDigest(c.Approval.LockDigest, approval.LockDigest) {
		return fmt.Errorf("release catalog: the catalog is not bound to the approved canonical profile and lock")
	}
	return nil
}

// DocumentDigest is the identity of one approved document's bytes.
func DocumentDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func equalDigest(left, right string) bool {
	return len(left) == len(right) && subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func validDigest(value string) bool {
	return regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(value)
}

func validComponentID(value string) bool {
	return regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`).MatchString(value)
}

func validAudience(value string) bool {
	return len(value) <= 256 && regexp.MustCompile(`^urn:anvilkit:audience:[a-z0-9][a-z0-9-]{1,63}$`).MatchString(value)
}

// decodeJSON strictly decodes one bounded JSON document. Unknown fields are
// refused: approved material with a member this process does not understand is
// material it cannot claim to have verified.
func decodeJSON(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		return fmt.Errorf("decode: trailing content after the document")
	}
	return nil
}
