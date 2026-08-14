// Package releasecandidate validates the pinned release-candidate matrix.
// It does not turn local conformance results into production evidence.
package releasecandidate

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
)

const (
	LoadModelRevision  = "agent-service-load-model-v1"
	MaximumMatrixBytes = 1 << 20
)

type Matrix struct {
	SchemaVersion     int    `json:"schemaVersion"`
	MatrixID          string `json:"matrixId"`
	Seed              string `json:"seed"`
	LoadModelRevision string `json:"loadModelRevision"`
	EntryGateStatus   string `json:"entryGateStatus"`
	Cases             []Case `json:"cases"`
}

type Case struct {
	ID            string   `json:"id"`
	Category      string   `json:"category"`
	TestPackage   string   `json:"testPackage"`
	TestName      string   `json:"testName"`
	Invariants    []string `json:"invariants"`
	LocalStatus   string   `json:"localStatus"`
	ReleaseStatus string   `json:"releaseStatus"`
	Blockers      []string `json:"blockers"`
}

func RequiredCategories() []string {
	return []string{
		"restart-every-durable-step", "multi-replica-failover", "duplicate-delivery",
		"disconnect-replay", "cursor-expiry", "input-wait-restart", "approval-wait-restart",
		"cancel-every-precommit-state", "explicit-retry", "parent-child",
		"schema-compatible-deployment", "continuation-loss", "contract-runtime-outage",
		"pagix-uncertainty", "interaction-parity",
	}
}

func DecodeMatrix(raw []byte) (Matrix, error) {
	if len(raw) == 0 || len(raw) > MaximumMatrixBytes {
		return Matrix{}, fmt.Errorf("release-candidate matrix exceeds bounded input")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var matrix Matrix
	if err := decoder.Decode(&matrix); err != nil {
		return Matrix{}, fmt.Errorf("decode release-candidate matrix: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Matrix{}, fmt.Errorf("release-candidate matrix must contain one JSON object")
	}
	if err := matrix.Validate(); err != nil {
		return Matrix{}, err
	}
	return matrix, nil
}

func (m Matrix) Validate() error {
	if m.SchemaVersion != 1 || !boundedID(m.MatrixID) || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(m.Seed) || m.LoadModelRevision != LoadModelRevision || (m.EntryGateStatus != "blocked" && m.EntryGateStatus != "closed") {
		return fmt.Errorf("release-candidate matrix identity or gate status is invalid")
	}
	required := make(map[string]bool, len(RequiredCategories()))
	for _, category := range RequiredCategories() {
		required[category] = false
	}
	identities := map[string]struct{}{}
	for _, candidate := range m.Cases {
		if !boundedID(candidate.ID) || !requiredCategory(required, candidate.Category) || !regexp.MustCompile(`^\./internal/[a-z0-9]+(?:/[a-z0-9]+)*$`).MatchString(candidate.TestPackage) || !regexp.MustCompile(`^Test[A-Za-z0-9_]+$`).MatchString(candidate.TestName) {
			return fmt.Errorf("invalid release-candidate case %q", candidate.ID)
		}
		if _, exists := identities[candidate.ID]; exists || required[candidate.Category] {
			return fmt.Errorf("duplicate release-candidate case or category %q", candidate.ID)
		}
		identities[candidate.ID] = struct{}{}
		required[candidate.Category] = true
		if !exactInvariants(candidate.Invariants) {
			return fmt.Errorf("case %s does not assert all release invariants", candidate.ID)
		}
		if candidate.LocalStatus != "passed" && candidate.LocalStatus != "requires-postgres" {
			return fmt.Errorf("case %s has invalid local status", candidate.ID)
		}
		if candidate.ReleaseStatus != "blocked" && candidate.ReleaseStatus != "passed" {
			return fmt.Errorf("case %s has invalid release status", candidate.ID)
		}
		if candidate.ReleaseStatus == "blocked" && len(candidate.Blockers) == 0 || candidate.ReleaseStatus == "passed" && len(candidate.Blockers) != 0 {
			return fmt.Errorf("case %s blocker state is inconsistent", candidate.ID)
		}
		if m.EntryGateStatus == "blocked" && candidate.ReleaseStatus == "passed" {
			return fmt.Errorf("case %s claims release evidence while candidate entry is blocked", candidate.ID)
		}
	}
	for category, present := range required {
		if !present {
			return fmt.Errorf("release-candidate matrix omits %s", category)
		}
	}
	return nil
}

func requiredCategory(required map[string]bool, category string) bool {
	_, exists := required[category]
	return exists
}

func exactInvariants(values []string) bool {
	required := map[string]bool{"no-repeated-external-effect": false, "no-lost-acknowledged-fact": false, "no-stale-result-accepted": false}
	if len(values) != len(required) {
		return false
	}
	for _, value := range values {
		if _, exists := required[value]; !exists || required[value] {
			return false
		}
		required[value] = true
	}
	return true
}

func boundedID(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	return regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]*$`).MatchString(value)
}
