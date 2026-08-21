package main

import (
	"regexp"
	"strings"
	"testing"
)

// Every forbidden label in this file is composed at run time from a prefix and
// a digit held separately, so the test's own source stays clean under the very
// scan it exercises. Spelling one out here would fail the build it protects.
var (
	textMarker       = regexp.MustCompile(deliveryLabelPattern)
	identifierMarker = regexp.MustCompile(deliveryIdentifierPattern)
	camelMarker      = regexp.MustCompile(deliveryCamelPattern)
	pathAllowlist    = regexp.MustCompile(governedNamePattern(governedPathNames()))
	contentAllowlist = regexp.MustCompile(governedNamePattern(governedContentNames()))
)

func labelPrefixes() []string {
	return []string{
		"m", "M", "wp", "WP", "Wp", "p", "P",
		"work-package-", "work_package_", "WORK-PACKAGE-", "Work_Package_", "workpackage", "work.package.",
		"milestone-", "MILESTONE_", "Milestone.", "milestone",
		"phase-", "PHASE_", "Phase.", "phase",
		"gate-", "GATE_", "Gate.", "gate",
	}
}

// TestDeliveryLabelsAreRejectedInEveryNamingShape covers the surfaces a label
// can hide in: a file name, a directory, an identifier, a test name, a comment,
// a metric, and a configuration key.
func TestDeliveryLabelsAreRejectedInEveryNamingShape(t *testing.T) {
	for _, prefix := range labelPrefixes() {
		for _, digits := range []string{"0", "1", "3", "4", "8", "12"} {
			label := prefix + digits
			// Names are held to the path tier, which admits no bare label at
			// all — so nothing may be created under a delivery label.
			for shape, subject := range map[string]string{
				"file name":     "internal/budget/" + label + "-reconciler.go",
				"directory":     "internal/" + label + "/store.go",
				"evidence name": "docs/acceptance/" + label + "/results.json",
			} {
				if deliveryLabel(textMarker, pathAllowlist, []byte(subject)) == "" {
					t.Errorf("%s %q passed the delivery-label scan", shape, subject)
				}
			}
			// The profile scope identity ADR-018 established is readable
			// inside governed contract prose, so it is the one label the
			// content tier admits. That it can never become a name is what
			// TestPathTierIsStricterThanContentTier proves.
			if strings.EqualFold(label, "p0") {
				continue
			}
			for shape, subject := range map[string]string{
				"comment":          "// the " + label + " sweep settles superseded holds",
				"metric":           "anvilkit_agent_service_" + label + "_total",
				"configuration":    "AGENT_SERVICE_" + label + "_ENABLED: true",
				"test name":        "func Test_" + label + "_reconciles(t *testing.T) {",
				"script reference": "run: bun scripts/agent-service-" + label + "-budget.ts",
			} {
				if deliveryLabel(textMarker, contentAllowlist, []byte(subject)) == "" {
					t.Errorf("%s %q passed the delivery-label scan", shape, subject)
				}
			}
			// An identifier opening with the label ends in an uppercase
			// letter that only the identifier scan admits.
			opening := label + "Reconciler"
			if deliveryLabel(identifierMarker, contentAllowlist, []byte(opening)) == "" {
				t.Errorf("identifier %q passed the identifier scan", opening)
			}
			// A label beginning a camel-case hump partway through a name has
			// no separator before it, and is caught by the camel scan.
			if label[:1] != strings.ToLower(label[:1]) {
				hump := "reconciles" + label + "Holds"
				if deliveryLabel(camelMarker, contentAllowlist, []byte(hump)) == "" {
					t.Errorf("camel-cased identifier %q passed the camel scan", hump)
				}
			}
		}
	}
}

// TestCapabilityNamesAndGovernedNamesRemainValid is the other half of the
// guard: a scan that rejects the names this repository is supposed to use, or
// the governed names it is not free to rename, would be worse than none.
func TestCapabilityNamesAndGovernedNamesRemainValid(t *testing.T) {
	capabilities := []string{
		"internal/budget/budget-reconciliation.go",
		"internal/recovery/operator-recovery.go",
		"scripts/contract-validation.ts",
		"anvilkit_agent_service_budget_reconciliation_total",
		"// RecoverSupersededFinality settles finalized superseded holds",
		"func TestLateFinalityReconcilesWithoutAnotherRetry(t *testing.T) {",
		"ReconcileSuperseded",
		"settleRunBudget",
		"budget-reconciliation",
		"operator-recovery",
		"contract-validation",
		// Ordinary words that merely contain a forbidden prefix must not trip:
		// the label has to stand alone as a token.
		"compileTemplate2Digest",
		"sha256:abc123",
		"the map4 helper is not a milestone",
	}
	// Ordinary camel-cased names that merely end in a letter and a digit carry
	// no hump, so the camel scan must leave them alone.
	for _, subject := range []string{"item0Total", "sum0Bytes", "checksum256Digest"} {
		if label := deliveryLabel(camelMarker, contentAllowlist, []byte(subject)); label != "" {
			t.Errorf("ordinary identifier %q was rejected as delivery label %q", subject, label)
		}
	}
	for _, subject := range capabilities {
		if label := deliveryLabel(textMarker, contentAllowlist, []byte(subject)); label != "" {
			t.Errorf("capability name %q was rejected as delivery label %q", subject, label)
		}
	}
	governed := []string{
		"contracts/agent/profile/p0-kernel-profile.json",
		"docs/acceptance/p0-kernel/gate-register.json",
		"the P0-Kernel Profile pins the canonical contract set",
		"p95",
		"p50",
		"createP95Milliseconds",
		"Canonical P0 Agent Service HTTP contract",
	}
	for _, subject := range governed {
		if label := deliveryLabel(textMarker, contentAllowlist, []byte(subject)); label != "" {
			t.Errorf("governed canonical name %q was rejected as delivery label %q", subject, label)
		}
	}
}

// TestPathTierIsStricterThanContentTier proves the allowlist cannot become a
// licence to create new delivery-labelled files. The profile scope identity is
// readable inside governed contract prose, but nothing may be named after it
// that the ADR did not already name.
func TestPathTierIsStricterThanContentTier(t *testing.T) {
	for _, subject := range []string{"internal/p0/store.go", "docs/acceptance/p0/results.json"} {
		if deliveryLabel(textMarker, pathAllowlist, []byte(subject)) == "" {
			t.Errorf("path %q was allowed to carry the profile scope identity", subject)
		}
		if deliveryLabel(textMarker, contentAllowlist, []byte(subject)) != "" {
			t.Errorf("content scan rejected the governed profile scope identity in %q", subject)
		}
	}
	// The names the ADR did establish stay valid in both tiers.
	for _, subject := range []string{"contracts/agent/profile/p0-kernel-profile.json", "docs/acceptance/p0-kernel/report.json"} {
		if label := deliveryLabel(textMarker, pathAllowlist, []byte(subject)); label != "" {
			t.Errorf("governed path %q was rejected as delivery label %q", subject, label)
		}
	}
}

// TestGovernedAllowlistStaysNarrow keeps the escape hatch small by
// construction: an entry that is only a bare label would excuse every use of
// it, which is the broad bypass this guard exists to avoid.
func TestGovernedAllowlistStaysNarrow(t *testing.T) {
	bare := regexp.MustCompile(`^` + deliveryLabelAlternation + `$`)
	for _, name := range governedPathNames() {
		if bare.MatchString(name) {
			t.Errorf("governed path name %q is a bare delivery label, not a governed name", name)
		}
	}
	if len(governedContentNames()) > 12 {
		t.Errorf("the governed allowlist has grown to %d entries; each one needs a governance decision", len(governedContentNames()))
	}
}
