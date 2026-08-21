package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Every forbidden label in this file, and every canonical scope name it
// exercises, is composed at run time from parts held separately or read from
// the checker itself. Spelling one out here would fail the build it protects,
// which is the same standard the rest of the tree is held to.
var (
	textMarker        = regexp.MustCompile(deliveryLabelPattern)
	identifierMarker  = regexp.MustCompile(deliveryIdentifierPattern)
	camelMarker       = regexp.MustCompile(deliveryCamelPattern)
	ordinaryAllowlist = regexp.MustCompile(governedNamePattern(measurementNames()))
	canonicalAllowed  = regexp.MustCompile(governedNamePattern(append(measurementNames(), canonicalScopeNames()...)))
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
// a metric, and a configuration key. Every shape is held to the allowlist an
// ordinary file gets, which admits no delivery label at all — including the
// canonical scope identity, which is readable only at the exact
// governance-owned locations that own it.
func TestDeliveryLabelsAreRejectedInEveryNamingShape(t *testing.T) {
	for _, prefix := range labelPrefixes() {
		for _, digits := range []string{"0", "1", "3", "4", "8", "12"} {
			label := prefix + digits
			for shape, subject := range map[string]string{
				"file name":     "internal/budget/" + label + "-reconciler.go",
				"directory":     "internal/" + label + "/store.go",
				"evidence name": "docs/acceptance/" + label + "/results.json",
			} {
				if deliveryLabel(textMarker, ordinaryAllowlist, []byte(subject)) == "" {
					t.Errorf("%s %q passed the delivery-label scan", shape, subject)
				}
			}
			for shape, subject := range map[string]string{
				"comment":          "// the " + label + " sweep settles superseded holds",
				"metric":           "anvilkit_agent_service_" + label + "_total",
				"configuration":    "AGENT_SERVICE_" + label + "_ENABLED: true",
				"test name":        "func Test_" + label + "_reconciles(t *testing.T) {",
				"script reference": "run: bun scripts/agent-service-" + label + "-budget.ts",
			} {
				if deliveryLabel(textMarker, ordinaryAllowlist, []byte(subject)) == "" {
					t.Errorf("%s %q passed the delivery-label scan", shape, subject)
				}
			}
			// An identifier opening with the label ends in an uppercase
			// letter that only the identifier scan admits.
			opening := label + "Reconciler"
			if deliveryLabel(identifierMarker, ordinaryAllowlist, []byte(opening)) == "" {
				t.Errorf("identifier %q passed the identifier scan", opening)
			}
			// A label beginning a camel-case hump partway through a name has
			// no separator before it, and is caught by the camel scan.
			if label[:1] != strings.ToLower(label[:1]) {
				hump := "reconciles" + label + "Holds"
				if deliveryLabel(camelMarker, ordinaryAllowlist, []byte(hump)) == "" {
					t.Errorf("camel-cased identifier %q passed the camel scan", hump)
				}
			}
		}
	}
}

// TestCapabilityNamesRemainValid is the other half of the guard: a scan that
// rejects the names this repository is supposed to use would be worse than
// none.
func TestCapabilityNamesRemainValid(t *testing.T) {
	capabilities := []string{
		"internal/budget/budget-reconciliation.go",
		"internal/recovery/operator-recovery.go",
		"internal/budget/cancellation-fencing.go",
		"scripts/contract-validation.ts",
		"anvilkit_agent_service_budget_reconciliation_total",
		"// RecoverSupersededFinality settles finalized superseded holds",
		"// FenceCancelledRun withdraws a cancelled run's dispatch authority",
		"func TestLateFinalityReconcilesWithoutAnotherRetry(t *testing.T) {",
		"func TestCancellationDuringBilledCallHoldsBudgetUntilFinality(t *testing.T) {",
		"ReconcileSuperseded",
		"ConcludeCancelledRun",
		"settleRunBudget",
		"budget-reconciliation",
		"operator-recovery",
		"contract-validation",
		// Ordinary words that merely contain a forbidden prefix must not trip:
		// the label has to stand alone as a token.
		"compileTemplate2Digest",
		"sha256:abc123",
		"the map4 helper is not a milestone",
		// Measurement vocabulary is not a delivery label and is readable
		// anywhere, exactly as it is written.
		"p95",
		"p50",
		"createP95Milliseconds",
	}
	// Ordinary camel-cased names that merely end in a letter and a digit carry
	// no hump, so the camel scan must leave them alone.
	for _, subject := range []string{"item0Total", "sum0Bytes", "checksum256Digest"} {
		if label := deliveryLabel(camelMarker, ordinaryAllowlist, []byte(subject)); label != "" {
			t.Errorf("ordinary identifier %q was rejected as delivery label %q", subject, label)
		}
	}
	for _, subject := range capabilities {
		if label := deliveryLabel(textMarker, ordinaryAllowlist, []byte(subject)); label != "" {
			t.Errorf("capability name %q was rejected as delivery label %q", subject, label)
		}
	}
}

// TestCanonicalScopeNamesAreReadableOnlyAtGovernedLocations is the narrowing
// this guard exists for. The canonical scope identity ADR-018 established is a
// delivery label like any other; what makes it readable is not the name but
// the exact governance-owned path that owns it. An ordinary file spelling it
// fails, and no path outside that set may carry it either.
func TestCanonicalScopeNamesAreReadableOnlyAtGovernedLocations(t *testing.T) {
	for _, name := range canonicalScopeNames() {
		readable := []string{
			name,
			"the " + name + " Profile pins the canonical contract set",
			`"stability": "` + name + `"`,
			"contracts/agent/profile/" + name + ".json",
		}
		for _, subject := range readable {
			if label := deliveryLabel(textMarker, canonicalAllowed, []byte(subject)); label != "" {
				t.Errorf("governed location rejected canonical name %q in %q as delivery label %q", name, subject, label)
			}
			if deliveryLabel(textMarker, ordinaryAllowlist, []byte(subject)) == "" {
				t.Errorf("ordinary location accepted canonical name %q in %q", name, subject)
			}
		}
		// A governed location excuses the canonical name it owns and nothing
		// else: any other delivery label still fails there.
		for _, other := range []string{"internal/" + "m" + "8" + "/store.go", "// the " + "phase-" + "2" + " sweep"} {
			if deliveryLabel(textMarker, canonicalAllowed, []byte(other)) == "" {
				t.Errorf("a governed location excused the unrelated delivery label in %q", other)
			}
		}
		if hump := "reconciles" + "M" + "8" + "Holds"; deliveryLabel(camelMarker, canonicalAllowed, []byte(hump)) == "" {
			t.Errorf("a governed location excused the unrelated delivery label in %q", hump)
		}
	}
}

// TestGovernedLocationsAreDerivedFromTheCanonicalLock proves the allowance is
// exact and current rather than a hand-kept list that drifts: the contract
// locations come from the lock ADR-018 makes authoritative, and an absent lock
// makes the scan stricter rather than more permissive.
func TestGovernedLocationsAreDerivedFromTheCanonicalLock(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, filepath.Dir(canonicalLockPath)), 0o755); err != nil {
		t.Fatal(err)
	}
	profile := "contracts/agent/profile/" + canonicalScopeNames()[0] + ".json"
	source := "contracts/agent/schemas/agent-run.schema.json"
	lock := `{"profile":{"path":"` + profile + `"},"sources":{"` + source + `":"sha256:deadbeef"}}`
	if err := os.WriteFile(filepath.Join(root, canonicalLockPath), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	locations := governedLocations(root)
	for _, expected := range []string{profile, source, canonicalLockPath, "contracts/pin.json"} {
		if !locations[expected] {
			t.Errorf("governed locations omit %q", expected)
		}
	}
	if locations["internal/budget/budget.go"] {
		t.Error("an ordinary source file was treated as a governance-owned location")
	}
	empty := governedLocations(t.TempDir())
	if empty[source] || empty[canonicalLockPath] {
		t.Error("an absent canonical lock granted contract locations anyway")
	}
}

// TestProhibitedTestIdentifierFailsTheBoundaryCommand runs the real command
// against a real tree on disk. Unit-testing the patterns proves the patterns;
// only this proves the command applies them to test files at all — which is
// exactly what it used to skip, and why two delivery-labelled test names
// survived in the tree for as long as they did.
func TestProhibitedTestIdentifierFailsTheBoundaryCommand(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "boundarycheck")
	build := exec.Command("go", "build", "-o", binary, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build the boundary command: %v\n%s", err, output)
	}
	// The label is composed here so this file stays clean under the very scan
	// it is exercising. The shape is deliberate: the label sits inside a
	// camel-case hump with no separator around it, so only a scan that parses
	// the file and reads its declared identifiers can catch it.
	label := "M" + "8"
	prohibited := "package sample\n\nimport \"testing\"\n\nfunc TestReconciles" + label + "Holds(t *testing.T) { _ = t }\n"
	permitted := "package sample\n\nimport \"testing\"\n\nfunc TestReconcilesSupersededHolds(t *testing.T) { _ = t }\n"
	run := func(body string) (string, error) {
		root := t.TempDir()
		if err := os.MkdirAll(filepath.Join(root, "internal", "sample"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "internal", "sample", "sample_test.go"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		output, err := exec.Command(binary, "-root", root).CombinedOutput()
		return string(output), err
	}
	output, err := run(prohibited)
	if err == nil {
		t.Fatalf("a prohibited test identifier passed the boundary command:\n%s", output)
	}
	if !strings.Contains(output, "internal/sample/sample_test.go") || !strings.Contains(output, "delivery-stage naming is forbidden in identifier") {
		t.Fatalf("the failure did not name the offending test identifier:\n%s", output)
	}
	if output, err := run(permitted); err != nil {
		t.Fatalf("a capability-named test was rejected: %v\n%s", err, output)
	}
	// The production import, package-state, and environment rules are
	// boundaries about production code. A test that trips all three still
	// passes, because holding tests to them would only teach people to keep
	// tests out of the checker's way.
	unconstrained := "package sample\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\nvar recorded = os.Getenv(\"AGENT_SERVICE_TEST\")\n\nfunc TestReadsItsOwnEnvironment(t *testing.T) { _ = recorded }\n"
	if output, err := run(unconstrained); err != nil {
		t.Fatalf("a test was held to a production boundary rule: %v\n%s", err, output)
	}
}
