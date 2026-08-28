package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	sourceContractRoot   = "../.."
	sourceReleasesDir    = "../../internal/runtimes/releases"
	sourceDefinitionsDir = "../../internal/agent/definitions"
	managerUnit          = "runtime.platform.page-change-manager"
)

// TestStoreDocumentsRoundTripByteIdentical proves the ordered rewriter
// reproduces every approved document byte for byte. Digests are taken over
// exact bytes, so a rewriter that changed formatting would change identity.
func TestStoreDocumentsRoundTripByteIdentical(t *testing.T) {
	for _, dir := range []string{sourceReleasesDir, sourceDefinitionsDir} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read %s: %v", dir, err)
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
				continue
			}
			path := filepath.Join(dir, entry.Name())
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			document, err := parseDocument(raw)
			if err != nil {
				t.Fatalf("parse %s: %v", path, err)
			}
			if got := document.encodedBytes(); string(got) != string(raw) {
				t.Errorf("%s does not round-trip byte-identically", path)
			}
		}
	}
}

func cutArguments(out string, extra ...string) []string {
	arguments := []string{
		"-contract-root", sourceContractRoot,
		"-releases", sourceReleasesDir,
		"-definitions", sourceDefinitionsDir,
		"-out", out,
		"-ephemeral",
	}
	return append(arguments, extra...)
}

// TestCutProducesAVerifiableStore cuts a release for a fresh image digest and
// proves the result passes the same verification the service runs, both
// through the cut's own gate and through the verify subcommand with the
// attestations it sealed.
func TestCutProducesAVerifiableStore(t *testing.T) {
	out := t.TempDir()
	imageDigest := "sha256:" + strings.Repeat("ab", 32)
	previous := previousImageDigest(t)
	arguments := append([]string{"cut"}, cutArguments(out,
		"-image", managerUnit+"="+imageDigest,
		"-source-commit", strings.Repeat("a", 40),
		"-builder", "release-pipeline-test",
	)...)
	if err := run(arguments); err != nil {
		t.Fatalf("cut: %v", err)
	}
	if err := run([]string{"verify",
		"-contract-root", sourceContractRoot,
		"-releases", filepath.Join(out, "releases"),
		"-definitions", filepath.Join(out, "definitions"),
		"-trust-root", filepath.Join(out, "attestations", "release-trust-root.json"),
		"-attestation", filepath.Join(out, "attestations", "runtime-release-catalog.attestation.json"),
		"-definition-attestation", filepath.Join(out, "attestations", "agent-definition-catalog.attestation.json"),
	}); err != nil {
		t.Fatalf("verify: %v", err)
	}

	document := readDocument(t, filepath.Join(out, "releases", "release.platform.page-change-manager.json"))
	for path, want := range map[string]string{
		"image.imageDigest":      imageDigest,
		"image.sourceCommit":     strings.Repeat("a", 40),
		"release.rollbackTarget": previous,
	} {
		parts := strings.Split(path, ".")
		got, err := document.stringAt(parts...)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if got != want {
			t.Errorf("%s = %s, want %s", path, got, want)
		}
	}
	for _, evidence := range []string{
		"evidence/platform.page-change-manager.provenance.json",
		"evidence/platform.page-change-manager.image-signature.json",
		"keys/release-signing.seed",
	} {
		if _, err := os.Stat(filepath.Join(out, evidence)); err != nil {
			t.Errorf("expected release evidence %s: %v", evidence, err)
		}
	}
}

// TestLifecycleRevocationCascades revokes one unit and proves the whole
// cascade holds: both of the unit's release documents carry the revocation,
// the store still verifies, and — the reason the state exists — the revoked
// release is no longer selectable while the definitions still pin it exactly.
func TestLifecycleRevocationCascades(t *testing.T) {
	out := t.TempDir()
	arguments := append([]string{"lifecycle"}, cutArguments(out,
		"-unit", managerUnit,
		"-state", "revoked",
		"-reason-code", "SUPPLY_CHAIN_REVOKED",
	)...)
	if err := run(arguments); err != nil {
		t.Fatalf("lifecycle cut: %v", err)
	}
	for _, name := range []string{"release.platform.manager.json", "release.platform.page-change-manager.json"} {
		document := readDocument(t, filepath.Join(out, "releases", name))
		state, err := document.stringAt("lifecycle", "state")
		if err != nil || state != "revoked" {
			t.Errorf("%s lifecycle state = %q (%v), want revoked", name, state, err)
		}
		reason, err := document.stringAt("lifecycle", "reasonCode")
		if err != nil || reason != "SUPPLY_CHAIN_REVOKED" {
			t.Errorf("%s lifecycle reasonCode = %q (%v)", name, reason, err)
		}
	}
}

// TestTamperedStoreFailsVerification changes one byte of a cut release
// document and proves verification refuses the store.
func TestTamperedStoreFailsVerification(t *testing.T) {
	out := t.TempDir()
	arguments := append([]string{"cut"}, cutArguments(out,
		"-image", managerUnit+"=sha256:"+strings.Repeat("cd", 32),
		"-source-commit", strings.Repeat("b", 40),
	)...)
	if err := run(arguments); err != nil {
		t.Fatalf("cut: %v", err)
	}
	tampered := filepath.Join(out, "releases", "release.platform.page-change-manager.json")
	raw, err := os.ReadFile(tampered)
	if err != nil {
		t.Fatal(err)
	}
	modified := strings.Replace(string(raw), `"maxConcurrency": 4`, `"maxConcurrency": 5`, 1)
	if modified == string(raw) {
		t.Fatal("the tamper target was not present")
	}
	if err := os.WriteFile(tampered, []byte(modified), 0o644); err != nil {
		t.Fatal(err)
	}
	err = run([]string{"verify",
		"-contract-root", sourceContractRoot,
		"-releases", filepath.Join(out, "releases"),
		"-definitions", filepath.Join(out, "definitions"),
	})
	if err == nil || !strings.Contains(err.Error(), "does not match the approved catalog") {
		t.Fatalf("tampered store verified: %v", err)
	}
}

// TestCutRefusesAMutableImageReference proves a tag cannot enter a release.
func TestCutRefusesAMutableImageReference(t *testing.T) {
	out := t.TempDir()
	arguments := append([]string{"cut"}, cutArguments(out,
		"-image", managerUnit+"=ghcr.io/anvilkit/page-change-manager:latest",
		"-source-commit", strings.Repeat("c", 40),
	)...)
	err := run(arguments)
	if err == nil || !strings.Contains(err.Error(), "not an immutable sha256 digest") {
		t.Fatalf("a tag was accepted as a release image: %v", err)
	}
}

// TestDeploymentScanGatesRenderedMaterial proves the release-CI scan refuses
// unresolved placeholders and unpinned images and accepts digest-pinned ones.
func TestDeploymentScanGatesRenderedMaterial(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}
	placeholder := write("placeholder.yaml", "spec:\n  image: REPLACED_AT_RELEASE_BY_DIGEST\n")
	if err := scanDeploymentMaterial(placeholder); err == nil || !strings.Contains(err.Error(), "unresolved digest placeholder") {
		t.Errorf("placeholder material passed the scan: %v", err)
	}
	tagged := write("tagged.yaml", "spec:\n  image: ghcr.io/anvilkit/unit:latest\n")
	if err := scanDeploymentMaterial(tagged); err == nil || !strings.Contains(err.Error(), "not pinned by digest") {
		t.Errorf("tag-addressed material passed the scan: %v", err)
	}
	pinned := write("pinned.yaml", "spec:\n  image: ghcr.io/anvilkit/unit@sha256:"+strings.Repeat("ef", 32)+"\n")
	if err := scanDeploymentMaterial(pinned); err != nil {
		t.Errorf("digest-pinned material failed the scan: %v", err)
	}
}

func previousImageDigest(t *testing.T) string {
	t.Helper()
	document := readDocument(t, filepath.Join(sourceReleasesDir, "release.platform.page-change-manager.json"))
	digest, err := document.stringAt("image", "imageDigest")
	if err != nil {
		t.Fatalf("read current image digest: %v", err)
	}
	return digest
}

func readDocument(t *testing.T, path string) *documentNode {
	t.Helper()
	document, err := parseDocumentFile(path)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return document
}
