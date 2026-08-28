package runtimes

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	contractvalidator "github.com/ancyloce/anvilkit-agent-service/contracts/validator"
	"github.com/ancyloce/anvilkit-agent-service/internal/agent"
)

const contractRoot = "../.."

func testConfig(t *testing.T, source Source) RegistryConfig {
	t.Helper()
	manifestSchema, err := os.ReadFile(filepath.Join(contractRoot, "contracts", "agent", "schemas", "agent-runtime-manifest.schema.json"))
	if err != nil {
		t.Fatalf("read pinned manifest schema: %v", err)
	}
	validator, err := contractvalidator.New(contractRoot)
	if err != nil {
		t.Fatalf("load pinned validator: %v", err)
	}
	catalogBytes, err := source.Catalog(context.Background())
	if err != nil {
		t.Fatalf("read catalog: %v", err)
	}
	var claimed Catalog
	if err := json.Unmarshal(catalogBytes, &claimed); err != nil {
		t.Fatalf("decode catalog: %v", err)
	}
	protocol, err := os.ReadFile(filepath.Join(contractRoot, "contracts", "agent", "openapi", "agent-runtime.openapi.json"))
	if err != nil {
		t.Fatalf("read canonical runtime description: %v", err)
	}
	return RegistryConfig{
		Source:            source,
		Validator:         validator,
		ManifestSchemaURI: ManifestSchemaURI(manifestSchema),
		// The approval is read from the catalog under test rather than from the
		// pinned intake: these tests are about release verification, and the
		// contract-identity binding has its own test below.
		Approval: Approval{ProfileDigest: claimed.Approval.ProfileDigest, LockDigest: claimed.Approval.LockDigest},
		Policy:   SelectionPolicy{InvocationProtocolDigest: DocumentDigest(protocol)},
	}
}

func testRegistry(t *testing.T) *Registry {
	t.Helper()
	registry, err := NewRegistry(context.Background(), testConfig(t, EmbeddedCatalog{}))
	if err != nil {
		t.Fatalf("build registry: %v", err)
	}
	return registry
}

// definitionUnder returns the approved definition a release was cut for, as the
// definition registry resolves it, so selection is exercised against the same
// material the service actually runs.
func definitionUnder(t *testing.T, definitionID string) agent.Definition {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "agent", "definitions", definitionID+".json"))
	if err != nil {
		t.Fatalf("read definition: %v", err)
	}
	definition, err := agent.ParseDefinition(raw)
	if err != nil {
		t.Fatalf("parse definition: %v", err)
	}
	return definition
}

// A release is approved material. Everything a dispatch decision depends on is
// verified before the release can ever be selected, so a release that reached
// the registry at all is one the service is allowed to act on.
func TestEveryApprovedReleaseIsVerifiedAtIngest(t *testing.T) {
	registry := testRegistry(t)
	releases := registry.Releases()
	if len(releases) == 0 {
		t.Fatal("no releases were ingested")
	}
	for _, release := range releases {
		if release.Lifecycle != "active" || len(release.Capabilities) == 0 {
			t.Fatalf("%s: ingested without a lifecycle state or capabilities: %+v", release.DefinitionID, release)
		}
		if !validDigest(release.ManifestDigest) || !validDigest(release.Binding.RuntimeImageDigest) {
			t.Fatalf("%s: ingested without immutable release identity: %+v", release.DefinitionID, release.Binding)
		}
		if !validAudience(release.Binding.RuntimeAudience) {
			t.Fatalf("%s: ingested with an ungoverned audience %q", release.DefinitionID, release.Binding.RuntimeAudience)
		}
	}
}

// Identical inputs select the same runtime release: selection reads approved
// material and the registry's own policy, and nothing else.
func TestIdenticalInputsSelectTheSameRelease(t *testing.T) {
	registry := testRegistry(t)
	definition := definitionUnder(t, "definition.platform.page-change-manager")
	request := Request{Definition: definition, Capability: TurnCapability}

	first, err := registry.Select(request)
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	for i := 0; i < 16; i++ {
		again, err := registry.Select(request)
		if err != nil {
			t.Fatalf("select %d: %v", i, err)
		}
		if again.ManifestDigest != first.ManifestDigest || again.Binding != first.Binding {
			t.Fatalf("selection is not deterministic: %+v then %+v", first.Binding, again.Binding)
		}
	}
	// A second registry built from the same approved material selects the same
	// release: determinism is a property of the material, not of one process.
	if other, err := testRegistry(t).Select(request); err != nil || other.Binding != first.Binding {
		t.Fatalf("a second registry selected %+v (%v)", other.Binding, err)
	}
	if first.Binding != definition.RuntimeBinding {
		t.Fatalf("the selected release is not the one the definition pins:\n selected %+v\n pinned   %+v", first.Binding, definition.RuntimeBinding)
	}
}

// Invalid or incompatible releases fail before dispatch — at selection for the
// state a release is in, and at ingest for material that could never be
// dispatched to at all.
func TestInvalidOrIncompatibleReleasesFailBeforeDispatch(t *testing.T) {
	definition := definitionUnder(t, "definition.platform.page-change-manager")

	t.Run("revoked and disabled releases are not selected", func(t *testing.T) {
		for _, state := range []string{"revoked", "disabled"} {
			registry, err := NewRegistry(context.Background(), testConfig(t, mutatedCatalog(t, func(manifest map[string]any) {
				manifest["lifecycle"] = map[string]any{"state": state, "effectiveAt": "2026-08-27T00:00:00.000Z", "reasonCode": "RELEASE_REVOKED_BY_OWNER"}
			})))
			if err != nil {
				t.Fatalf("a %s release must still ingest, so an existing run can still be explained: %v", state, err)
			}
			if _, err := registry.Select(Request{Definition: definition, Capability: TurnCapability}); err == nil ||
				!strings.Contains(err.Error(), state) {
				t.Fatalf("a %s release was selected for new work: %v", state, err)
			}
		}
	})

	t.Run("a release speaking another invocation protocol never ingests", func(t *testing.T) {
		_, err := NewRegistry(context.Background(), testConfig(t, mutatedCatalog(t, func(manifest map[string]any) {
			protocol := manifest["protocol"].(map[string]any)
			protocol["invocationProtocolDigest"] = "sha256:" + strings.Repeat("9", 64)
		})))
		if err == nil || !strings.Contains(err.Error(), "invocation protocol") {
			t.Fatalf("an incompatible protocol was ingested: %v", err)
		}
	})

	t.Run("a mutable or unsigned image never ingests", func(t *testing.T) {
		for name, mutate := range map[string]func(map[string]any){
			"mutable image tag": func(manifest map[string]any) {
				manifest["image"].(map[string]any)["imageDigest"] = "ghcr.io/anvilkit/page-change-manager:latest"
			},
			"no provenance": func(manifest map[string]any) {
				manifest["image"].(map[string]any)["provenanceDigest"] = ""
			},
			"no image signature": func(manifest map[string]any) {
				manifest["image"].(map[string]any)["signatureDigest"] = ""
			},
		} {
			if _, err := NewRegistry(context.Background(), testConfig(t, mutatedCatalog(t, mutate))); err == nil {
				t.Fatalf("%s was ingested", name)
			}
		}
	})

	t.Run("a release the definition does not pin is not selected", func(t *testing.T) {
		registry := testRegistry(t)
		moved := definition
		moved.RuntimeBinding.RuntimeImageDigest = "sha256:" + strings.Repeat("1", 64)
		if _, err := registry.Select(Request{Definition: moved, Capability: TurnCapability}); err == nil ||
			!strings.Contains(err.Error(), "image digest") {
			t.Fatalf("a release the definition does not pin was selected: %v", err)
		}
	})

	t.Run("a capability the release does not serve is not selected", func(t *testing.T) {
		registry := testRegistry(t)
		if _, err := registry.Select(Request{Definition: definition, Capability: "artifact.scan"}); err == nil ||
			!strings.Contains(err.Error(), "capability") {
			t.Fatalf("an unserved capability was selected for: %v", err)
		}
	})

	t.Run("a definition with no approved release is not selected", func(t *testing.T) {
		registry := testRegistry(t)
		unknown := definition
		unknown.DefinitionID = "definition.platform.not-approved"
		if _, err := registry.Select(Request{Definition: unknown, Capability: TurnCapability}); err == nil {
			t.Fatal("a definition with no approved release was selected for")
		}
	})
}

// A lifecycle state takes effect when its manifest says it does. A revocation
// cut ahead of time leaves the release selectable until then; an activation cut
// ahead of time is not selectable before then; and a manifest whose effective
// time cannot be read is not releasable at all.
func TestALifecycleStateAppliesFromItsEffectiveTime(t *testing.T) {
	definition := definitionUnder(t, "definition.platform.page-change-manager")
	request := Request{Definition: definition, Capability: TurnCapability}
	const scheduled = "2030-01-01T00:00:00.000Z"
	before := func() time.Time { return time.Date(2029, 12, 31, 23, 59, 59, 0, time.UTC) }
	after := func() time.Time { return time.Date(2030, 1, 1, 0, 0, 1, 0, time.UTC) }
	lifecycle := func(state string) func(map[string]any) {
		return func(manifest map[string]any) {
			entry := map[string]any{"state": state, "effectiveAt": scheduled}
			if state != "active" {
				entry["reasonCode"] = "RELEASE_REVOKED_BY_OWNER"
			}
			manifest["lifecycle"] = entry
		}
	}
	selectAt := func(t *testing.T, mutate func(map[string]any), now func() time.Time) error {
		t.Helper()
		config := testConfig(t, mutatedCatalog(t, mutate))
		config.Now = now
		registry, err := NewRegistry(context.Background(), config)
		if err != nil {
			t.Fatalf("a scheduled lifecycle change must still ingest: %v", err)
		}
		// The mutated manifest has a new digest, so the request pins the
		// mutated release exactly as a definition rebound by the cut would:
		// what is under test is the lifecycle, not the pin agreement.
		pinned := request
		for _, release := range registry.Releases() {
			if release.DefinitionID == definition.DefinitionID {
				pinned.Definition.RuntimeBinding = release.Binding
			}
		}
		_, err = registry.Select(pinned)
		return err
	}
	for _, state := range []string{"revoked", "disabled"} {
		if err := selectAt(t, lifecycle(state), before); err != nil {
			t.Fatalf("a %s cut ahead of time withdrew the release early: %v", state, err)
		}
		if err := selectAt(t, lifecycle(state), after); err == nil || !strings.Contains(err.Error(), state) {
			t.Fatalf("a %s release was selected after its effective time: %v", state, err)
		}
	}
	if err := selectAt(t, lifecycle("active"), before); err == nil || !strings.Contains(err.Error(), "not yet active") {
		t.Fatalf("an activation cut ahead of time was selected early: %v", err)
	}
	if err := selectAt(t, lifecycle("active"), after); err != nil {
		t.Fatalf("an activation was not selectable once effective: %v", err)
	}
	if _, err := NewRegistry(context.Background(), testConfig(t, mutatedCatalog(t, func(manifest map[string]any) {
		manifest["lifecycle"] = map[string]any{"state": "active", "effectiveAt": "soon"}
	}))); err == nil {
		t.Fatal("a lifecycle whose effective time cannot be read was ingested")
	}
}

// A catalog produced against another canonical profile or lock is not this
// service's approved material, whatever it says about itself.
func TestACatalogBoundToOtherContractMaterialNeverIngests(t *testing.T) {
	config := testConfig(t, EmbeddedCatalog{})
	config.Approval.LockDigest = "sha256:" + strings.Repeat("0", 64)
	if _, err := NewRegistry(context.Background(), config); err == nil {
		t.Fatal("a catalog bound to another lock was ingested")
	}
}

// The catalog is the list of what exists. A document whose bytes are not the
// ones the catalog approves is not approved material.
func TestAReplacedManifestDocumentNeverIngests(t *testing.T) {
	source := alteredSource{t: t, inner: EmbeddedCatalog{}, target: "release.platform.page-change-manager.json",
		mutate: func(manifest map[string]any) { manifest["scaling"].(map[string]any)["maxReplicas"] = 512 }}
	_, err := NewRegistry(context.Background(), testConfig(t, source))
	if err == nil || !strings.Contains(err.Error(), "does not match the approved catalog") {
		t.Fatalf("a replaced manifest document was ingested: %v", err)
	}
}

// mutatedCatalog serves the approved catalog with one manifest document
// altered, leaving the catalog's own digests alone unless the mutation is meant
// to be re-approved.
func mutatedCatalog(t *testing.T, mutate func(map[string]any)) Source {
	t.Helper()
	return alteredSource{t: t, inner: EmbeddedCatalog{}, mutate: mutate, target: "release.platform.page-change-manager.json", reApprove: true}
}

type alteredSource struct {
	t      *testing.T
	inner  Source
	mutate func(map[string]any)
	target string
	// reApprove re-records the altered document's digest in the catalog. Tests
	// about what the registry itself refuses set it, so the catalog digest check
	// does not stop the mutation first; the digest check has its own test, which
	// leaves it unset.
	reApprove bool
}

func (a alteredSource) Catalog(ctx context.Context) ([]byte, error) {
	raw, err := a.inner.Catalog(ctx)
	if err != nil {
		return nil, err
	}
	if a.mutate == nil || !a.reApprove {
		return raw, nil
	}
	document, err := a.Document(ctx, a.target)
	if err != nil {
		return nil, err
	}
	var catalog map[string]any
	if err := json.Unmarshal(raw, &catalog); err != nil {
		return nil, err
	}
	for _, entry := range catalog["releases"].([]any) {
		release := entry.(map[string]any)
		if release["document"] == a.target && a.reApprove {
			release["documentDigest"] = DocumentDigest(document)
		}
	}
	return json.Marshal(catalog)
}

func (a alteredSource) Document(ctx context.Context, name string) ([]byte, error) {
	raw, err := a.inner.Document(ctx, name)
	if err != nil || name != a.target || a.mutate == nil {
		return raw, err
	}
	var manifest map[string]any
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, err
	}
	a.mutate(manifest)
	return json.Marshal(manifest)
}
