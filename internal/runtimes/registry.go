package runtimes

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/contracts/generated/schema"
	"github.com/ancyloce/anvilkit-agent-service/contracts/validator"
	"github.com/ancyloce/anvilkit-agent-service/internal/agent"
)

// Source supplies the approved release catalog and the manifest documents it
// names. Implementations are approved release stores, never discovery.
type Source interface {
	Catalog(context.Context) ([]byte, error)
	Document(ctx context.Context, name string) ([]byte, error)
}

// SchemaValidator validates one document against one pinned schema identity.
type SchemaValidator interface {
	Validate(schemaURI string, raw []byte) []validator.Finding
}

// ManifestSchemaURI derives the pinned schema identity for the canonical
// AgentRuntimeManifest schema bytes.
func ManifestSchemaURI(schemaBytes []byte) string {
	digest := sha256.Sum256(schemaBytes)
	return "anvilkit://schema/agent-runtime-manifest?digest=sha256:" + hex.EncodeToString(digest[:])
}

// SelectionPolicy is the service's own rule set for what it will select, as
// distinct from what a request asks for. It is fixed when the registry is
// built so that selection is a function of approved material and this policy
// alone — nothing a caller passes can widen it.
type SelectionPolicy struct {
	// InvocationProtocolDigest is the protocol this Agent Service speaks. A
	// release that speaks another one is incompatible: the two processes would
	// agree on the transport and disagree on the contract.
	InvocationProtocolDigest string
}

// RegistryConfig wires the approved source, mandatory schema validation, the
// verified contract identity the catalog must be bound to, and the selection
// policy.
type RegistryConfig struct {
	Source            Source
	Validator         SchemaValidator
	ManifestSchemaURI string
	Approval          Approval
	Policy            SelectionPolicy
	// Now is the clock a lifecycle state is evaluated against at selection.
	// A manifest's lifecycle carries the instant it takes effect, so a
	// revocation cut ahead of time withdraws the release then, not at ingest.
	// It defaults to the system clock.
	Now func() time.Time
}

// Release is one verified runtime release: the manifest as approved material,
// the identity it was ingested under, and the binding a Run pins when this
// release is selected.
type Release struct {
	RuntimeUnitID string
	DefinitionID  string
	// CutForDefinitionDigest is the definition generation the release records
	// itself as built for. See verify for why it is recorded rather than
	// required to equal the current generation.
	CutForDefinitionDigest string
	ManifestDigest         string
	Capabilities           []string
	// Lifecycle is the state the manifest declares, and EffectiveAt is when
	// that state takes effect. Read them together through LifecycleAt: a
	// state without its time makes every scheduled change immediate.
	Lifecycle   string
	EffectiveAt time.Time
	Binding     agent.RuntimeBinding
	Manifest    schema.AgentRuntimeManifest
}

// LifecycleAt reports the lifecycle state in force at one instant. Before the
// manifest's effective time, a release cut as active is not yet active, and a
// release cut as revoked or disabled is still the active release the cut
// withdraws — a lifecycle decision takes effect when its operator said it
// would, not when the service that carries it happened to start.
func (r Release) LifecycleAt(now time.Time) string {
	if now.Before(r.EffectiveAt) {
		if r.Lifecycle == "active" {
			return "not yet active"
		}
		return "active"
	}
	return r.Lifecycle
}

// Registry holds the approved release set. Construction fails closed: a
// manifest that is not in the approved catalog, whose bytes do not match it,
// that fails the canonical schema, that carries a mutable or unsigned image,
// that speaks another invocation protocol, or that contradicts the definition
// it claims to be a release of, produces no registry at all.
type Registry struct {
	byDefinition  map[string]Release
	policy        SelectionPolicy
	catalogDigest string
	now           func() time.Time
}

// NewRegistry ingests and verifies every approved release.
func NewRegistry(ctx context.Context, cfg RegistryConfig) (*Registry, error) {
	if cfg.Source == nil || cfg.Validator == nil || cfg.ManifestSchemaURI == "" {
		return nil, fmt.Errorf("runtime registry: source, schema validator, and pinned schema identity are required")
	}
	if !validDigest(cfg.Policy.InvocationProtocolDigest) {
		return nil, fmt.Errorf("runtime registry: the selection policy must pin the invocation protocol this service speaks")
	}
	catalogBytes, err := cfg.Source.Catalog(ctx)
	if err != nil {
		return nil, fmt.Errorf("runtime registry: load approved catalog: %w", err)
	}
	catalog, err := ParseCatalog(catalogBytes)
	if err != nil {
		return nil, fmt.Errorf("runtime registry: %w", err)
	}
	if err := catalog.Authenticate(cfg.Approval); err != nil {
		return nil, fmt.Errorf("runtime registry: %w", err)
	}

	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	registry := &Registry{
		byDefinition:  make(map[string]Release, len(catalog.Releases)),
		policy:        cfg.Policy,
		catalogDigest: DocumentDigest(catalogBytes),
		now:           now,
	}
	for _, entry := range catalog.Releases {
		raw, err := cfg.Source.Document(ctx, entry.Document)
		if err != nil {
			return nil, fmt.Errorf("runtime registry: release %s: %w", entry.DefinitionID, err)
		}
		if !equalDigest(DocumentDigest(raw), entry.DocumentDigest) {
			return nil, fmt.Errorf("runtime registry: release %s does not match the approved catalog", entry.DefinitionID)
		}
		// The canonical schema decides the shape; this package decides what is
		// releasable. Validating first means every rule below can read a
		// document it knows is contract-valid.
		if findings := cfg.Validator.Validate(cfg.ManifestSchemaURI, raw); len(findings) != 0 {
			return nil, fmt.Errorf("runtime registry: release %s violates the canonical AgentRuntimeManifest contract: %v", entry.DefinitionID, findings)
		}
		var manifest schema.AgentRuntimeManifest
		if err := decodeJSON(raw, &manifest); err != nil {
			return nil, fmt.Errorf("runtime registry: decode release %s: %w", entry.DefinitionID, err)
		}
		release, err := registry.verify(entry, manifest, DocumentDigest(raw))
		if err != nil {
			return nil, fmt.Errorf("runtime registry: %w", err)
		}
		registry.byDefinition[entry.DefinitionID] = release
	}
	return registry, nil
}

// verify holds one manifest to everything a release must be true about before
// it can ever be selected.
func (r *Registry) verify(entry CatalogRelease, manifest schema.AgentRuntimeManifest, manifestDigest string) (Release, error) {
	label := entry.DefinitionID
	if manifest.Kind != "AgentRuntimeManifest" {
		return Release{}, fmt.Errorf("release %s does not declare itself an AgentRuntimeManifest", label)
	}
	if string(manifest.RuntimeUnitId) != entry.RuntimeUnitID || string(manifest.Definition.DefinitionId) != entry.DefinitionID {
		return Release{}, fmt.Errorf("release %s is a release of other material than the catalog approves", label)
	}
	// The manifest records the definition generation the release was cut for.
	// It cannot record the *current* generation: a definition pins its runtime
	// manifest digest, and that digest covers this reference, so a manifest
	// naming the definition that names it would have to contain a digest of a
	// document containing its own digest. The ratchet — release cut for
	// generation N, definition generation N+1 pins it — is how a real release
	// pipeline resolves that, and proving a generation belongs to a
	// definition's history needs history this repository does not keep yet.
	// Until a release pipeline that keeps that history exists, the direction
	// that can be proven is proven exactly, below: the definition pins this
	// release and nothing else.
	// Provenance and image identity. An image named by a tag can be replaced
	// under a release that was approved once; a release with no provenance or
	// signature reference attests to nothing at all.
	for name, digest := range map[string]string{
		"image":               string(manifest.Image.ImageDigest),
		"provenance":          string(manifest.Image.ProvenanceDigest),
		"image signature":     string(manifest.Image.SignatureDigest),
		"rollback target":     string(manifest.Release.RollbackTarget),
		"definition":          string(manifest.Definition.DefinitionDigest),
		"invocation protocol": string(manifest.Protocol.InvocationProtocolDigest),
	} {
		if !validDigest(digest) {
			return Release{}, fmt.Errorf("release %s names no immutable %s digest", label, name)
		}
	}
	if !equalDigest(string(manifest.Protocol.InvocationProtocolDigest), r.policy.InvocationProtocolDigest) {
		return Release{}, fmt.Errorf("release %s speaks invocation protocol %s, which this service does not", label, manifest.Protocol.InvocationProtocolDigest)
	}
	if !validAudience(manifest.Workload.Audience) {
		return Release{}, fmt.Errorf("release %s names no governed workload audience", label)
	}
	if len(manifest.Capabilities) == 0 {
		return Release{}, fmt.Errorf("release %s declares no capability, so nothing could ever be dispatched to it", label)
	}
	capabilities := make([]string, 0, len(manifest.Capabilities))
	for _, capability := range manifest.Capabilities {
		capabilities = append(capabilities, string(capability))
	}
	sort.Strings(capabilities)
	lifecycle := string(manifest.Lifecycle.State)
	switch lifecycle {
	case "active", "revoked", "disabled":
	default:
		return Release{}, fmt.Errorf("release %s carries lifecycle state %q, which is outside the governed vocabulary", label, lifecycle)
	}
	// The effective time is parsed at ingest so a selection never has to
	// decide what an unreadable instant means: a release whose lifecycle
	// cannot be placed in time is not releasable material.
	effectiveAt := time.Time(manifest.Lifecycle.EffectiveAt)
	if effectiveAt.IsZero() {
		return Release{}, fmt.Errorf("release %s carries a lifecycle with no effective time", label)
	}
	return Release{
		RuntimeUnitID:          entry.RuntimeUnitID,
		DefinitionID:           entry.DefinitionID,
		CutForDefinitionDigest: string(manifest.Definition.DefinitionDigest),
		ManifestDigest:         manifestDigest,
		Capabilities:           capabilities,
		Lifecycle:              lifecycle,
		EffectiveAt:            effectiveAt.UTC(),
		Binding: agent.RuntimeBinding{
			RuntimeUnitID:            entry.RuntimeUnitID,
			RuntimeManifestDigest:    manifestDigest,
			RuntimeImageDigest:       string(manifest.Image.ImageDigest),
			InvocationProtocolDigest: string(manifest.Protocol.InvocationProtocolDigest),
			RuntimeAudience:          manifest.Workload.Audience,
		},
		Manifest: manifest,
	}, nil
}

// Request is what a caller asks the registry to select for.
type Request struct {
	// Definition is the definition the registry resolved for this run. Its
	// pinned binding is the release the approving authority chose; selection
	// proves that choice is still one this service may act on.
	Definition agent.Definition
	// Capability is the task capability the dispatched work will carry.
	Capability string
}

// TurnCapability is the capability an Agent turn requires: the runtime resolves
// the turn through the governed Model Gateway.
const TurnCapability = "provider.invoke"

// Select returns the one approved release for a definition, or a typed reason
// why there is none. It is a pure function of approved material, the request,
// and the registry's selection policy: identical inputs select the same
// release, and nothing about the calling process can change that.
func (r *Registry) Select(request Request) (Release, error) {
	definition := request.Definition
	if definition.DefinitionID == "" {
		return Release{}, fmt.Errorf("runtime selection: a definition identity is required")
	}
	release, known := r.byDefinition[definition.DefinitionID]
	if !known {
		return Release{}, fmt.Errorf("runtime selection: definition %s has no approved runtime release", definition.DefinitionID)
	}
	// A revoked or emergency-disabled release may not be selected for new work.
	// Runs already pinned to it are unaffected: rollback changes selection, not
	// the pins of runs that are already executing. The state is read at the
	// instant its manifest says it takes effect, so a change the operator cut
	// ahead of time neither applies early nor lingers past its time.
	if state := release.LifecycleAt(r.now().UTC()); state != "active" {
		return Release{}, fmt.Errorf("runtime selection: the approved release for %s is %s", definition.DefinitionID, state)
	}
	if request.Capability != "" && !contains(release.Capabilities, request.Capability) {
		return Release{}, fmt.Errorf("runtime selection: the approved release for %s does not serve capability %s", definition.DefinitionID, request.Capability)
	}
	// The definition's own binding and the release must be the same release.
	// The definition says which runtime its authority approved; the registry
	// says which runtime exists and is verified. A disagreement means one of
	// the two moved, and neither is safe to prefer silently.
	if err := sameRelease(definition.RuntimeBinding, release.Binding); err != nil {
		return Release{}, fmt.Errorf("runtime selection: definition %s %w", definition.DefinitionID, err)
	}
	return release, nil
}

// Releases lists the approved set ordered by definition identity.
func (r *Registry) Releases() []Release {
	releases := make([]Release, 0, len(r.byDefinition))
	for _, release := range r.byDefinition {
		releases = append(releases, release)
	}
	sort.Slice(releases, func(i, j int) bool { return releases[i].DefinitionID < releases[j].DefinitionID })
	return releases
}

// CatalogDigest is the digest of the approved catalog this registry was built
// from. It is the identity an external attestation signs.
func (r *Registry) CatalogDigest() string { return r.catalogDigest }

func sameRelease(pinned, approved agent.RuntimeBinding) error {
	for name, pair := range map[string][2]string{
		"runtime unit":      {pinned.RuntimeUnitID, approved.RuntimeUnitID},
		"manifest digest":   {pinned.RuntimeManifestDigest, approved.RuntimeManifestDigest},
		"image digest":      {pinned.RuntimeImageDigest, approved.RuntimeImageDigest},
		"protocol digest":   {pinned.InvocationProtocolDigest, approved.InvocationProtocolDigest},
		"workload audience": {pinned.RuntimeAudience, approved.RuntimeAudience},
	} {
		if pair[0] != pair[1] {
			return fmt.Errorf("pins a %s the approved release does not carry", name)
		}
	}
	return nil
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

//go:embed releases/catalog.json
//go:embed releases/release.platform.manager.json
//go:embed releases/release.platform.component-spec-specialist.json
//go:embed releases/release.platform.page-change-manager.json
//go:embed releases/release.platform.page-candidate-specialist.json
var embeddedReleases embed.FS

// EmbeddedCatalog is the first-party approved release store shipped with the
// service. Every file it can serve is named explicitly in the embed directives
// above, so a missing file is a build failure rather than a silently smaller
// catalog at run time.
type EmbeddedCatalog struct{}

func (EmbeddedCatalog) Catalog(context.Context) ([]byte, error) {
	return embeddedReleases.ReadFile("releases/catalog.json")
}

func (EmbeddedCatalog) Document(_ context.Context, name string) ([]byte, error) {
	if strings.ContainsAny(name, `/\`) || name == "" {
		return nil, fmt.Errorf("release document %q is not an approved document name", name)
	}
	return embeddedReleases.ReadFile("releases/" + name)
}
