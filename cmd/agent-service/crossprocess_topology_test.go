package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ancyloce/anvilkit-agent-service/internal/api"
	"github.com/ancyloce/anvilkit-agent-service/internal/config"
	contractguard "github.com/ancyloce/anvilkit-agent-service/internal/contracts"
	"github.com/ancyloce/anvilkit-agent-service/internal/journal"
	"github.com/ancyloce/anvilkit-agent-service/internal/persistence"
	"github.com/ancyloce/anvilkit-agent-service/internal/runtimes"
	"github.com/ancyloce/anvilkit-agent-service/internal/telemetry"
	workflowdbos "github.com/ancyloce/anvilkit-agent-service/internal/workflow/dbos"
)

// The cross-process topology: PostgreSQL, an Agent Service composed with the
// HTTP dispatcher and the runtime boundary served, and the Manager and
// Specialist as separate processes each with their own workload identity,
// result-signing key, and mounted trust root. The model gateway, worker, and
// domain (Pagix) are controlled fakes composed into the Agent Service — the
// downstream dependencies the kernel keeps as test doubles — but the
// reasoning loop runs only in the two runtime processes. Nothing here can
// complete through an in-process reasoning path: the dispatcher is HTTP, and
// the in-process runtime is refused by name in the production-eligibility gate.
//
// Two transparent intermediaries make faults injectable without touching
// either side: a fault proxy between the dispatcher and each unit, and a
// control-plane gate between the units and the Agent Service. The Agent
// Service itself is composed in the test process for most scenarios and run
// as the production binary in its own process where a scenario has to crash
// or replace it.

var builtUnits struct {
	once       sync.Once
	dir        string
	manager    string
	specialist string
	err        error
}

// runtimeUnitBinaries builds the two runtime unit binaries once per run.
func runtimeUnitBinaries(t *testing.T) (managerPath, specialistPath string) {
	t.Helper()
	if _, err := os.Stat("../../../agent-runtimes/go.mod"); err != nil {
		t.Skipf("the agent-runtimes submodule is not checked out: %v", err)
	}
	builtUnits.once.Do(func() {
		dir, err := os.MkdirTemp("", "anvilkit-runtime-units-")
		if err != nil {
			builtUnits.err = err
			return
		}
		builtUnits.dir = dir
		for _, unit := range []struct {
			name   string
			target *string
		}{
			{"page-change-manager", &builtUnits.manager},
			{"page-candidate-specialist", &builtUnits.specialist},
		} {
			output := filepath.Join(dir, unit.name)
			if err := goBuild("../../../agent-runtimes", output, nil, "./agents/"+unit.name); err != nil {
				builtUnits.err = err
				return
			}
			*unit.target = output
		}
	})
	if builtUnits.err != nil {
		t.Fatalf("building runtime units: %v", builtUnits.err)
	}
	return builtUnits.manager, builtUnits.specialist
}

var builtService struct {
	once        sync.Once
	binary      string
	releaseTool string
	err         error
}

// serviceBinary builds the production agent-service binary — the real
// entrypoint, not a test composition — once per run, together with the
// runtime-release tool a rollout cuts its material with.
func serviceBinary(t *testing.T) (service, releaseTool string) {
	t.Helper()
	builtService.once.Do(func() {
		dir, err := os.MkdirTemp("", "anvilkit-agent-service-")
		if err != nil {
			builtService.err = err
			return
		}
		builtService.binary = filepath.Join(dir, "agent-service")
		if err := goBuild("../..", builtService.binary, nil, "./cmd/agent-service"); err != nil {
			builtService.err = err
			return
		}
		builtService.releaseTool = filepath.Join(dir, "runtime-release")
		if err := goBuild("../..", builtService.releaseTool, nil, "./cmd/runtime-release"); err != nil {
			builtService.err = err
		}
	})
	if builtService.err != nil {
		t.Fatalf("building the agent-service binary: %v", builtService.err)
	}
	return builtService.binary, builtService.releaseTool
}

// overlayServiceBinary builds the production agent-service binary with the
// given source files replaced — the way a release cut reaches a deployment:
// the approved release and definition stores are embedded at build time, so a
// new generation of approved material is a new build of the service.
func overlayServiceBinary(t *testing.T, replace map[string]string) string {
	t.Helper()
	absolute := make(map[string]string, len(replace))
	for source, replacement := range replace {
		absolute[mustAbs(t, source)] = mustAbs(t, replacement)
	}
	overlay := writeJSONFile(t, t.TempDir(), "overlay.json", map[string]any{"Replace": absolute})
	output := filepath.Join(t.TempDir(), "agent-service-overlay")
	if err := goBuild("../..", output, []string{"-overlay", overlay}, "./cmd/agent-service"); err != nil {
		t.Fatalf("building the overlaid agent-service binary: %v", err)
	}
	return output
}

func goBuild(dir, output string, flags []string, pkg string) error {
	arguments := append([]string{"build"}, flags...)
	arguments = append(arguments, "-o", output, pkg)
	cmd := exec.Command("go", arguments...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=go1.26.6")
	if combined, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("go build %s: %v\n%s", pkg, err, combined)
	}
	return nil
}

// releaseRecord is the approved release document a unit is deployed with; the
// unit's manifest IS this document, so admission's release binding matches the
// dispatched task's binding exactly.
type releaseRecord struct {
	path             string
	documentDigest   string
	imageDigest      string
	protocolDigest   string
	provenanceDigest string
	audience         string
	unitID           string
	definitionID     string
	definitionDigest string
	drainSeconds     int
}

// embeddedReleases is the approved release store the service ships with.
const embeddedReleases = "../../internal/runtimes/releases"

// embeddedDefinitions is the approved definition store the service ships with.
const embeddedDefinitions = "../../internal/agent/definitions"

func loadReleaseRecord(t *testing.T, unitID, name string) releaseRecord {
	t.Helper()
	return loadReleaseRecordPath(t, unitID, filepath.Join(embeddedReleases, name))
}

func loadReleaseRecordPath(t *testing.T, unitID, path string) releaseRecord {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	var document struct {
		RuntimeUnitID string `json:"runtimeUnitId"`
		Definition    struct {
			DefinitionID     string `json:"definitionId"`
			DefinitionDigest string `json:"definitionDigest"`
		} `json:"definition"`
		Image struct {
			ImageDigest      string `json:"imageDigest"`
			ProvenanceDigest string `json:"provenanceDigest"`
		} `json:"image"`
		Protocol struct {
			InvocationProtocolDigest string `json:"invocationProtocolDigest"`
		} `json:"protocol"`
		Workload struct {
			Audience string `json:"audience"`
		} `json:"workload"`
		Release struct {
			DrainSeconds int `json:"drainSeconds"`
		} `json:"release"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	if document.RuntimeUnitID != unitID {
		t.Fatalf("release %s is a release of %s, not %s", path, document.RuntimeUnitID, unitID)
	}
	return releaseRecord{
		path:             path,
		documentDigest:   "sha256:" + hex.EncodeToString(sum[:]),
		imageDigest:      document.Image.ImageDigest,
		protocolDigest:   document.Protocol.InvocationProtocolDigest,
		provenanceDigest: document.Image.ProvenanceDigest,
		audience:         document.Workload.Audience,
		unitID:           document.RuntimeUnitID,
		definitionID:     document.Definition.DefinitionID,
		definitionDigest: document.Definition.DefinitionDigest,
		drainSeconds:     document.Release.DrainSeconds,
	}
}

type keypair struct {
	public ed25519.PublicKey
	seed   string
}

func newKeypair(t *testing.T) keypair {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(seed)
	return keypair{public: key.Public().(ed25519.PublicKey), seed: base64.RawURLEncoding.EncodeToString(seed)}
}

const trustTimestamp = "2006-01-02T15:04:05.000Z"

func writeCredentialTrustRoot(t *testing.T, dir string, credential keypair, keyID string, audiences []string, now time.Time) string {
	t.Helper()
	root := map[string]any{
		"kind":                    "ContractTrustRoot",
		"snapshotId":              "cross-process-task-credentials",
		"issuedAt":                now.Format(trustTimestamp),
		"nextUpdate":              now.Add(24 * time.Hour).Format(trustTimestamp),
		"maximumClockSkewSeconds": 60,
		"keys": []map[string]any{{
			"keyId":        keyID,
			"issuer":       "urn:anvilkit:service:agent-service",
			"audiences":    audiences,
			"algorithms":   []string{"EdDSA"},
			"publicKeyJwk": map[string]string{"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(credential.public)},
			"status":       "active",
			"notBefore":    now.Add(-time.Hour).Format(trustTimestamp),
			"notAfter":     now.Add(24 * time.Hour).Format(trustTimestamp),
		}},
	}
	return writeJSONFile(t, dir, "task-credential-trust-root.json", root)
}

type signingTrustKey struct {
	keyID            string
	unitID           string
	audience         string
	public           ed25519.PublicKey
	manifestDigest   string
	provenanceDigest string
}

// signingTrustFor is the trust entry that lets a service attribute results to
// one released unit signing with one key.
func signingTrustFor(keyID string, release releaseRecord, signing keypair) signingTrustKey {
	return signingTrustKey{keyID: keyID, unitID: release.unitID, audience: release.audience, public: signing.public, manifestDigest: release.documentDigest, provenanceDigest: release.provenanceDigest}
}

func writeSigningTrust(t *testing.T, dir, name string, keys []signingTrustKey, now time.Time) string {
	t.Helper()
	entries := make([]map[string]any, 0, len(keys))
	for _, key := range keys {
		entries = append(entries, map[string]any{
			"keyId":                  key.keyID,
			"runtimeUnitIds":         []string{key.unitID},
			"audiences":              []string{key.audience},
			"algorithm":              "dsse-ed25519-v1",
			"publicKeyJwk":           map[string]string{"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(key.public)},
			"status":                 "active",
			"notBefore":              now.Add(-time.Hour).Format(trustTimestamp),
			"notAfter":               now.Add(24 * time.Hour).Format(trustTimestamp),
			"runtimeManifestDigests": []string{key.manifestDigest},
			"provenanceDigests":      []string{key.provenanceDigest},
		})
	}
	store := map[string]any{
		"kind":                    "AgentRuntimeSigningTrust",
		"snapshotId":              "cross-process-signing-trust",
		"issuedAt":                now.Format(trustTimestamp),
		"nextUpdate":              now.Add(24 * time.Hour).Format(trustTimestamp),
		"maximumClockSkewSeconds": 60,
		"keys":                    entries,
	}
	return writeJSONFile(t, dir, name, store)
}

func writeJSONFile(t *testing.T, dir, name string, document any) string {
	t.Helper()
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, append(encoded, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// capturedAnswer is one answer an intermediary read from the side it forwards
// to, kept so a scenario can inspect it or present it again later.
type capturedAnswer struct {
	status int
	header http.Header
	body   []byte
}

func (a *capturedAnswer) write(response http.ResponseWriter) {
	for name, values := range a.header {
		for _, value := range values {
			response.Header().Add(name, value)
		}
	}
	response.WriteHeader(a.status)
	_, _ = response.Write(a.body)
}

// forwardRequest replays one inbound request against a target and reads the
// whole answer. The context decides who may abandon it: the caller's, or a
// detached one the caller cannot cancel.
func forwardRequest(ctx context.Context, request *http.Request, target string, body []byte) (*capturedAnswer, error) {
	forwarded, err := http.NewRequestWithContext(ctx, request.Method, target+request.URL.Path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	for name, values := range request.Header {
		for _, value := range values {
			forwarded.Header.Add(name, value)
		}
	}
	upstream, err := http.DefaultClient.Do(forwarded)
	if err != nil {
		return nil, err
	}
	defer func() { _ = upstream.Body.Close() }()
	answer, err := io.ReadAll(upstream.Body)
	if err != nil {
		return nil, err
	}
	return &capturedAnswer{status: upstream.StatusCode, header: upstream.Header.Clone(), body: answer}, nil
}

func hijackClose(response http.ResponseWriter) {
	if hijacker, ok := response.(http.Hijacker); ok {
		if connection, _, err := hijacker.Hijack(); err == nil {
			_ = connection.Close()
		}
	}
}

// faultProxy sits between the dispatcher and a runtime unit so a scenario can
// inject a transport fault — a dropped response, a delay, a hard failure, a
// duplicate delivery, a stale answer — without touching the unit. Its address
// is stable across the run; its target and behaviour are set after the unit
// spawns.
type faultProxy struct {
	server *httptest.Server
	target atomic.Pointer[string]
	// mode is the current fault behaviour, read per request.
	mode atomic.Pointer[proxyMode]
	// captured is the last answer a dropped response carried: what the unit
	// actually said, which the dispatcher never heard.
	captured atomic.Pointer[capturedAnswer]
	// duplicates records what the second delivery of a duplicated request
	// answered.
	duplicates struct {
		sync.Mutex
		deliveries []duplicateDelivery
	}
	// dispatched records every task body that reached the unit, by physical
	// attempt: the bytes a network retry would present again. The durable
	// offer record cannot serve that purpose — it keeps the fence's digest,
	// never the token — so what was actually sent is remembered here.
	dispatched struct {
		sync.Mutex
		bodies map[string][]byte
	}
	// releaseOnCleanup releases a held block gate so a failed test does not
	// hang the server's Close on an in-flight handler.
	releaseOnCleanup func()
}

type proxyMode struct {
	// dropResponse forwards the request to the unit but returns a transport
	// error to the dispatcher — the unit executed, the answer was lost. The
	// answer is captured.
	dropResponse bool
	// failClosed answers the dispatcher with a network failure without
	// reaching the unit at all.
	failClosed bool
	// blockUntil holds the request until the channel is closed, modelling a
	// slow unit the dispatch deadline must bound.
	blockUntil chan struct{}
	// duplicate delivers the same request to the unit twice — the same
	// AgentTask delivered more than once — and answers the dispatcher with the
	// first answer. What the second delivery answered is recorded.
	duplicate bool
	// answerCaptured answers the dispatcher with the answer captured from an
	// earlier dropped response, without reaching the unit: an old attempt's
	// result presented against a newer dispatch.
	answerCaptured bool
	// detach forwards with a context the dispatcher cannot cancel, so the unit
	// keeps executing after the dispatcher has given up on the attempt.
	detach bool
	// once, when set, reverts the proxy to normal after it applies the fault to
	// one request. It models a single lost response or a single crash, after
	// which the durable replacement reaches a healthy unit.
	once bool
	// next, when set with once, is the mode that follows the spent fault
	// instead of normal: a sequence of faults, each applied to one request.
	next *proxyMode
}

// duplicateDelivery is what the second delivery of one request answered.
type duplicateDelivery struct {
	status    int
	replayed  bool
	identical bool
}

func newFaultProxy(t *testing.T) *faultProxy {
	t.Helper()
	proxy := &faultProxy{}
	proxy.mode.Store(&proxyMode{})
	proxy.server = httptest.NewServer(http.HandlerFunc(proxy.serve))
	t.Cleanup(func() {
		if proxy.releaseOnCleanup != nil {
			proxy.releaseOnCleanup()
		}
		proxy.server.Close()
	})
	return proxy
}

func (p *faultProxy) serve(response http.ResponseWriter, request *http.Request) {
	mode := p.mode.Load()
	if mode.once && (mode.dropResponse || mode.failClosed || mode.duplicate || mode.answerCaptured) {
		// The fault is spent on this request; the next dispatch reaches a
		// healthy unit — or the next fault in the sequence — which is what
		// makes recovery observable.
		if mode.next != nil {
			p.mode.Store(mode.next)
		} else {
			p.normal()
		}
	}
	if mode.blockUntil != nil {
		select {
		case <-mode.blockUntil:
		case <-request.Context().Done():
			return
		}
	}
	if mode.failClosed {
		hijackClose(response)
		return
	}
	if mode.answerCaptured {
		captured := p.captured.Load()
		if captured == nil {
			response.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		captured.write(response)
		return
	}
	target := p.target.Load()
	if target == nil {
		response.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	body, _ := io.ReadAll(request.Body)
	if attemptID := request.Header.Get("Idempotency-Key"); attemptID != "" && request.URL.Path == "/task" {
		p.dispatched.Lock()
		if p.dispatched.bodies == nil {
			p.dispatched.bodies = map[string][]byte{}
		}
		p.dispatched.bodies[attemptID] = append([]byte(nil), body...)
		p.dispatched.Unlock()
	}
	ctx := request.Context()
	if mode.detach {
		ctx = context.Background()
	}
	answer, err := forwardRequest(ctx, request, *target, body)
	if err != nil {
		response.WriteHeader(http.StatusBadGateway)
		return
	}
	if mode.duplicate {
		// The same bytes, the same headers, the same attempt: the second
		// delivery of one AgentTask.
		record := duplicateDelivery{}
		if second, secondErr := forwardRequest(ctx, request, *target, body); secondErr == nil {
			record = duplicateDelivery{status: second.status, replayed: second.header.Get("Idempotency-Replayed") == "true", identical: bytes.Equal(second.body, answer.body)}
		}
		p.duplicates.Lock()
		p.duplicates.deliveries = append(p.duplicates.deliveries, record)
		p.duplicates.Unlock()
	}
	if mode.dropResponse {
		// The unit executed and answered; the dispatcher never learns the
		// outcome. Hijack and close so the dispatcher sees a transport error.
		p.captured.Store(answer)
		hijackClose(response)
		return
	}
	if mode.detach && request.Context().Err() != nil {
		// The dispatcher gave up before the unit answered; the answer has
		// nowhere to go.
		return
	}
	answer.write(response)
}

func (p *faultProxy) normal()        { p.mode.Store(&proxyMode{}) }
func (p *faultProxy) fail()          { p.mode.Store(&proxyMode{failClosed: true}) }
func (p *faultProxy) dropOnce()      { p.mode.Store(&proxyMode{dropResponse: true, once: true}) }
func (p *faultProxy) failOnce()      { p.mode.Store(&proxyMode{failClosed: true, once: true}) }
func (p *faultProxy) duplicateOnce() { p.mode.Store(&proxyMode{duplicate: true, once: true}) }
func (p *faultProxy) detach()        { p.mode.Store(&proxyMode{detach: true}) }

// dropThenReplayStale loses one answer and then presents that lost answer —
// the old attempt's successful, validly signed result — to the very next
// dispatch, which by then belongs to the replacement attempt.
func (p *faultProxy) dropThenReplayStale() {
	p.mode.Store(&proxyMode{dropResponse: true, once: true, next: &proxyMode{answerCaptured: true, once: true}})
}

// duplicateDeliveries reports what every duplicated delivery's second copy
// answered.
// dispatchedBody returns the exact task bytes one attempt was dispatched with.
func (p *faultProxy) dispatchedBody(attemptID string) ([]byte, bool) {
	p.dispatched.Lock()
	defer p.dispatched.Unlock()
	body, known := p.dispatched.bodies[attemptID]
	return append([]byte(nil), body...), known
}

func (p *faultProxy) duplicateDeliveries() []duplicateDelivery {
	p.duplicates.Lock()
	defer p.duplicates.Unlock()
	return append([]duplicateDelivery(nil), p.duplicates.deliveries...)
}

func (p *faultProxy) block() func() {
	gate := make(chan struct{})
	p.mode.Store(&proxyMode{blockUntil: gate})
	var once sync.Once
	release := func() { once.Do(func() { close(gate); p.normal() }) }
	// A test that fails before it releases the gate would leave the proxy
	// handler blocked, and the httptest server's Close would then wait for it
	// forever. Cleanup releases it so a failure surfaces as a failure.
	p.releaseOnCleanup = release
	return release
}

// credentialClaims is what an intermediary may read from a task credential
// without verifying it: enough to route and to match a hold. Nothing here is
// trusted for anything else.
type credentialClaims struct {
	audience       string
	runID          string
	attemptID      string
	manifestDigest string
}

func claimsOf(authorization string) credentialClaims {
	token := strings.TrimSpace(strings.TrimPrefix(authorization, "Bearer "))
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return credentialClaims{}
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return credentialClaims{}
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(payload, &document); err != nil {
		return credentialClaims{}
	}
	var claims credentialClaims
	_ = json.Unmarshal(document["aud"], &claims.audience)
	var binding runtimes.Binding
	_ = json.Unmarshal(document[runtimes.CredentialBindingClaim], &binding)
	claims.runID, claims.attemptID, claims.manifestDigest = binding.RunID, binding.PhysicalAttemptID, binding.RuntimeManifestDigest
	return claims
}

// controlPlaneGate sits between the runtime units and the Agent Service — the
// one origin a unit may reach — so a scenario can hold a unit's callback
// before the service sees it, or hold the service's answer before the unit
// does, and can move the units to a successor service without their knowing.
// Callbacks are routed by the run they belong to when a scenario runs more
// than one service instance, the way a fleet behind one address would be.
type controlPlaneGate struct {
	server *httptest.Server
	target atomic.Pointer[string]
	lock   sync.Mutex
	routes map[string]string
	// releaseRoutes send the callbacks of every attempt pinned to one runtime
	// manifest to one service instance: the instance whose approved catalog
	// carries that release.
	releaseRoutes map[string]string
	holds         []*gateHold
}

// gateHold is one pending interception: the first callback that matches is
// held until released, and what the service answered is recorded.
type gateHold struct {
	match func(path string, claims credentialClaims) bool
	// after holds the answer on its way back to the unit rather than the
	// request on its way to the service.
	after   bool
	caught  chan struct{}
	gate    chan struct{}
	done    chan struct{}
	spent   atomic.Bool
	release sync.Once
	finish  sync.Once
	outcome gateOutcome
	// answer is what the service answered a held-after callback, known the
	// moment it is caught — before the unit hears it.
	answer atomic.Pointer[capturedAnswer]
}

// gateOutcome is what became of a held callback.
type gateOutcome struct {
	// forwarded reports whether the service saw the request at all.
	forwarded bool
	// delivered reports whether the unit received the answer.
	delivered bool
	status    int
	body      []byte
}

func newControlPlaneGate(t *testing.T) *controlPlaneGate {
	t.Helper()
	gate := &controlPlaneGate{routes: map[string]string{}, releaseRoutes: map[string]string{}}
	gate.server = httptest.NewServer(http.HandlerFunc(gate.serve))
	t.Cleanup(func() {
		gate.lock.Lock()
		holds := append([]*gateHold(nil), gate.holds...)
		gate.lock.Unlock()
		for _, hold := range holds {
			hold.Release()
		}
		gate.server.Close()
	})
	return gate
}

func (g *controlPlaneGate) retarget(url string) { g.target.Store(&url) }

// route sends every callback of one run to a specific service instance.
func (g *controlPlaneGate) route(runID, url string) {
	g.lock.Lock()
	defer g.lock.Unlock()
	g.routes[runID] = url
}

// routeRelease sends every callback of attempts pinned to one manifest to a
// specific service instance.
func (g *controlPlaneGate) routeRelease(manifestDigest, url string) {
	g.lock.Lock()
	defer g.lock.Unlock()
	g.releaseRoutes[manifestDigest] = url
}

func (g *controlPlaneGate) targetFor(claims credentialClaims) string {
	g.lock.Lock()
	defer g.lock.Unlock()
	if url, routed := g.routes[claims.runID]; routed && claims.runID != "" {
		return url
	}
	if url, routed := g.releaseRoutes[claims.manifestDigest]; routed && claims.manifestDigest != "" {
		return url
	}
	if target := g.target.Load(); target != nil {
		return *target
	}
	return ""
}

// hold registers a one-shot interception of the first matching callback.
func (g *controlPlaneGate) hold(after bool, match func(path string, claims credentialClaims) bool) *gateHold {
	hold := &gateHold{match: match, after: after, caught: make(chan struct{}), gate: make(chan struct{}), done: make(chan struct{})}
	g.lock.Lock()
	g.holds = append(g.holds, hold)
	g.lock.Unlock()
	return hold
}

func (g *controlPlaneGate) claim(path string, claims credentialClaims) *gateHold {
	g.lock.Lock()
	defer g.lock.Unlock()
	for _, hold := range g.holds {
		if hold.spent.Load() || !hold.match(path, claims) {
			continue
		}
		hold.spent.Store(true)
		return hold
	}
	return nil
}

func (h *gateHold) Release() { h.release.Do(func() { close(h.gate) }) }

func (h *gateHold) conclude(outcome gateOutcome) {
	h.finish.Do(func() {
		h.outcome = outcome
		close(h.done)
	})
}

// awaitCaught waits until the hold has intercepted its callback.
func (h *gateHold) awaitCaught(t *testing.T, timeout time.Duration) {
	t.Helper()
	select {
	case <-h.caught:
	case <-time.After(timeout):
		t.Fatal("the control-plane gate never caught the callback it was set to hold")
	}
}

// result waits for the held callback to conclude and reports what became of it.
func (h *gateHold) result(t *testing.T, timeout time.Duration) gateOutcome {
	t.Helper()
	select {
	case <-h.done:
		return h.outcome
	case <-time.After(timeout):
		t.Fatal("the held callback never concluded")
		return gateOutcome{}
	}
}

func (g *controlPlaneGate) serve(response http.ResponseWriter, request *http.Request) {
	claims := claimsOf(request.Header.Get("Authorization"))
	body, _ := io.ReadAll(request.Body)
	hold := g.claim(request.URL.Path, claims)
	if hold != nil && !hold.after {
		close(hold.caught)
		select {
		case <-hold.gate:
		case <-request.Context().Done():
		}
		if request.Context().Err() != nil {
			// The unit went away while its callback was held: the service
			// never sees it.
			hold.conclude(gateOutcome{})
			return
		}
	}
	target := g.targetFor(claims)
	if target == "" {
		if hold != nil {
			hold.conclude(gateOutcome{})
		}
		response.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	// The service is reached with a context the unit cannot cancel, so a held
	// answer is an answer the service has fully committed to.
	answer, err := forwardRequest(context.Background(), request, target, body)
	if err != nil {
		if hold != nil {
			hold.conclude(gateOutcome{})
		}
		response.WriteHeader(http.StatusBadGateway)
		return
	}
	if hold != nil && hold.after {
		hold.answer.Store(answer)
		close(hold.caught)
		select {
		case <-hold.gate:
		case <-request.Context().Done():
			hold.conclude(gateOutcome{forwarded: true, status: answer.status, body: answer.body})
			return
		}
	}
	if hold != nil {
		hold.conclude(gateOutcome{forwarded: true, delivered: request.Context().Err() == nil, status: answer.status, body: answer.body})
	}
	answer.write(response)
}

// callbackFrom matches one callback path from one runtime audience.
func callbackFrom(path, audience string) func(string, credentialClaims) bool {
	return func(requestPath string, claims credentialClaims) bool {
		return requestPath == path && claims.audience == audience
	}
}

// callbackForRun matches one callback path — or any path, when empty — made
// on behalf of one run.
func callbackForRun(path, runID string) func(string, credentialClaims) bool {
	return func(requestPath string, claims credentialClaims) bool {
		return (path == "" || requestPath == path) && claims.runID == runID
	}
}

// unitSpec is everything one runtime unit process is spawned from, kept so a
// crashed unit can be respawned as the same released unit.
type unitSpec struct {
	binary              string
	release             releaseRecord
	controlPlane        string
	credentialTrustRoot string
	signing             keypair
	keyID               string
	proxy               *faultProxy
}

// runtimeUnit is one spawned runtime process behind its fault proxy.
type runtimeUnit struct {
	spec    unitSpec
	cmd     *exec.Cmd
	address string
	logPath string
	release releaseRecord
	proxy   *faultProxy
	pid     int
	waited  sync.Once
	exit    chan error
}

func (u *runtimeUnit) stop() {
	if u.cmd != nil && u.cmd.Process != nil {
		_ = u.cmd.Process.Kill()
		_ = u.awaitExit(10 * time.Second)
	}
}

// kill ends the process abruptly — SIGKILL, no drain — the way a crashed or
// evicted runtime disappears.
func (u *runtimeUnit) kill(t *testing.T) {
	t.Helper()
	if err := u.cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := u.awaitExit(10 * time.Second); err != nil {
		t.Fatalf("the killed unit did not exit: %v", err)
	}
}

// drain asks the unit to stop the way a rollout does — SIGTERM — and reports
// how long it took to exit. A unit past its released drain window is a failure.
func (u *runtimeUnit) drain(t *testing.T) time.Duration {
	t.Helper()
	started := u.beginDrain(t)
	return u.awaitDrained(t, started)
}

// beginDrain sends the unit the rollout's stop signal and returns when it was
// sent.
func (u *runtimeUnit) beginDrain(t *testing.T) time.Time {
	t.Helper()
	started := time.Now()
	if err := u.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	return started
}

// awaitDrained waits for a draining unit to exit inside its released window.
func (u *runtimeUnit) awaitDrained(t *testing.T, started time.Time) time.Duration {
	t.Helper()
	if err := u.awaitExit(time.Duration(u.release.drainSeconds+10) * time.Second); err != nil {
		t.Fatalf("the draining unit did not exit inside its drain window: %v", err)
	}
	elapsed := time.Since(started)
	if elapsed > time.Duration(u.release.drainSeconds)*time.Second {
		t.Fatalf("the unit drained in %s, past its released %ds window", elapsed, u.release.drainSeconds)
	}
	return elapsed
}

func (u *runtimeUnit) awaitExit(timeout time.Duration) error {
	u.waited.Do(func() {
		u.exit = make(chan error, 1)
		go func() { u.exit <- u.cmd.Wait() }()
	})
	select {
	case <-u.exit:
		u.exit <- nil
		return nil
	case <-time.After(timeout):
		return fmt.Errorf("timeout after %s", timeout)
	}
}

// ready probes the unit's readiness path.
func (u *runtimeUnit) ready() (int, bool) {
	client := &http.Client{Timeout: time.Second}
	response, err := client.Get(u.address + "/readyz")
	if err != nil {
		return 0, false
	}
	_ = response.Body.Close()
	return response.StatusCode, true
}

// respawn starts the same released unit again as a fresh process behind the
// same proxy, the way a scheduler replaces a crashed pod.
func (u *runtimeUnit) respawn(t *testing.T) *runtimeUnit {
	t.Helper()
	return spawnUnit(t, u.spec)
}

// spawnUnit starts one runtime unit process and waits for it to become ready.
func spawnUnit(t *testing.T, spec unitSpec) *runtimeUnit {
	t.Helper()
	listen, address := freeListenAddress(t)
	cmd := exec.Command(spec.binary)
	cmd.Env = append(os.Environ(),
		"ANVILKIT_RUNTIME_MANIFEST="+mustAbs(t, spec.release.path),
		"ANVILKIT_CONTROL_PLANE="+spec.controlPlane,
		"ANVILKIT_RESULT_SIGNING_KEY="+spec.signing.seed,
		"ANVILKIT_RESULT_SIGNING_KEY_ID="+spec.keyID,
		"ANVILKIT_TASK_CREDENTIAL_TRUST_ROOT="+spec.credentialTrustRoot,
		"ANVILKIT_LISTEN="+listen,
	)
	logPath := filepath.Join(t.TempDir(), filepath.Base(spec.binary)+".log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	unit := &runtimeUnit{spec: spec, cmd: cmd, address: address, logPath: logPath, release: spec.release, proxy: spec.proxy, pid: cmd.Process.Pid}
	t.Cleanup(func() {
		unit.stop()
		dumpLogOnFailure(t, spec.release.unitID+" pid "+strconv.Itoa(unit.pid), logPath)
	})
	target := address
	spec.proxy.target.Store(&target)

	deadline := time.Now().Add(25 * time.Second)
	for time.Now().Before(deadline) {
		if status, reachable := unit.ready(); reachable && status == http.StatusOK {
			return unit
		}
		time.Sleep(150 * time.Millisecond)
	}
	logs, _ := os.ReadFile(logPath)
	unit.stop()
	t.Fatalf("runtime unit %s did not become ready:\n%s", spec.release.unitID, logs)
	return nil
}

// freeListenAddress reserves a free port and returns the listen spec and the
// dialable address for it.
func freeListenAddress(t *testing.T) (listen, address string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("127.0.0.1:%d", port), fmt.Sprintf("http://127.0.0.1:%d", port)
}

func mustAbs(t *testing.T, path string) string {
	t.Helper()
	absolute, err := filepath.Abs(path)
	if err != nil {
		t.Fatal(err)
	}
	return absolute
}

// serviceProcess is the production agent-service binary running as its own
// process over the topology's environment.
type serviceProcess struct {
	cmd     *exec.Cmd
	url     string
	logPath string
	pid     int
	waited  sync.Once
	exit    chan error
}

// spawnService starts the production binary and waits for its readiness
// probe — the same probe a scheduler would route on — to answer.
func spawnService(t *testing.T, binary string, environment map[string]string) *serviceProcess {
	t.Helper()
	listen, address := freeListenAddress(t)
	cmd := exec.Command(binary)
	// The child sees only the topology's configuration: nothing this test
	// process may have set for an in-process composition leaks into it.
	env := make([]string, 0, len(os.Environ())+len(environment)+1)
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "ANVILKIT_") {
			env = append(env, entry)
		}
	}
	for name, value := range environment {
		env = append(env, name+"="+value)
	}
	cmd.Env = append(env, "ANVILKIT_HTTP_ADDRESS="+listen)
	logPath := filepath.Join(t.TempDir(), "agent-service.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	process := &serviceProcess{cmd: cmd, url: address, logPath: logPath, pid: cmd.Process.Pid}
	t.Cleanup(func() {
		process.stop()
		dumpLogOnFailure(t, "agent-service pid "+strconv.Itoa(process.pid), logPath)
	})
	client := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		response, probeErr := client.Get(address + "/readyz")
		if probeErr == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return process
			}
		}
		if process.exited() {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	logs, _ := os.ReadFile(logPath)
	process.stop()
	t.Fatalf("the agent-service process did not become ready:\n%s", logs)
	return nil
}

// dumpLogOnFailure carries a child process's log into the test output when
// the test failed, so a process that misbehaved explains itself.
func dumpLogOnFailure(t *testing.T, name, logPath string) {
	t.Helper()
	if !t.Failed() {
		return
	}
	logs, err := os.ReadFile(logPath)
	if err != nil {
		return
	}
	if len(logs) > 16384 {
		logs = logs[len(logs)-16384:]
	}
	t.Logf("%s log:\n%s", name, logs)
}

func (s *serviceProcess) exited() bool {
	s.waited.Do(func() {
		s.exit = make(chan error, 1)
		go func() { s.exit <- s.cmd.Wait() }()
	})
	select {
	case <-s.exit:
		s.exit <- nil
		return true
	default:
		return false
	}
}

func (s *serviceProcess) awaitExit(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if s.exited() {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("the process did not exit within %s", timeout)
}

func (s *serviceProcess) stop() {
	if s.cmd != nil && s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
		_ = s.awaitExit(10 * time.Second)
	}
}

// crash ends the service abruptly — SIGKILL, no ordered shutdown, no
// checkpoint — the way a node loss or an OOM kill does.
func (s *serviceProcess) crash(t *testing.T) {
	t.Helper()
	if err := s.cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := s.awaitExit(10 * time.Second); err != nil {
		t.Fatalf("the crashed service did not exit: %v", err)
	}
}

// retire stops the service the way a rollout does: SIGTERM and the ordered
// shutdown it triggers.
func (s *serviceProcess) retire(t *testing.T) {
	t.Helper()
	if err := s.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := s.awaitExit(45 * time.Second); err != nil {
		t.Fatalf("the retiring service did not shut down: %v", err)
	}
}

// controlPlane is one Agent Service instance a scenario drives: its public
// address, the definition its run authority admits, the environment it was
// composed from, and — when it is the production binary — the process itself.
type controlPlane struct {
	url              string
	executorID       string
	definitionID     string
	definitionDigest string
	environment      map[string]string
	process          *serviceProcess
	server           *httptest.Server
}

// topology is one composed cross-process environment.
type topology struct {
	t          *testing.T
	ctx        context.Context
	service    *controlPlane
	observe    *pgxpool.Pool
	gate       *controlPlaneGate
	manager    *runtimeUnit
	specialist *runtimeUnit
	bearers    bearers
	client     *http.Client
	trace      string
	// credentialIssuer mints task-scoped credentials the way the service does,
	// so a scenario can present adversarial credentials to the live unit /task
	// endpoint, or act as a dispatched attempt at the served boundary.
	credentialIssuer    *runtimes.TaskCredentials
	credentialKey       keypair
	credentialKeyID     string
	credentialTrustRoot string
	databaseURL         string
	trustDir            string
	now                 time.Time
	managerRelease      releaseRecord
	specialistRelease   releaseRecord
	managerSigning      keypair
	specialistSigning   keypair
	signingKeys         []signingTrustKey
	signingTrust        string
	// instances counts the service instances composed, so each gets its own
	// executor identity and, with it, its own durable script ledger.
	instances int
}

const (
	managerSigningKeyID    = "urn:anvilkit:key:cross-process-manager-result"
	specialistSigningKeyID = "urn:anvilkit:key:cross-process-specialist-result"
	credentialKeyID        = "urn:anvilkit:key:cross-process-task-credentials"
)

// topologyOptions selects how one scenario's environment is composed.
type topologyOptions struct {
	script string
	// maxModelCalls, when non-zero, pins a run budget that funds exactly that
	// many governed model calls.
	maxModelCalls int
	// serviceProcess runs the Agent Service as the production binary in its
	// own process rather than composing it inside the test process.
	serviceProcess bool
	// dispatchTimeout, when set, is the dispatch deadline — and with it the
	// attempt lease — the service is composed with; the default is 8s. A
	// scenario that must present an old attempt while its window is still
	// open lengthens it so the proof does not race the clock.
	dispatchTimeout time.Duration
}

// newTopology composes the full cross-process environment for one scenario
// with the default run budget.
func newTopology(t *testing.T, script string) *topology {
	return composeTopology(t, topologyOptions{script: script})
}

// newTopologyWithBudget composes the environment with a run budget that funds
// exactly maxModelCalls governed model calls, so a scenario can drive the run
// into budget exhaustion.
func newTopologyWithBudget(t *testing.T, script string, maxModelCalls int) *topology {
	return composeTopology(t, topologyOptions{script: script, maxModelCalls: maxModelCalls})
}

// newTopologyWithServiceProcess composes the environment with the Agent
// Service running as the production binary in its own process.
func newTopologyWithServiceProcess(t *testing.T, script string) *topology {
	return composeTopology(t, topologyOptions{script: script, serviceProcess: true})
}

// newTopologyWithLease composes the environment with a longer dispatch
// deadline and attempt lease, for scenarios that present an old attempt while
// its window must still be open.
func newTopologyWithLease(t *testing.T, script string, lease time.Duration) *topology {
	return composeTopology(t, topologyOptions{script: script, dispatchTimeout: lease})
}

func requirePostgres(t *testing.T) string {
	t.Helper()
	base := os.Getenv("POSTGRES_TEST_URL")
	if base == "" {
		if os.Getenv("ANVILKIT_REQUIRE_POSTGRES_PROOFS") != "" {
			t.Fatal("POSTGRES_TEST_URL is not set but ANVILKIT_REQUIRE_POSTGRES_PROOFS requires these proofs")
		}
		t.Skip("POSTGRES_TEST_URL is not set")
	}
	return base
}

// composeTopology composes the full cross-process environment for one scenario.
func composeTopology(t *testing.T, options topologyOptions) *topology {
	t.Helper()
	base := requirePostgres(t)
	managerBinary, specialistBinary := runtimeUnitBinaries(t)

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	t.Cleanup(cancel)

	databaseURL := isolatedSliceDatabase(t, ctx, base)
	migration, err := pgx.Connect(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	if err := persistence.NewMigrator(migration).Apply(ctx); err != nil {
		t.Fatal(err)
	}
	if err := migration.Close(ctx); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	trustDir := t.TempDir()
	managerRelease := loadReleaseRecord(t, "runtime.platform.page-change-manager", "release.platform.page-change-manager.json")
	specialistRelease := loadReleaseRecord(t, "runtime.platform.page-candidate-specialist", "release.platform.page-candidate-specialist.json")

	credentialKey := newKeypair(t)
	credentialTrustRoot := writeCredentialTrustRoot(t, trustDir, credentialKey, credentialKeyID,
		[]string{managerRelease.audience, specialistRelease.audience}, now)
	credentialIssuer, err := runtimes.NewTaskCredentials(credentialKey.seed, credentialKeyID, 5*time.Minute, func() time.Time { return time.Now().UTC() })
	if err != nil {
		t.Fatal(err)
	}

	managerSigning := newKeypair(t)
	specialistSigning := newKeypair(t)
	signingKeys := []signingTrustKey{
		signingTrustFor(managerSigningKeyID, managerRelease, managerSigning),
		signingTrustFor(specialistSigningKeyID, specialistRelease, specialistSigning),
	}
	signingTrust := writeSigningTrust(t, trustDir, "runtime-signing-trust.json", signingKeys, now)

	// The fault proxies have stable addresses known before the service is
	// composed; the dispatcher reaches the units through them. The gate has a
	// stable address known before the units spawn; they reach the service
	// through it.
	managerProxy := newFaultProxy(t)
	specialistProxy := newFaultProxy(t)
	gate := newControlPlaneGate(t)

	top := &topology{
		t: t, ctx: ctx, gate: gate,
		client:              &http.Client{Timeout: 30 * time.Second},
		trace:               "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01",
		credentialIssuer:    credentialIssuer,
		credentialKey:       credentialKey,
		credentialKeyID:     credentialKeyID,
		credentialTrustRoot: credentialTrustRoot,
		databaseURL:         databaseURL,
		trustDir:            trustDir,
		now:                 now,
		managerRelease:      managerRelease,
		specialistRelease:   specialistRelease,
		managerSigning:      managerSigning,
		specialistSigning:   specialistSigning,
		signingKeys:         signingKeys,
		signingTrust:        signingTrust,
	}
	top.bearers = mintBearers(t)

	managerID, managerDigest := pageChangeManagerReference(t)
	endpoints := managerRelease.unitID + "=" + managerProxy.server.URL + "," + specialistRelease.unitID + "=" + specialistProxy.server.URL
	top.service = top.composeService(serviceOptions{
		script:           options.script,
		maxModelCalls:    options.maxModelCalls,
		process:          options.serviceProcess,
		dispatchTimeout:  options.dispatchTimeout,
		definitionID:     managerID,
		definitionDigest: managerDigest,
		endpoints:        endpoints,
		signingTrust:     signingTrust,
	})
	gate.retarget(top.service.url)

	observe, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(observe.Close)
	top.observe = observe

	top.manager = spawnUnit(t, unitSpec{binary: managerBinary, release: managerRelease, controlPlane: gate.server.URL, credentialTrustRoot: credentialTrustRoot, signing: managerSigning, keyID: managerSigningKeyID, proxy: managerProxy})
	top.specialist = spawnUnit(t, unitSpec{binary: specialistBinary, release: specialistRelease, controlPlane: gate.server.URL, credentialTrustRoot: credentialTrustRoot, signing: specialistSigning, keyID: specialistSigningKeyID, proxy: specialistProxy})
	return top
}

// serviceOptions is what one Agent Service instance is composed from.
type serviceOptions struct {
	script           string
	maxModelCalls    int
	process          bool
	dispatchTimeout  time.Duration
	binary           string
	definitionID     string
	definitionDigest string
	endpoints        string
	signingTrust     string
	// authorityGeneration is the generation of the run authority this
	// instance seeds for the scope. A definition generation that differs from
	// the one in force needs a newer authority generation to pin it: the same
	// generation is refused as superseded, and the standing authority stays.
	authorityGeneration int
	// releaseTrustRoot and the attestations, when set, are the operator
	// material that attests the release and definition catalogs the instance
	// was built with.
	releaseTrustRoot       string
	releaseAttestation     string
	definitionAttestation  string
	definitionCatalogTrust string
}

// composeService composes one Agent Service instance over the topology's
// database, trust material, and units — in this process, or as the
// production binary in its own process.
func (top *topology) composeService(options serviceOptions) *controlPlane {
	t := top.t
	t.Helper()
	top.instances++
	executorID := "cross-process-executor-" + strconv.Itoa(top.instances)
	authorityPath := writeRunAuthorityFor(t, options.definitionID, options.definitionDigest, options.maxModelCalls, options.authorityGeneration)
	dispatchTimeout := options.dispatchTimeout
	if dispatchTimeout <= 0 {
		dispatchTimeout = 8 * time.Second
	}
	environment := map[string]string{
		"ANVILKIT_ENVIRONMENT":                     "development",
		"ANVILKIT_CONTRACT_ROOT":                   "../..",
		"ANVILKIT_CONTROL_DATABASE_URL":            top.databaseURL,
		"ANVILKIT_WORKFLOW_DATABASE_URL":           top.databaseURL,
		"ANVILKIT_EVENTS_DATABASE_URL":             top.databaseURL,
		"ANVILKIT_ARTIFACTS_DATABASE_URL":          top.databaseURL,
		"ANVILKIT_EVALUATION_DATABASE_URL":         top.databaseURL,
		"ANVILKIT_MODEL_IMPLEMENTATION":            "controlled-fake",
		"ANVILKIT_TOOL_IMPLEMENTATION":             "controlled-fake",
		"ANVILKIT_DOMAIN_IMPLEMENTATION":           "controlled-fake",
		"ANVILKIT_CONTRACT_RUNTIME_IMPLEMENTATION": "controlled-fake",
		"ANVILKIT_WORKER_IMPLEMENTATION":           "controlled-fake",
		"ANVILKIT_RUNTIME_DISPATCHER":              "http",
		"ANVILKIT_RUNTIME_ENDPOINTS":               options.endpoints,
		"ANVILKIT_RUNTIME_CREDENTIAL_KEY":          top.credentialKey.seed,
		"ANVILKIT_RUNTIME_CREDENTIAL_KEY_ID":       top.credentialKeyID,
		"ANVILKIT_RUNTIME_CREDENTIAL_TRUST_ROOT":   top.credentialTrustRoot,
		"ANVILKIT_RUNTIME_SIGNING_TRUST":           options.signingTrust,
		"ANVILKIT_RUNTIME_DISPATCH_TIMEOUT":        dispatchTimeout.String(),
		"ANVILKIT_CONTROLLED_MODEL_SCRIPT":         options.script,
		"ANVILKIT_SIGNING_KEY":                     "cross-process-signing-material-0123",
		"ANVILKIT_ENCRYPTION_KEY":                  "cross-process-encryption-material-0123",
		"ANVILKIT_RUN_AUTHORITY_FILE":              authorityPath,
		"ANVILKIT_AUTH_TRUST_SNAPSHOT":             top.bearers.trustPath,
		"ANVILKIT_STREAM_CURSOR_SPOOL":             filepath.Join(t.TempDir(), "stream-cursors"),
		"ANVILKIT_AUTH_ISSUERS":                    "issuer",
		"ANVILKIT_EXECUTOR_ID":                     executorID,
	}
	if options.releaseTrustRoot != "" {
		environment["ANVILKIT_RUNTIME_TRUST_ROOT"] = options.releaseTrustRoot
		environment["ANVILKIT_RUNTIME_ATTESTATION"] = options.releaseAttestation
		environment["ANVILKIT_DEFINITION_TRUST_ROOT"] = options.definitionCatalogTrust
		environment["ANVILKIT_DEFINITION_ATTESTATION"] = options.definitionAttestation
	}
	plane := &controlPlane{executorID: executorID, definitionID: options.definitionID, definitionDigest: options.definitionDigest, environment: environment}
	if options.process {
		binary := options.binary
		if binary == "" {
			binary, _ = serviceBinary(t)
		}
		plane.process = spawnService(t, binary, environment)
		plane.url = plane.process.url
		return plane
	}
	handler := composeInProcess(t, top.ctx, environment)
	plane.server = httptest.NewServer(handler)
	t.Cleanup(plane.server.Close)
	plane.url = plane.server.URL
	return plane
}

// on returns a view of the topology driving a different service instance over
// the same database, units, and trust.
func (top *topology) on(plane *controlPlane) *topology {
	view := *top
	view.service = plane
	return &view
}

// restartService crashes the service process and starts a successor with the
// crashed executor's identity over the same durable state — the recovery a
// scheduler performs — then points the units at the successor.
func (top *topology) restartService() *serviceProcess {
	t := top.t
	t.Helper()
	if top.service.process == nil {
		t.Fatal("the service is composed in-process; a restart needs the production binary in its own process")
	}
	top.service.process.crash(t)
	binary, _ := serviceBinary(t)
	successor := spawnService(t, binary, top.service.environment)
	top.service.process = successor
	top.service.url = successor.url
	top.gate.retarget(successor.url)
	return successor
}

// composeInProcess builds the production API handler over the given
// environment inside this process.
func composeInProcess(t *testing.T, ctx context.Context, environment map[string]string) http.Handler {
	t.Helper()
	for name, value := range environment {
		t.Setenv(name, value)
	}
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	pools, err := openPersistencePools(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pools.Close)
	guard, err := contractguard.NewGuard(cfg.ContractRoot)
	if err != nil {
		t.Fatal(err)
	}
	clock, auditClock, err := applicationClock(cfg)
	if err != nil {
		t.Fatal(err)
	}
	receipts := journal.NewMemoryStore()
	protectedAudit, closeAudit, err := buildProtectedAudit(ctx, cfg, auditClock, receipts, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(closeAudit)
	handle := &runtimeHandle{}
	// The cross-process composition dispatches over HTTP and supplies no
	// stand-in: like the production binary, it has none to compose.
	core, err := buildRuntimeCore(ctx, cfg, pools, guard, receipts, clock, protectedAudit, handle, executionStandIns{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := workflowdbos.New(ctx, workflowdbos.Config{DatabaseURL: cfg.WorkflowDatabase, Schema: "agent_dbos", ExecutorID: cfg.ExecutorID, ApplicationVersion: "cross-process-test", Logger: slog.Default()}, core.executor)
	if err != nil {
		t.Fatal(err)
	}
	handle.set(runtime)
	if err := runtime.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := runtime.Stop(context.Background()); err != nil {
			t.Errorf("stop workflow runtime: %v", err)
		}
	})
	redactor := telemetry.NewRedactor([]string{cfg.SigningKey.RedactionValue(), cfg.EncryptionKey.RedactionValue()})
	observability, err := telemetry.New(cfg.ServiceName, nil, redactor)
	if err != nil {
		t.Fatal(err)
	}
	options, err := agentAPIOptions(ctx, cfg, pools, runtime, core, observability)
	if err != nil {
		t.Fatal(err)
	}
	return api.New(readyAlways{}, options...)
}

// writeRunAuthorityFor writes a run authority for one definition. A positive
// maxModelCalls narrows the pinned budget to fund exactly that many model
// calls; a generation above one seeds a newer authority generation than the
// vertical slice's default.
func writeRunAuthorityFor(t *testing.T, definitionID, definitionDigest string, maxModelCalls, generation int) string {
	t.Helper()
	base := writeRunAuthority(t, definitionID, definitionDigest)
	if maxModelCalls <= 0 && generation <= 1 {
		return base
	}
	raw, err := os.ReadFile(base)
	if err != nil {
		t.Fatal(err)
	}
	// The authority is a bounded JSON document; only the named members are
	// rewritten, so the rest of the pinned budget and policy are unchanged.
	rewritten := string(raw)
	if maxModelCalls > 0 {
		rewritten = strings.Replace(rewritten, `"maximumCalls":10`, `"maximumCalls":`+strconv.Itoa(maxModelCalls), 1)
	}
	if generation > 1 {
		rewritten = strings.Replace(rewritten, `"generation":1`, `"generation":`+strconv.Itoa(generation), 1)
	}
	if rewritten == string(raw) {
		t.Fatal("the run authority did not carry the members to rewrite")
	}
	path := filepath.Join(t.TempDir(), "authority-rewritten.json")
	if err := os.WriteFile(path, []byte(rewritten), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
