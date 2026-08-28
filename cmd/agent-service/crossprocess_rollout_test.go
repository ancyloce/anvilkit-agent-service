package main

import (
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestCrossProcessRolloutAndRollbackChangeSelectionForNewRunsOnly covers the
// rollout and rollback rows of the matrix with real release material and real
// processes. A rollout in this design is a release cut — a new manager image,
// and the manifest, release catalog, definition pins, definition catalog, and
// both attestations that cascade from it — compiled into a new build of the
// Agent Service and deployed beside a unit mounted with the new manifest. A
// rollback is the cut that returns the manager to the previous image.
//
// What the scenario proves:
//
//   - new runs select the rolled-out release: their pin and every task they
//     dispatch carry its manifest and image digests;
//   - a run pinned before the rollout keeps its pin — it is never re-pinned
//     and never executes on the new release;
//   - the old unit drains: a task it admitted completes after the stop signal,
//     a new admission is refused, and the process exits inside its released
//     drain window;
//   - after a rollback, new runs return to the previous image and the
//     rolled-back unit refuses the withdrawn release's tasks by binding.
//
// It also records a finding (recovery matrix R-1). The run authority of a scope pins one
// definition by digest, a release cut necessarily rebinds the definition — the
// definition pins the manifest digest — and every turn and interrupt requires
// the current authority's definition to be byte-identical to the run's own.
// A rollout therefore needs a new authority generation, and a run still in
// flight under the previous generation cannot resume: it is refused as
// AUTHORITY_STALE, fails closed, and keeps the pin it was created with. The
// plan's "old work drains" holds at the unit; within one authority scope it
// does not hold for the run, and the scenario asserts the behaviour as it is.
func TestCrossProcessRolloutAndRollbackChangeSelectionForNewRunsOnly(t *testing.T) {
	const waitingScript = "plan-need-input,delegate-page-specialist,compose-page"
	top := newTopology(t, waitingScript)
	_, releaseTool := serviceBinary(t)
	managerBinary, _ := runtimeUnitBinaries(t)
	v1 := top.managerRelease
	top.gate.routeRelease(v1.documentDigest, top.service.url)

	// A run on the current release, durably waiting for input — in flight
	// across the whole rollout.
	runA := top.createRun("cross-rollout-a", "make the hero bolder")
	top.gate.route(runIDOf(runA), top.service.url)
	etagA := top.waitForStatus(runA, "awaiting_input")
	pinA := top.runtimeBinding(runA)
	if pinA.RuntimeManifestDigest != v1.documentDigest || pinA.RuntimeImageDigest != v1.imageDigest {
		t.Fatalf("run A pins %+v, want the current release %s", pinA, v1.documentDigest)
	}

	// Rollout: a new manager image is cut. Every approved document that pins
	// the manager release cascades — manifest, release catalog, definitions,
	// definition catalog — and both catalogs are re-attested. The rebound
	// definition needs a new authority generation to pin it.
	v2Cut := cutRelease(t, releaseTool, embeddedReleases, embeddedDefinitions, "",
		"-image", v1.unitID+"="+sha256Digest([]byte("page-change-manager image v2")), "-source-commit", strings.Repeat("2", 40))
	v2 := loadReleaseRecordPath(t, v1.unitID, filepath.Join(v2Cut.releases, "release.platform.page-change-manager.json"))
	if v2.documentDigest == v1.documentDigest || v2.imageDigest == v1.imageDigest {
		t.Fatalf("the cut did not produce a new release: %+v", v2)
	}
	unitV2, planeV2 := top.deployRelease("v2", v2Cut, v2, managerBinary, waitingScript, 2)
	onV2 := top.on(planeV2)

	// New runs select the new release: their pin and every task they dispatch
	// carry the new manifest and image digests.
	runB := onV2.createRun("cross-rollout-b", "make the hero bolder")
	top.gate.route(runIDOf(runB), planeV2.url)
	etagB := onV2.waitForStatus(runB, "awaiting_input")
	pinB := onV2.runtimeBinding(runB)
	if pinB.RuntimeManifestDigest != v2.documentDigest || pinB.RuntimeImageDigest != v2.imageDigest {
		t.Fatalf("run B pins %+v, want the rolled-out release %s", pinB, v2.documentDigest)
	}
	top.assertTasksPinned(runIDOf(runB), v1.unitID, v2.documentDigest, v2.imageDigest)

	// The run pinned before the rollout keeps its pin and cannot be moved to
	// the new release: the authority that now governs the scope pins the
	// rebound definition, and resuming the run is refused as stale (R-1).
	top.assertRunParkedAcrossGeneration(runA, etagA, pinA, v1)

	// The old unit drains: an admitted task completes after the stop signal,
	// a new admission is refused, and the process exits inside its window.
	top.assertUnitDrains(top.manager, v1, "rollout-drain")

	// Rollback: the new manifest is withdrawn by a cut that returns the
	// manager to the previous image — the release the withdrawn manifest
	// named as its rollback target — under the next authority generation.
	v3Cut := cutRelease(t, releaseTool, v2Cut.releases, v2Cut.definitions, v2Cut.seed,
		"-image", v1.unitID+"="+v1.imageDigest, "-source-commit", strings.Repeat("1", 40))
	v3 := loadReleaseRecordPath(t, v1.unitID, filepath.Join(v3Cut.releases, "release.platform.page-change-manager.json"))
	if v3.imageDigest != v1.imageDigest || v3.documentDigest == v2.documentDigest {
		t.Fatalf("the rollback cut did not return to the previous image: %+v", v3)
	}
	unitV3, planeV3 := top.deployRelease("v3", v3Cut, v3, managerBinary, "delegate-page-specialist,compose-page", 3)
	onV3 := top.on(planeV3)

	// New runs return to the allowed release and complete on it, signed by
	// its unit's key.
	runC := onV3.createRun("cross-rollback-c", "make the hero bolder")
	top.gate.route(runIDOf(runC), planeV3.url)
	pinC := onV3.runtimeBinding(runC)
	if pinC.RuntimeManifestDigest != v3.documentDigest || pinC.RuntimeImageDigest != v1.imageDigest {
		t.Fatalf("run C pins %+v, want the rolled-back release %s on image %s", pinC, v3.documentDigest, v1.imageDigest)
	}
	etagC := onV3.waitForStatus(runC, "awaiting_approval")
	onV3.approve(runC, etagC)
	onV3.waitForStatus(runC, "completed")
	top.assertTasksPinned(runIDOf(runC), v1.unitID, v3.documentDigest, v1.imageDigest)
	top.assertManagerResultsSignedBy(runIDOf(runC), "urn:anvilkit:key:cross-process-manager-result-v3")
	onV3.assertScenario(completed(runC, 0))

	// The run pinned to the withdrawn release keeps its pin across the
	// rollback exactly as A did across the rollout.
	onV2.assertRunParkedAcrossGeneration(runB, etagB, pinB, v2)

	// The withdrawn release's work cannot be served by the rolled-back unit:
	// a task pinned to the withdrawn manifest, presented to the v3 unit with
	// a valid credential and an open window, is refused by binding before any
	// reasoning — the unit it was pinned to is the only unit that admits it.
	withdrawn := managerTask(v2, time.Now().UTC().Add(2*time.Minute), "withdrawn-release")
	if status, _, _ := top.dispatchToUnit(unitV3, withdrawn, top.credentialFor(withdrawn)); status != http.StatusForbidden {
		t.Fatalf("the rolled-back unit answered a task pinned to the withdrawn release with %d, want 403", status)
	}
	if status, _, _ := top.dispatchToUnit(unitV2, withdrawn, top.credentialFor(withdrawn)); status == http.StatusForbidden {
		t.Fatal("the withdrawn release's own unit refused a task pinned to it")
	}

	// The replaced instances retire in order: the services by their ordered
	// shutdown, the units by their released drain.
	planeV2.process.retire(t)
	unitV2.drain(t)
	planeV3.process.retire(t)
	unitV3.drain(t)
}

// assertRunParkedAcrossGeneration proves a run created under a previous
// authority generation keeps its pin and cannot resume under the current one:
// answering its open input is refused as stale authority, it stays parked, it
// committed nothing further, and no result of it was ever signed by a unit of
// another release.
func (top *topology) assertRunParkedAcrossGeneration(runPath, etag string, pin runtimeBindingView, release releaseRecord) {
	t := top.t
	t.Helper()
	response, payload := top.tryAnswerInput(runPath, etag, "the hero section")
	if response.StatusCode == http.StatusOK || !strings.Contains(string(payload), "AUTHORITY_STALE") {
		t.Fatalf("resuming a run of the previous authority generation answered %d: %s; want a stale-authority refusal", response.StatusCode, payload)
	}
	if after := top.runtimeBinding(runPath); after != pin {
		t.Fatalf("the parked run's pin changed: %+v then %+v", pin, after)
	}
	runID := runIDOf(runPath)
	top.assertTasksPinned(runID, release.unitID, release.documentDigest, release.imageDigest)
	if foreign := top.countWith(`SELECT count(*) `+resultsOf+` AND t.runtime_manifest_digest<>$2`, runID, release.documentDigest); foreign != 0 {
		t.Fatalf("%d results of the parked run belong to another release", foreign)
	}
	top.assertScenario(scenario{
		run: runPath, final: "awaiting_input", artifacts: 0,
		events:   []string{"run.created", "run.state-changed", "run.input-requested"},
		evidence: 0, usage: 1,
		fence: fence{tasks: 1, succeeded: 1},
	})
}

// releaseCut is the material one runtime-release cut produced.
type releaseCut struct {
	releases, definitions                                string
	trustRoot, releaseAttestation, definitionAttestation string
	seed                                                 string
}

// cutRelease runs the runtime-release tool the way the release pipeline does:
// from an approved source store into a complete, self-verified cut store with
// its attestations. An empty seed path cuts with an ephemeral key whose seed
// the cut publishes for the next cut to reuse.
func cutRelease(t *testing.T, tool, sourceReleases, sourceDefinitions, seedPath string, arguments ...string) releaseCut {
	t.Helper()
	out := t.TempDir()
	args := []string{"cut", "-contract-root", "../..", "-releases", sourceReleases, "-definitions", sourceDefinitions, "-out", out}
	if seedPath == "" {
		args = append(args, "-ephemeral")
	} else {
		args = append(args, "-signing-seed", seedPath)
	}
	args = append(args, arguments...)
	cmd := exec.Command(tool, args...)
	if combined, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("runtime-release %s: %v\n%s", strings.Join(args, " "), err, combined)
	}
	cut := releaseCut{
		releases:              filepath.Join(out, "releases"),
		definitions:           filepath.Join(out, "definitions"),
		trustRoot:             filepath.Join(out, "attestations", "release-trust-root.json"),
		releaseAttestation:    filepath.Join(out, "attestations", "runtime-release-catalog.attestation.json"),
		definitionAttestation: filepath.Join(out, "attestations", "agent-definition-catalog.attestation.json"),
		seed:                  seedPath,
	}
	if seedPath == "" {
		cut.seed = filepath.Join(out, "keys", "release-signing.seed")
	}
	for _, required := range []string{cut.trustRoot, cut.releaseAttestation, cut.definitionAttestation, cut.seed} {
		if _, err := os.Stat(required); err != nil {
			t.Fatalf("the cut did not produce %s: %v", required, err)
		}
	}
	return cut
}

// overlayFor maps every embedded approved document to the cut's copy, so a
// service built with it carries the cut as its approved material.
func overlayFor(t *testing.T, cut releaseCut) map[string]string {
	t.Helper()
	replace := map[string]string{}
	for source, target := range map[string]string{embeddedReleases: cut.releases, embeddedDefinitions: cut.definitions} {
		entries, err := os.ReadDir(source)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			replacement := filepath.Join(target, entry.Name())
			if _, err := os.Stat(replacement); err != nil {
				t.Fatalf("the cut store lacks %s: %v", entry.Name(), err)
			}
			replace[filepath.Join(source, entry.Name())] = replacement
		}
	}
	return replace
}

// deployRelease deploys one cut: a service built with the cut as its approved
// material, attested by the cut's trust root, seeding the given authority
// generation for the rebound definition; and a manager unit mounted with the
// cut's manifest and its own signing key, which the service trusts.
func (top *topology) deployRelease(name string, cut releaseCut, release releaseRecord, managerBinary, script string, authorityGeneration int) (*runtimeUnit, *controlPlane) {
	t := top.t
	t.Helper()
	signing := newKeypair(t)
	keyID := "urn:anvilkit:key:cross-process-manager-result-" + name
	top.signingKeys = append(top.signingKeys, signingTrustFor(keyID, release, signing))
	trust := writeSigningTrust(t, top.trustDir, "runtime-signing-trust-"+name+".json", top.signingKeys, top.now)
	proxy := newFaultProxy(t)
	binary := overlayServiceBinary(t, overlayFor(t, cut))
	definitionID, definitionDigest := definitionReference(t, filepath.Join(cut.definitions, "definition.platform.page-change-manager.json"))
	plane := top.composeService(serviceOptions{
		script:                 script,
		process:                true,
		binary:                 binary,
		definitionID:           definitionID,
		definitionDigest:       definitionDigest,
		endpoints:              release.unitID + "=" + proxy.server.URL + "," + top.specialistRelease.unitID + "=" + top.specialist.proxy.server.URL,
		signingTrust:           trust,
		authorityGeneration:    authorityGeneration,
		releaseTrustRoot:       cut.trustRoot,
		releaseAttestation:     cut.releaseAttestation,
		definitionAttestation:  cut.definitionAttestation,
		definitionCatalogTrust: cut.trustRoot,
	})
	top.gate.routeRelease(release.documentDigest, plane.url)
	unit := spawnUnit(t, unitSpec{binary: managerBinary, release: release, controlPlane: top.gate.server.URL, credentialTrustRoot: top.credentialTrustRoot, signing: signing, keyID: keyID, proxy: proxy})
	return unit, plane
}

// assertTasksPinned proves every task a run dispatched to one unit carries
// the given release digests.
func (top *topology) assertTasksPinned(runID, unitID, manifestDigest, imageDigest string) {
	top.t.Helper()
	tasks := top.countWith(`SELECT count(*) FROM agent_workflow.runtime_tasks WHERE run_id=$1 AND runtime_unit_id=$2`, runID, unitID)
	pinned := top.countWith(`SELECT count(*) FROM agent_workflow.runtime_tasks WHERE run_id=$1 AND runtime_unit_id=$2 AND runtime_manifest_digest=$3 AND runtime_image_digest=$4`, runID, unitID, manifestDigest, imageDigest)
	if tasks == 0 || pinned != tasks {
		top.t.Fatalf("%d of %d tasks for %s carry release %s / %s", pinned, tasks, unitID, manifestDigest, imageDigest)
	}
}

// assertManagerResultsSignedBy proves every committed manager result of a run
// was signed by the given key and no other.
func (top *topology) assertManagerResultsSignedBy(runID, keyID string) {
	top.t.Helper()
	signed := top.countWith(`SELECT count(*) `+resultsOf+` AND t.runtime_unit_id=$2 AND r.signature_key_id=$3`, runID, top.managerRelease.unitID, keyID)
	others := top.countWith(`SELECT count(*) `+resultsOf+` AND t.runtime_unit_id=$2 AND r.signature_key_id<>$3`, runID, top.managerRelease.unitID, keyID)
	if signed < 2 || others != 0 {
		top.t.Fatalf("manager results signed by %s = %d, by other keys = %d; want every manager result signed by that unit's key", keyID, signed, others)
	}
}

// assertUnitDrains proves the released drain contract on a live unit: a task
// admitted before the stop signal completes after it, a task offered after
// the signal is refused, and the process exits inside its drain window.
func (top *topology) assertUnitDrains(unit *runtimeUnit, release releaseRecord, id string) {
	t := top.t
	t.Helper()
	// A task the unit admits and executes until its first callback, which the
	// gate holds — the unit is mid-execution when the stop signal arrives.
	task := managerTask(release, time.Now().UTC().Add(2*time.Minute), id)
	hold := top.gate.hold(false, callbackForRun("", string(task.RunId)))
	credential := top.credentialFor(task)
	answered := make(chan error, 1)
	go func() {
		_, _, _, err := top.tryDispatchToUnit(unit, task, credential)
		answered <- err
	}()
	hold.awaitCaught(t, 30*time.Second)

	started := unit.beginDrain(t)
	// A draining unit admits nothing new: the offer is refused, or the
	// listener is already gone.
	refused := managerTask(release, time.Now().UTC().Add(2*time.Minute), id+"-after-drain")
	if status, _, _, err := top.tryDispatchToUnit(unit, refused, top.credentialFor(refused)); err == nil && status == http.StatusOK {
		t.Fatal("a draining unit admitted a new task")
	}
	// The admitted task runs to its answer: the unit stays up for it.
	hold.Release()
	select {
	case err := <-answered:
		if err != nil {
			t.Fatalf("the task admitted before the drain was not answered: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the task admitted before the drain was never answered")
	}
	unit.awaitDrained(t, started)
}
