package execution_test

import (
	"fmt"

	"github.com/ancyloce/anvilkit-agent-service/internal/runtimes"
)

// harnessReleases stands in for the Runtime Registry's selection: every
// definition's own pinned binding is its approved, active release, except the
// ones a test withdraws, which select as revoked. The harness has no release
// catalog of its own — definitions here are built for the pipeline under test,
// not cut into releases — so what this proves is that the executor asks the
// selector and honours its answer, and the registry's own suite proves what
// the answer is.
type harnessReleases struct{ withdrawn []string }

func (h harnessReleases) Select(request runtimes.Request) (runtimes.Release, error) {
	for _, withdrawn := range h.withdrawn {
		if withdrawn == request.Definition.DefinitionID {
			return runtimes.Release{}, fmt.Errorf("runtime selection: the approved release for %s is revoked", request.Definition.DefinitionID)
		}
	}
	return runtimes.Release{
		RuntimeUnitID:  request.Definition.RuntimeBinding.RuntimeUnitID,
		DefinitionID:   request.Definition.DefinitionID,
		ManifestDigest: request.Definition.RuntimeBinding.RuntimeManifestDigest,
		Capabilities:   []string{runtimes.TurnCapability},
		Lifecycle:      "active",
		Binding:        request.Definition.RuntimeBinding,
	}, nil
}
