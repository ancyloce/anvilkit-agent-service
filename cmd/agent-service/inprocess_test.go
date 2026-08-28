package main

import (
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/runtimes"
	"github.com/ancyloce/anvilkit-agent-service/internal/runtimes/inprocess"
)

// inProcessRuntimeKeyID names the key the in-process stand-in signs results
// with. It is a distinct identity from any released unit's, so evidence never
// attributes a stand-in's result to a release.
const inProcessRuntimeKeyID = "urn:anvilkit:key:in-process-runtime-result"

// controlledStandIns supplies the in-process runtime stand-in to a test
// composition. This is the one place the stand-in is ever built: the file is
// test code, the production binary links none of it, and the module boundary
// check refuses the import anywhere that is not a test.
func controlledStandIns() executionStandIns {
	return executionStandIns{Runtime: func(parts inProcessRuntimeParts) (inProcessRuntime, error) {
		signer, err := inprocess.NewSeededSigner(parts.SigningMaterial, inProcessRuntimeKeyID)
		if err != nil {
			return nil, err
		}
		runtime, err := inprocess.New(inprocess.Config{
			Definitions: parts.Definitions,
			Selector:    parts.Models,
			Invoker:     parts.Models,
			Signer:      signer,
			Credentials: parts.Credentials,
			Now:         parts.Now,
			Repairs:     parts.Repairs,
		})
		if err != nil {
			return nil, err
		}
		return &inProcessStandIn{Runtime: runtime, signer: signer}, nil
	}}
}

// inProcessStandIn is the stand-in together with the trust that attributes its
// own results, synthesized from the same key it signs with.
type inProcessStandIn struct {
	*inprocess.Runtime
	signer *inprocess.SeededSigner
}

func (s *inProcessStandIn) SigningTrust(releases []runtimes.Release, now func() time.Time) (runtimes.SigningTrustSource, error) {
	return runtimes.NewControlledSigningTrust(s.signer.PublicKey(), inProcessRuntimeKeyID, releases, now)
}
