// Package contractclient owns fail-closed Contract Runtime validation.
package contractclient

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/runs"
)

type Health interface{ Check(context.Context) error }
type Kind string

const (
	Plan     Kind = "plan"
	Artifact Kind = "artifact"
)

type Request struct {
	WorkspaceID, ProjectID, RunID                        string
	Kind                                                 Kind
	Payload                                              []byte
	BOMDigest, SchemaDigest, CatalogDigest, PolicyDigest string
}
type Result struct {
	Valid            bool
	Findings         []problem.FieldError
	ValidatorVersion string
}
type Runtime interface {
	CompileValidate(context.Context, Request) (Result, error)
}
type Evidence struct {
	WorkspaceID, ProjectID, RunID                                          string
	Kind                                                                   Kind
	BOMDigest, SchemaDigest, ValidatorVersion, CatalogDigest, PolicyDigest string
	Valid                                                                  bool
	Findings                                                               []problem.FieldError
	ValidatedAt                                                            time.Time
}
type Recorder interface {
	Record(context.Context, Evidence) error
}
type Sleeper interface {
	Sleep(context.Context, time.Duration) error
}
type Clock interface{ Now() time.Time }
type Orchestrator struct {
	runtime  Runtime
	recorder Recorder
	sleeper  Sleeper
	clock    Clock
	attempts int
	backoff  time.Duration
}

func New(runtime Runtime, recorder Recorder, sleeper Sleeper, clock Clock, attempts int, backoff time.Duration) (*Orchestrator, error) {
	if runtime == nil || recorder == nil || sleeper == nil || clock == nil || attempts < 1 || attempts > 5 || backoff < 0 || backoff > 30*time.Second {
		return nil, fmt.Errorf("contract validation dependencies or bounds are invalid")
	}
	return &Orchestrator{runtime, recorder, sleeper, clock, attempts, backoff}, nil
}
func (o *Orchestrator) Validate(ctx context.Context, request Request) (Evidence, error) {
	if request.WorkspaceID == "" || request.ProjectID == "" || request.RunID == "" || (request.Kind != Plan && request.Kind != Artifact) || len(request.Payload) == 0 || len(request.Payload) > 16*1024*1024 || !digest(request.BOMDigest) || !digest(request.SchemaDigest) || !digest(request.CatalogDigest) || !digest(request.PolicyDigest) {
		return Evidence{}, problem.New(problem.CodeRequestInvalid, "")
	}
	for attempt := 1; attempt <= o.attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return Evidence{}, err
		}
		result, err := o.runtime.CompileValidate(ctx, request)
		if err != nil {
			if contextErr := ctx.Err(); contextErr != nil {
				return Evidence{}, contextErr
			}
			if attempt < o.attempts {
				if err := o.sleeper.Sleep(ctx, o.backoff*time.Duration(attempt)); err != nil {
					return Evidence{}, err
				}
			}
			continue
		}
		if !validResult(result) {
			return Evidence{}, fmt.Errorf("evidence returned by the Contract Runtime is not bounded")
		}
		validatedAt := o.clock.Now()
		if validatedAt.IsZero() {
			return Evidence{}, fmt.Errorf("evidence time from the Contract Runtime is unavailable")
		}
		evidence := Evidence{request.WorkspaceID, request.ProjectID, request.RunID, request.Kind, request.BOMDigest, request.SchemaDigest, result.ValidatorVersion, request.CatalogDigest, request.PolicyDigest, result.Valid, append([]problem.FieldError(nil), result.Findings...), validatedAt}
		if err := o.recorder.Record(ctx, evidence); err != nil {
			return Evidence{}, fmt.Errorf("record validation evidence: %w", err)
		}
		if !result.Valid {
			details := problem.New(problem.CodeContractInvalid, "")
			details.FieldErrors = evidence.Findings
			details.Detail = "candidate failed pinned contract validation"
			return evidence, details
		}
		return evidence, nil
	}
	details := problem.New(problem.CodeValidationUnavailable, "")
	details.Detail = "Contract Runtime remained unavailable after bounded retry"
	return Evidence{}, details
}

func validResult(result Result) bool {
	if len(result.ValidatorVersion) < 1 || len(result.ValidatorVersion) > 128 || len(result.Findings) > 256 {
		return false
	}
	for _, finding := range result.Findings {
		if len(finding.Code) < 1 || len(finding.Code) > 128 || len(finding.InstancePath) > 1024 || len(finding.SchemaPath) > 1024 || len(finding.Message) > 4096 {
			return false
		}
	}
	return true
}
func (o *Orchestrator) RequireForReview(evidence Evidence) error {
	if evidence.RunID == "" || !evidence.Valid || evidence.ValidatorVersion == "" || !digest(evidence.BOMDigest) || !digest(evidence.SchemaDigest) || !digest(evidence.CatalogDigest) || !digest(evidence.PolicyDigest) {
		return problem.New(problem.CodeContractInvalid, "")
	}
	return nil
}
func (o *Orchestrator) ReviewProof(evidence Evidence) (runs.ValidationProof, error) {
	if err := o.RequireForReview(evidence); err != nil {
		return runs.ValidationProof{}, err
	}
	return runs.ValidationProof{Valid: true, BOMDigest: evidence.BOMDigest, SchemaDigest: evidence.SchemaDigest, ValidatorVersion: evidence.ValidatorVersion, CatalogDigest: evidence.CatalogDigest}, nil
}
func digest(value string) bool {
	if len(value) != 71 || value[:7] != "sha256:" {
		return false
	}
	for _, c := range value[7:] {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// MemoryRecorder records validation evidence in memory for tests.
type MemoryRecorder struct {
	lock    sync.Mutex
	Records []Evidence
}

func (r *MemoryRecorder) Record(_ context.Context, evidence Evidence) error {
	r.lock.Lock()
	defer r.lock.Unlock()
	r.Records = append(r.Records, evidence)
	return nil
}
