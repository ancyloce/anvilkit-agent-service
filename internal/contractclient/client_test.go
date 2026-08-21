package contractclient

import (
	"context"
	"errors"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"testing"
	"time"
)

type runtime struct {
	fail   int
	calls  int
	result Result
}

func (r *runtime) CompileValidate(context.Context, Request) (Result, error) {
	r.calls++
	if r.calls <= r.fail {
		return Result{}, errors.New("outage")
	}
	return r.result, nil
}

type recorder struct{ values []Evidence }

func (r *recorder) Record(_ context.Context, e Evidence) error {
	r.values = append(r.values, e)
	return nil
}

type sleeper struct{}

func (sleeper) Sleep(context.Context, time.Duration) error { return nil }

type clock struct{}

func (clock) Now() time.Time { return time.Unix(1, 0) }
func request(kind Kind) Request {
	return Request{WorkspaceID: "workspace", ProjectID: "project", RunID: "run", Kind: kind, Payload: []byte(`{}`), BOMDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", SchemaDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", CatalogDigest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", PolicyDigest: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}
}
func TestPlanAndArtifactCrossingBoundaryRecordCompleteEvidence(t *testing.T) {
	for _, kind := range []Kind{Plan, Artifact} {
		runtime := &runtime{result: Result{Valid: true, ValidatorVersion: "validator-v1"}}
		record := &recorder{}
		orchestrator, _ := New(runtime, record, sleeper{}, clock{}, 2, time.Millisecond)
		evidence, err := orchestrator.Validate(context.Background(), request(kind))
		if err != nil || len(record.values) != 1 || record.values[0].Kind != kind || orchestrator.RequireForReview(evidence) != nil {
			t.Fatalf("kind=%s evidence=%#v err=%v", kind, evidence, err)
		}
		if proof, err := orchestrator.ReviewProof(evidence); err != nil || !proof.Valid {
			t.Fatalf("review proof=%#v err=%v", proof, err)
		}
	}
}
func TestOutageRetriesThenStableRetryableProblemWithoutEvidence(t *testing.T) {
	runtime := &runtime{fail: 10}
	record := &recorder{}
	orchestrator, _ := New(runtime, record, sleeper{}, clock{}, 3, time.Millisecond)
	_, err := orchestrator.Validate(context.Background(), request(Plan))
	var details problem.Details
	if !errors.As(err, &details) || details.Code != string(problem.CodeValidationUnavailable) || details.Retryability != "safe-after-backoff" || runtime.calls != 3 || len(record.values) != 0 {
		t.Fatalf("calls=%d records=%d err=%v", runtime.calls, len(record.values), err)
	}
}
func TestInvalidCandidateRecordedButCannotReachReview(t *testing.T) {
	runtime := &runtime{result: Result{Valid: false, ValidatorVersion: "validator-v1", Findings: []problem.FieldError{{Code: "VALIDATION_FAILED"}}}}
	record := &recorder{}
	orchestrator, _ := New(runtime, record, sleeper{}, clock{}, 1, 0)
	evidence, err := orchestrator.Validate(context.Background(), request(Artifact))
	if err == nil || len(record.values) != 1 || orchestrator.RequireForReview(evidence) == nil {
		t.Fatalf("evidence=%#v err=%v", evidence, err)
	}
}

func TestValidationBoundsAndCancellationFailClosed(t *testing.T) {
	if _, err := New(&runtime{}, &recorder{}, sleeper{}, clock{}, 1, 31*time.Second); err == nil {
		t.Fatal("unbounded retry delay accepted")
	}
	orchestrator, _ := New(&runtime{result: Result{Valid: true, ValidatorVersion: "validator-v1"}}, &recorder{}, sleeper{}, clock{}, 1, 0)
	oversized := request(Plan)
	oversized.Payload = make([]byte, 16*1024*1024+1)
	if _, err := orchestrator.Validate(context.Background(), oversized); err == nil {
		t.Fatal("oversized validation payload accepted")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := orchestrator.Validate(cancelled, request(Plan)); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation became a retryable outage: %v", err)
	}
	malformed := &runtime{result: Result{Valid: true, ValidatorVersion: "validator-v1", Findings: make([]problem.FieldError, 257)}}
	orchestrator, _ = New(malformed, &recorder{}, sleeper{}, clock{}, 1, 0)
	if _, err := orchestrator.Validate(context.Background(), request(Plan)); err == nil {
		t.Fatal("unbounded Contract Runtime evidence accepted")
	}
}
