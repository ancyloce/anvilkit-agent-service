package interrupts

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/runs"
)

func expiryFailure(code problem.Code) problem.Details {
	details := problem.New(code, "")
	details.Detail = "the durable deadline elapsed before a response was accepted"
	return details
}

func openInputRequest(t *testing.T, repository *MemoryRepository, service *Service, expiresAt time.Time) InputRequest {
	t.Helper()
	schema := json.RawMessage(`{"type":"object","required":["answer"],"properties":{"answer":{"type":"string","maxLength":20}},"additionalProperties":false}`)
	request, opened, err := service.RequestInput(context.Background(), write("run", 4, "open"), OpenInput{Question: "Which locale?", ResponseSchema: schema, ExpiresAt: expiresAt, ResumeCheckpoint: "planning:compile"})
	if err != nil || opened.Snapshot.Status != runs.AwaitingInput {
		t.Fatalf("opened=%#v err=%v", opened, err)
	}
	return request
}

// Acceptance and expiry contend for the same request. Exactly one may win: a
// split decision would either lose an accepted answer or leave the run alive
// with no workflow driving it.
func TestInputExpiryAndResponseNeverBothWin(t *testing.T) {
	for attempt := range 50 {
		repository := NewMemoryRepository()
		if err := repository.Seed(scope(), snapshot("run", runs.Planning, 4)); err != nil {
			t.Fatal(err)
		}
		clock := &testClock{now: testNow}
		service, _, _ := newTestService(t, repository, clock, &testAuthority{}, &testReconciler{clear: true}, &testReservation{})
		request := openInputRequest(t, repository, service, testNow.Add(time.Hour))

		command := InputResponseCommand{RequestID: request.ID, RequestVersion: request.Version, Value: json.RawMessage(`{"answer":"en-US"}`)}
		var wait sync.WaitGroup
		wait.Add(2)
		var responseErr error
		var expiry Expiry
		var expiryErr error
		start := make(chan struct{})
		go func() {
			defer wait.Done()
			<-start
			_, responseErr = service.RespondInput(context.Background(), write("run", 5, "respond"), command)
		}()
		go func() {
			defer wait.Done()
			<-start
			expiry, expiryErr = repository.ExpireInput(context.Background(), write("run", 5, "expire"), request.ID, expiryFailure(problem.CodeInputRequestExpired), clock.Now())
		}()
		close(start)
		wait.Wait()

		if expiryErr != nil {
			t.Fatalf("attempt %d: expiry failed: %v", attempt, expiryErr)
		}
		final, err := repository.Current(context.Background(), scope(), "run")
		if err != nil {
			t.Fatal(err)
		}
		stored, err := repository.Input(context.Background(), scope(), "run", request.ID)
		if err != nil {
			t.Fatal(err)
		}
		switch responseErr {
		case nil:
			// The response won: expiry must report the race, the request must
			// stay unexpired, and the run must remain alive for the workflow.
			if !expiry.Raced {
				t.Fatalf("attempt %d: accepted response did not win the race: %+v", attempt, expiry)
			}
			if stored.ExpiredAt != nil {
				t.Fatalf("attempt %d: an answered request was also expired", attempt)
			}
			if final.Status == runs.Failed {
				t.Fatalf("attempt %d: an answered run was failed by expiry", attempt)
			}
		default:
			// Expiry won: the run is durably failed and the request is
			// durably expired, so the late response fails closed.
			if expiry.Raced {
				t.Fatalf("attempt %d: expiry claimed a race it did not lose", attempt)
			}
			if stored.ExpiredAt == nil {
				t.Fatalf("attempt %d: expiry committed without the durable marker", attempt)
			}
			if final.Status != runs.Failed {
				t.Fatalf("attempt %d: expiry left the run in %s with no driver", attempt, final.Status)
			}
			var details problem.Details
			if !errors.As(responseErr, &details) || details.Code != string(problem.CodeInputRequestExpired) {
				t.Fatalf("attempt %d: losing response error = %v", attempt, responseErr)
			}
		}
	}
}

// The durable expiry marker, not the wall clock, is what makes a response
// unrevivable: even a response inside its original deadline fails closed once
// the request is expired.
func TestExpiredInputCannotBeRevivedInsideItsDeadline(t *testing.T) {
	repository := NewMemoryRepository()
	if err := repository.Seed(scope(), snapshot("run", runs.Planning, 4)); err != nil {
		t.Fatal(err)
	}
	clock := &testClock{now: testNow}
	service, _, _ := newTestService(t, repository, clock, &testAuthority{}, &testReconciler{clear: true}, &testReservation{})
	request := openInputRequest(t, repository, service, testNow.Add(time.Hour))

	expiry, err := repository.ExpireInput(context.Background(), write("run", 5, "expire"), request.ID, expiryFailure(problem.CodeInputRequestExpired), clock.Now())
	if err != nil || expiry.Raced || expiry.Superseded {
		t.Fatalf("expiry = %+v err = %v", expiry, err)
	}
	_, err = service.RespondInput(context.Background(), write("run", expiry.Snapshot.Version, "respond-late"), InputResponseCommand{RequestID: request.ID, RequestVersion: request.Version, Value: json.RawMessage(`{"answer":"en-US"}`)})
	var details problem.Details
	if !errors.As(err, &details) || details.Code != string(problem.CodeInputRequestExpired) {
		t.Fatalf("late response inside the deadline must fail closed: %v", err)
	}
	if current, _ := repository.Current(context.Background(), scope(), "run"); current.Status != runs.Failed {
		t.Fatalf("late response changed the failed run to %s", current.Status)
	}
}

// Re-running the expiry operation after recovery must converge instead of
// failing an already-failed run a second time.
func TestInputExpiryIsIdempotentAcrossRecovery(t *testing.T) {
	repository := NewMemoryRepository()
	if err := repository.Seed(scope(), snapshot("run", runs.Planning, 4)); err != nil {
		t.Fatal(err)
	}
	clock := &testClock{now: testNow}
	service, _, _ := newTestService(t, repository, clock, &testAuthority{}, &testReconciler{clear: true}, &testReservation{})
	request := openInputRequest(t, repository, service, testNow.Add(time.Hour))

	first, err := repository.ExpireInput(context.Background(), write("run", 5, "expire"), request.ID, expiryFailure(problem.CodeInputRequestExpired), clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	second, err := repository.ExpireInput(context.Background(), write("run", 5, "expire"), request.ID, expiryFailure(problem.CodeInputRequestExpired), clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	if second.Raced || second.Superseded {
		t.Fatalf("re-executed expiry = %+v", second)
	}
	if second.Snapshot.Version != first.Snapshot.Version || second.Snapshot.Status != runs.Failed {
		t.Fatalf("re-executed expiry moved the aggregate: %+v", second.Snapshot)
	}
}

// A decided approval racing its deadline behaves identically.
func TestApprovalExpiryAndDecisionNeverBothWin(t *testing.T) {
	for attempt := range 50 {
		repository := NewMemoryRepository()
		if err := repository.Seed(scope(), snapshot("run", runs.AwaitingReview, 4)); err != nil {
			t.Fatal(err)
		}
		clock := &testClock{now: testNow}
		service, _, _ := newTestService(t, repository, clock, &testAuthority{}, &testReconciler{clear: true}, &testReservation{})
		request, opened, err := service.RequestApproval(context.Background(), write("run", 4, "open"), OpenApproval{
			ActionDigest:     "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Effects:          json.RawMessage(`["domain-effect"]`),
			ExpectedCost:     json.RawMessage(`{"amount":"0","currency":"USD"}`),
			ReviewerPolicy:   reviewerPolicy(),
			ExpiresAt:        testNow.Add(time.Hour),
			ResumeCheckpoint: "review:await",
		})
		if err != nil || opened.Snapshot.Status != runs.AwaitingApproval {
			t.Fatalf("opened=%#v err=%v", opened, err)
		}

		var wait sync.WaitGroup
		wait.Add(2)
		var decisionErr error
		var expiry Expiry
		start := make(chan struct{})
		go func() {
			defer wait.Done()
			<-start
			_, decisionErr = service.DecideApproval(context.Background(), write("run", 5, "decide"), ApprovalDecisionCommand{RequestID: request.ID, RequestVersion: request.Version, Decision: DecisionReject, Reason: "revise"})
		}()
		go func() {
			defer wait.Done()
			<-start
			expiry, _ = repository.ExpireApproval(context.Background(), write("run", 5, "expire"), request.ID, expiryFailure(problem.CodeApprovalRequestExpired), clock.Now())
		}()
		close(start)
		wait.Wait()

		stored, err := repository.Approval(context.Background(), scope(), "run", request.ID)
		if err != nil {
			t.Fatal(err)
		}
		if stored.Decision != nil && stored.ExpiredAt != nil {
			t.Fatalf("attempt %d: approval was both decided and expired", attempt)
		}
		if decisionErr == nil && !expiry.Raced {
			t.Fatalf("attempt %d: accepted decision did not win the race: %+v", attempt, expiry)
		}
		if decisionErr != nil {
			var details problem.Details
			if !errors.As(decisionErr, &details) || details.Code != string(problem.CodeApprovalRequestExpired) {
				t.Fatalf("attempt %d: losing decision error = %v", attempt, decisionErr)
			}
		}
	}
}
