package api

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// deadlineRecorder is a response writer with real deadline and flush support,
// standing in for the server's own writer underneath the production wrapper.
type deadlineRecorder struct {
	*httptest.ResponseRecorder
	deadlines int
	flushes   int
	flushErr  error
}

func (r *deadlineRecorder) SetWriteDeadline(time.Time) error {
	r.deadlines++
	return nil
}

func (r *deadlineRecorder) FlushError() error {
	r.flushes++
	return r.flushErr
}

// The production response wrapper must not hide the server's own deadline and
// flush support. Without Unwrap, http.ResponseController cannot reach the
// writer underneath, so a long-lived event stream would silently lose its
// write deadline; and a plain Flush on the wrapper would make the controller
// stop unwrapping and report success for a flush that never happened.
func TestProductionResponseWrapperExposesDeadlinesAndFlushErrors(t *testing.T) {
	inner := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	tracked := &trackedResponse{ResponseWriter: inner}
	controller := http.NewResponseController(tracked)

	if err := controller.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("write deadline unavailable through the production wrapper: %v", err)
	}
	if inner.deadlines != 1 {
		t.Fatalf("deadlines reaching the server writer=%d, want 1", inner.deadlines)
	}
	if err := controller.Flush(); err != nil {
		t.Fatalf("flush through the production wrapper failed: %v", err)
	}
	if inner.flushes != 1 {
		t.Fatalf("flushes reaching the server writer=%d, want 1", inner.flushes)
	}

	// A failed hand-off must surface as an error rather than as silence.
	inner.flushErr = errors.New("client is not reading")
	if err := controller.Flush(); err == nil {
		t.Fatal("a failed flush was reported as success through the production wrapper")
	}

	// Flushing commits the response, so the wrapper records that it wrote.
	if !tracked.wrote {
		t.Fatal("the wrapper did not record that the response was committed")
	}
}
