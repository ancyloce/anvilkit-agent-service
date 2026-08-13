package api

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/lifecycle"
)

func TestServerGoroutineStopsWithOrderedDrain(t *testing.T) {
	readiness := lifecycle.NewReadiness(lifecycle.Dependency{Name: "ready", Check: lifecycle.CheckFunc(func(context.Context) error { return nil })})
	handler := New(readiness)
	server := NewServer("", handler)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	response, err := http.Get("http://" + listener.Addr().String() + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("health status %d", response.StatusCode)
	}
	handler.BeginDrain()
	response, err = http.Get("http://" + listener.Addr().String() + "/runs")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusServiceUnavailable || response.Header.Get("Retry-After") == "" {
		t.Fatalf("drain response status=%d retry=%q", response.StatusCode, response.Header.Get("Retry-After"))
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, http.ErrServerClosed) {
			t.Fatalf("server returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("server goroutine leaked after shutdown")
	}
}
