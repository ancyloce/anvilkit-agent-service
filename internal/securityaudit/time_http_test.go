package securityaudit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHTTPTimeSourceReadsDateHeader(t *testing.T) {
	want := time.Date(2026, time.August, 14, 12, 34, 56, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodHead {
			t.Fatalf("method = %s", request.Method)
		}
		response.Header().Set("Date", want.Format(http.TimeFormat))
		response.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	source, err := NewHTTPTimeSource(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	got, err := source.Now(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(want) {
		t.Fatalf("Now() = %s, want %s", got, want)
	}
}

func TestHTTPTimeSourceRejectsMissingDateAndFailure(t *testing.T) {
	for name, status := range map[string]int{"missing-date": http.StatusNoContent, "failure": http.StatusServiceUnavailable} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				response.Header()["Date"] = nil
				response.WriteHeader(status)
			}))
			defer server.Close()
			source, err := NewHTTPTimeSource(server.URL, server.Client())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := source.Now(context.Background()); err == nil {
				t.Fatal("expected authoritative time failure")
			}
		})
	}
}
