package securityaudit

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// HTTPTimeSource reads authoritative time from the standard Date response
// header. The endpoint is intentionally queried for every decision so an
// outage cannot silently fall back to the host clock.
type HTTPTimeSource struct {
	url    string
	client *http.Client
}

func NewHTTPTimeSource(endpoint string, client *http.Client) (*HTTPTimeSource, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, fmt.Errorf("authoritative time endpoint must be an absolute HTTP URL")
	}
	if client == nil {
		return nil, fmt.Errorf("authoritative time HTTP client is required")
	}
	return &HTTPTimeSource{url: parsed.String(), client: client}, nil
}

func (s *HTTPTimeSource) Now(ctx context.Context) (time.Time, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodHead, s.url, nil)
	if err != nil {
		return time.Time{}, fmt.Errorf("create authoritative time request: %w", err)
	}
	response, err := s.client.Do(request)
	if err != nil {
		return time.Time{}, fmt.Errorf("query authoritative time: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return time.Time{}, fmt.Errorf("query authoritative time: unexpected status %d", response.StatusCode)
	}
	value, err := http.ParseTime(response.Header.Get("Date"))
	if err != nil {
		return time.Time{}, fmt.Errorf("parse authoritative Date header: %w", err)
	}
	return value.UTC(), nil
}

var _ TimeSource = (*HTTPTimeSource)(nil)
