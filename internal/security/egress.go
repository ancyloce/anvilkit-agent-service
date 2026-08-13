// Package security implements bounded untrusted-content admission and egress policy.
package security

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
)

type Resolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

type EgressPolicy struct {
	AllowedHosts    map[string]struct{}
	MaximumBytes    int64
	MaximumDuration time.Duration
	AllowRedirects  bool
}

type Destination struct {
	URL *url.URL
	IPs []net.IP
}

type EgressGuard struct {
	policy   EgressPolicy
	resolver Resolver
}

func NewEgressGuard(policy EgressPolicy, resolver Resolver) (*EgressGuard, error) {
	if len(policy.AllowedHosts) == 0 || policy.MaximumBytes < 1 || policy.MaximumDuration <= 0 || resolver == nil {
		return nil, fmt.Errorf("bounded egress policy and resolver are required")
	}
	return &EgressGuard{policy: policy, resolver: resolver}, nil
}

func (g *EgressGuard) Resolve(ctx context.Context, raw string) (Destination, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" {
		return Destination{}, problem.New(problem.CodeAuthorizationDenied, "")
	}
	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	if _, allowed := g.policy.AllowedHosts[host]; !allowed || (parsed.Port() != "" && parsed.Port() != "443") {
		return Destination{}, problem.New(problem.CodeAuthorizationDenied, "")
	}
	addresses, err := g.resolver.LookupIPAddr(ctx, host)
	if err != nil || len(addresses) == 0 {
		return Destination{}, problem.New(problem.CodeInfrastructureUnavailable, "")
	}
	destination := Destination{URL: parsed}
	for _, address := range addresses {
		if !publicIP(address.IP) {
			return Destination{}, problem.New(problem.CodeAuthorizationDenied, "")
		}
		destination.IPs = append(destination.IPs, append(net.IP(nil), address.IP...))
	}
	return destination, nil
}

func (g *EgressGuard) ValidateRedirect(ctx context.Context, from Destination, target string) (Destination, error) {
	if !g.policy.AllowRedirects {
		return Destination{}, problem.New(problem.CodeAuthorizationDenied, "")
	}
	next, err := g.Resolve(ctx, target)
	if err != nil {
		return Destination{}, err
	}
	if strings.ToLower(next.URL.Hostname()) != strings.ToLower(from.URL.Hostname()) {
		return Destination{}, problem.New(problem.CodeAuthorizationDenied, "")
	}
	return next, nil
}

func (g *EgressGuard) MaximumBytes() int64            { return g.policy.MaximumBytes }
func (g *EgressGuard) MaximumDuration() time.Duration { return g.policy.MaximumDuration }

func (g *EgressGuard) ReadResponse(ctx context.Context, body io.Reader) ([]byte, error) {
	if body == nil {
		return nil, problem.New(problem.CodeRequestInvalid, "")
	}
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > g.policy.MaximumDuration {
		return nil, problem.New(problem.CodeAuthorizationDenied, "")
	}
	limited := io.LimitReader(body, g.policy.MaximumBytes+1)
	value, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read bounded egress response: %w", err)
	}
	if int64(len(value)) > g.policy.MaximumBytes {
		return nil, problem.New(problem.CodeProviderLimitExceeded, "")
	}
	return value, nil
}

func publicIP(ip net.IP) bool {
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		// Cloud metadata, carrier-grade NAT, documentation, benchmark, and
		// reserved ranges are data destinations, never service authority.
		blocked := []*net.IPNet{
			mustCIDR("100.64.0.0/10"), mustCIDR("169.254.0.0/16"),
			mustCIDR("192.0.0.0/24"), mustCIDR("192.0.2.0/24"),
			mustCIDR("198.18.0.0/15"), mustCIDR("198.51.100.0/24"),
			mustCIDR("203.0.113.0/24"), mustCIDR("224.0.0.0/4"),
			mustCIDR("240.0.0.0/4"),
		}
		for _, network := range blocked {
			if network.Contains(v4) {
				return false
			}
		}
	}
	return true
}

func mustCIDR(value string) *net.IPNet {
	_, network, _ := net.ParseCIDR(value)
	return network
}

type MemoryCandidate struct {
	WorkspaceID, ProjectID, SourceID, Classification string
	Content                                          []byte
	ExpiresAt                                        time.Time
}

type MemoryGuard struct {
	maximumBytes int
	now          func() time.Time
}

func NewMemoryGuard(maximumBytes int, now func() time.Time) (*MemoryGuard, error) {
	if maximumBytes < 1 || now == nil {
		return nil, fmt.Errorf("memory bound and clock are required")
	}
	return &MemoryGuard{maximumBytes: maximumBytes, now: now}, nil
}

func (g *MemoryGuard) Admit(candidate MemoryCandidate) error {
	if candidate.WorkspaceID == "" || candidate.ProjectID == "" || candidate.SourceID == "" || candidate.Classification == "" || len(candidate.Content) == 0 || len(candidate.Content) > g.maximumBytes || candidate.ExpiresAt.IsZero() || !g.now().Before(candidate.ExpiresAt) {
		return problem.New(problem.CodeAuthorizationDenied, "")
	}
	if hostile(candidate.Content) {
		return problem.New(problem.CodeAuthorizationDenied, "")
	}
	return nil
}

func hostile(content []byte) bool {
	lower := strings.ToLower(string(content))
	patterns := []string{"ignore previous", "system prompt", "developer message", "execute tool", "authorization:", "aws_secret", "169.254.169.254", "<script", "javascript:", "data:text/html", "\u202e", "\u2066"}
	for _, pattern := range patterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	compact := strings.TrimSpace(string(content))
	if decoded, err := base64.StdEncoding.DecodeString(compact); err == nil && string(decoded) != string(content) {
		return hostile(decoded)
	}
	return false
}
