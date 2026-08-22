// Package security implements bounded untrusted-content admission and egress policy.
package security

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
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
	// Dial is the connection primitive the guard connects through, and
	// TrustRoots the certificate authorities it verifies peers against. Both
	// are the deployment's, and both are nil in every deployment: nil means
	// the host's own dialer and the host's own trust store, which is what
	// production wants.
	//
	// They are named on the policy for the same reason Resolver is a
	// parameter rather than a package call — the guard's decisions are about
	// where a connection goes, and a decision about connections can only be
	// proved against a connection somebody can stand up. A deployment never
	// sets them; a conformance suite that needs a peer to connect to does.
	Dial       func(ctx context.Context, network, address string) (net.Conn, error)
	TrustRoots *x509.CertPool
}

type Destination struct {
	URL  *url.URL
	IPs  []net.IP
	host string
}

type EgressGuard struct {
	policy   EgressPolicy
	resolver Resolver
}

func NewEgressGuard(policy EgressPolicy, resolver Resolver) (*EgressGuard, error) {
	if len(policy.AllowedHosts) == 0 || policy.MaximumBytes < 1 || policy.MaximumBytes > 1<<30 || policy.MaximumDuration <= 0 || policy.MaximumDuration > 30*time.Second || resolver == nil {
		return nil, fmt.Errorf("bounded egress policy and resolver are required")
	}
	allowed := make(map[string]struct{}, len(policy.AllowedHosts))
	for configured := range policy.AllowedHosts {
		host := strings.ToLower(strings.TrimSuffix(configured, "."))
		if host == "" || strings.ContainsAny(host, "/:@[]") {
			return nil, fmt.Errorf("invalid allowed egress host")
		}
		allowed[host] = struct{}{}
	}
	policy.AllowedHosts = allowed
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
	lookupContext, cancel := context.WithTimeout(ctx, g.policy.MaximumDuration)
	defer cancel()
	addresses, err := g.resolver.LookupIPAddr(lookupContext, host)
	if err != nil || len(addresses) == 0 {
		return Destination{}, problem.New(problem.CodeInfrastructureUnavailable, "")
	}
	destination := Destination{URL: parsed, host: host}
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
	if from.URL == nil || from.host == "" || next.host != from.host {
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
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
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
	if ip.To4() == nil {
		blocked := []*net.IPNet{
			mustCIDR("2001::/23"), mustCIDR("2001:db8::/32"),
			mustCIDR("2002::/16"), mustCIDR("fc00::/7"), mustCIDR("fe80::/10"),
		}
		for _, network := range blocked {
			if network.Contains(ip) {
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
	now := g.now().UTC()
	if !safeID(candidate.WorkspaceID) || !safeID(candidate.ProjectID) || !safeID(candidate.SourceID) || candidate.Classification != "untrusted" || len(candidate.Content) == 0 || len(candidate.Content) > g.maximumBytes || now.IsZero() || candidate.ExpiresAt.IsZero() || !now.Before(candidate.ExpiresAt) || candidate.ExpiresAt.After(now.Add(24*time.Hour)) {
		return problem.New(problem.CodeAuthorizationDenied, "")
	}
	if hostile(candidate.Content) {
		return problem.New(problem.CodeAuthorizationDenied, "")
	}
	return nil
}

func hostile(content []byte) bool {
	return hostileDepth(content, 0)
}

func hostileDepth(content []byte, depth int) bool {
	if depth > 8 {
		return true
	}
	lower := strings.ToLower(string(content))
	patterns := []string{"ignore previous", "system prompt", "developer message", "execute tool", "authorization:", "aws_secret", "169.254.169.254", "<script", "<iframe", "onerror=", "onload=", "srcdoc=", "javascript:", "data:text/html", "\u202e", "\u2066"}
	for _, pattern := range patterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	// Content that is structured is examined as structure. Tool output is
	// JSON, and JSON escapes: a script tag arrives as \u003cscript\u003e and
	// matches none of the patterns above while meaning exactly what they
	// describe. Decoding the document and examining each string it holds is
	// what closes that, and it closes nesting with it — a hostile string
	// inside an object inside an array is still a hostile string.
	if structured := jsonStrings(content); len(structured) > 0 {
		for _, value := range structured {
			if hostileDepth([]byte(value), depth+1) {
				return true
			}
		}
	}
	compact := strings.TrimSpace(string(content))
	decoders := []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding}
	for _, decoder := range decoders {
		if decoded, err := decoder.DecodeString(compact); err == nil && string(decoded) != string(content) && hostileDepth(decoded, depth+1) {
			return true
		}
	}
	// Encoded content does not have to be the whole of what arrives. A
	// base64 instruction carried as one field of a larger document decodes
	// only when it is taken on its own, so every token that could be base64
	// is tried on its own.
	for _, token := range encodedTokens(compact) {
		for _, decoder := range decoders {
			if decoded, err := decoder.DecodeString(token); err == nil && len(decoded) > 0 && string(decoded) != token && hostileDepth(decoded, depth+1) {
				return true
			}
		}
	}
	if decoded, err := url.QueryUnescape(compact); err == nil && decoded != compact && hostileDepth([]byte(decoded), depth+1) {
		return true
	}
	if decoded := html.UnescapeString(compact); decoded != compact && hostileDepth([]byte(decoded), depth+1) {
		return true
	}
	return false
}

func safeID(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for index, character := range value {
		if (character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || (index > 0 && (character == '.' || character == '_' || character == ':' || character == '-')) {
			continue
		}
		return false
	}
	return true
}

// jsonStrings decodes one JSON document and returns every string it holds,
// with the document's own escaping already undone. It answers nothing for
// content that is not JSON, and nothing for a bare JSON string — that is the
// content itself, and recursing on it would not terminate.
func jsonStrings(content []byte) []string {
	var decoded any
	if err := json.Unmarshal(content, &decoded); err != nil {
		return nil
	}
	if _, bare := decoded.(string); bare {
		return nil
	}
	var values []string
	var walk func(any)
	walk = func(value any) {
		// The bound is a cost bound, not a correctness one: a document large
		// enough to exceed it is already past the admission size limit.
		if len(values) >= maximumInspectedStrings {
			return
		}
		switch typed := value.(type) {
		case string:
			values = append(values, typed)
		case []any:
			for _, item := range typed {
				walk(item)
			}
		case map[string]any:
			for name, item := range typed {
				values = append(values, name)
				walk(item)
			}
		}
	}
	walk(decoded)
	return values
}

// encodedTokens returns the substrings that could be base64. A token is worth
// trying when it is long enough to carry an instruction and is drawn entirely
// from the base64 alphabets.
func encodedTokens(content string) []string {
	var tokens []string
	var builder strings.Builder
	flush := func() {
		if builder.Len() >= minimumEncodedToken && len(tokens) < maximumInspectedStrings {
			tokens = append(tokens, builder.String())
		}
		builder.Reset()
	}
	for _, character := range content {
		if base64Character(character) {
			builder.WriteRune(character)
			continue
		}
		flush()
	}
	flush()
	// The whole content is already tried by the caller; a single token equal
	// to it is not a second thing to try.
	if len(tokens) == 1 && tokens[0] == content {
		return nil
	}
	return tokens
}

func base64Character(character rune) bool {
	switch {
	case character >= 'A' && character <= 'Z', character >= 'a' && character <= 'z', character >= '0' && character <= '9':
		return true
	case character == '+', character == '/', character == '-', character == '_', character == '=':
		return true
	}
	return false
}

const (
	// minimumEncodedToken is the shortest base64 run worth decoding. Below
	// it a token decodes to a few bytes that cannot carry an instruction, and
	// ordinary words decode by accident.
	minimumEncodedToken = 16
	// maximumInspectedStrings bounds how much of one candidate is examined.
	maximumInspectedStrings = 256
)
