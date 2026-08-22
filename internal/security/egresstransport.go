package security

import (
	"context"
	"crypto/tls"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
)

// Response is what one bounded outbound exchange returned: the status, the
// media type the peer declared, and the body — already read under the
// policy's size bound.
type Response struct {
	StatusCode int
	MediaType  string
	Body       []byte
}

// maximumRedirects bounds how many hops one exchange may take. Each hop is
// re-decided by the guard, so this is a cost bound rather than a safety one —
// but an unbounded chain of individually-permitted hops is still a way to
// spend a deployment's whole egress timeout on nothing.
const maximumRedirects = 3

// Fetch performs one outbound exchange under the deployment's egress policy,
// and it is the only way anything in this service reaches an address an agent
// named.
//
// Deciding a destination and connecting to one were separate acts before this
// existed. The guard answered whether a URL was permitted; whatever made the
// request afterwards resolved the name again, followed whatever redirects it
// was given, and read whatever came back. Every one of those steps could
// arrive somewhere the guard had refused:
//
//   - the second resolution can answer a different address than the one the
//     guard approved, which is the whole of DNS rebinding;
//   - a redirect is a new destination that nothing re-decided;
//   - a response with no size bound is an unbounded read into a run's memory,
//     and one with no deadline is a held connection.
//
// So the connection is made here. The name is resolved once, by the guard, and
// the dial is pinned to exactly the addresses that resolution returned — the
// host name still governs TLS, so certificate verification is unchanged, but
// nothing gets to re-answer where that name points. Redirects come back
// through the guard. The deadline and the size bound are the policy's, applied
// to the exchange rather than offered as advice to whoever is making it.
func (g *EgressGuard) Fetch(ctx context.Context, raw string) (Response, error) {
	destination, err := g.Resolve(ctx, raw)
	if err != nil {
		return Response{}, err
	}
	bounded, cancel := context.WithTimeout(ctx, g.policy.MaximumDuration)
	defer cancel()

	exchange := &pinnedExchange{guard: g, pinned: map[string][]net.IP{destination.host: destination.IPs}, from: destination}
	client := &http.Client{
		Transport: &http.Transport{
			// No proxy. A proxy is a destination the policy never decided,
			// and one configured in the process environment would silently
			// become the address every permitted name resolves to.
			Proxy:                 nil,
			DialContext:           exchange.dial,
			TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: g.policy.TrustRoots},
			ForceAttemptHTTP2:     true,
			MaxIdleConnsPerHost:   1,
			DisableCompression:    false,
			ResponseHeaderTimeout: g.policy.MaximumDuration,
		},
		CheckRedirect: exchange.redirect,
	}
	// The transport is this exchange's own, so it is closed with it rather
	// than left holding connections to a destination the next call may not be
	// permitted to reach.
	defer client.Transport.(*http.Transport).CloseIdleConnections()

	request, err := http.NewRequestWithContext(bounded, http.MethodGet, destination.URL.String(), nil)
	if err != nil {
		return Response{}, problem.New(problem.CodeRequestInvalid, "")
	}
	response, err := client.Do(request)
	if err != nil {
		// A refusal the guard made during the exchange — a redirect to a
		// destination the policy does not permit, or a dial to an address it
		// did not approve — is carried out as the governed refusal it is
		// rather than reported as a transport failure.
		if refusal := governedRefusal(err); refusal != nil {
			return Response{}, *refusal
		}
		return Response{}, problem.New(problem.CodeInfrastructureUnavailable, "")
	}
	defer func() { _ = response.Body.Close() }()
	body, err := g.ReadResponse(bounded, response.Body)
	if err != nil {
		return Response{}, err
	}
	mediaType := ""
	if declared := response.Header.Get("Content-Type"); declared != "" {
		if parsed, _, err := mime.ParseMediaType(declared); err == nil {
			mediaType = parsed
		}
	}
	return Response{StatusCode: response.StatusCode, MediaType: mediaType, Body: body}, nil
}

// pinnedExchange holds the addresses one exchange is permitted to connect to.
// It grows only through the guard: a redirect the guard admits adds that
// destination's resolved addresses and nothing else does.
type pinnedExchange struct {
	guard  *EgressGuard
	pinned map[string][]net.IP
	from   Destination
}

// dial connects to a host the guard already resolved, at one of the addresses
// that resolution returned.
//
// The address the transport hands down is the URL's host and port, not a
// resolved address, which is exactly what makes this the right place to stand:
// resolving it here would be a second lookup, and a second lookup is a second
// answer. The pinned set is used instead, so what is connected to is what was
// decided.
func (e *pinnedExchange) dial(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, problem.New(problem.CodeAuthorizationDenied, "")
	}
	if port != "443" {
		return nil, problem.New(problem.CodeAuthorizationDenied, "")
	}
	addresses, pinned := e.pinned[strings.ToLower(strings.TrimSuffix(host, "."))]
	if !pinned || len(addresses) == 0 {
		return nil, problem.New(problem.CodeAuthorizationDenied, "")
	}
	dial := e.guard.policy.Dial
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	var last error
	for _, ip := range addresses {
		// Checked again at the moment of connecting. The set was built from a
		// resolution the guard admitted, and asking once more here costs
		// nothing and closes the gap between "was approved" and "is being
		// connected to".
		if !publicIP(ip) {
			last = problem.New(problem.CodeAuthorizationDenied, "")
			continue
		}
		conn, err := dial(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		last = err
	}
	if last == nil {
		last = problem.New(problem.CodeAuthorizationDenied, "")
	}
	return nil, last
}

// redirect re-decides every hop. A redirect is a destination the caller never
// named, so it is admitted on exactly the terms the first one was: the
// policy's allowlist, its resolution, and its rule about whether redirects are
// followed at all.
func (e *pinnedExchange) redirect(request *http.Request, via []*http.Request) error {
	if len(via) > maximumRedirects {
		return problem.New(problem.CodeProviderLimitExceeded, "")
	}
	next, err := e.guard.ValidateRedirect(request.Context(), e.from, redirectTarget(request.URL))
	if err != nil {
		return err
	}
	e.pinned[next.host] = next.IPs
	e.from = next
	return nil
}

// redirectTarget renders the URL a redirect points at. It is rendered rather
// than passed as a value because the guard decides destinations from their
// text, exactly as it does for the destination a caller names.
func redirectTarget(value *url.URL) string {
	if value == nil {
		return ""
	}
	return value.String()
}

// governedRefusal recovers the governed refusal a transport error is carrying.
// The HTTP client wraps whatever the dialer or the redirect policy returned,
// so the refusal arrives inside a url.Error rather than as itself.
func governedRefusal(err error) *problem.Details {
	var details problem.Details
	for candidate := err; candidate != nil; {
		if value, ok := candidate.(problem.Details); ok {
			details = value
			return &details
		}
		unwrapped, ok := candidate.(interface{ Unwrap() error })
		if !ok {
			return nil
		}
		candidate = unwrapped.Unwrap()
	}
	return nil
}
