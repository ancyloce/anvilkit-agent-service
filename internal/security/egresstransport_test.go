package security_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/security"
)

// The addresses this suite pretends the allowed names resolve to. They are
// ordinary public addresses, because that is what the guard has to be given
// before its later decisions are the ones under test.
const (
	permittedAddress = "203.0.114.10"
	rebindAddress    = "169.254.169.254"
)

// Egress is enforced where the connection is actually made, not where a URL is
// merely inspected.
//
// The guard used to answer whether a destination was permitted and stop there.
// Whatever made the request afterwards resolved the name a second time,
// followed whatever redirects it was handed, and read whatever came back — so
// a destination the guard had refused was reachable through any of three
// doors it never stood in. These cases go through the real exchange: the peer
// is a real TLS server, and what the guard decided is checked against what the
// connection did.
func TestEgressIsEnforcedAtTheConnection(t *testing.T) {
	t.Run("a permitted destination is fetched and its body bounded", func(t *testing.T) {
		peer := newEgressPeer(t, func(response http.ResponseWriter, _ *http.Request) {
			response.Header().Set("Content-Type", "application/json; charset=utf-8")
			_, _ = response.Write([]byte(`{"answer":"permitted"}`))
		})
		guard, dialed := peer.guard(t, map[string][]string{"allowed.example": {permittedAddress}}, func(policy *security.EgressPolicy) {})
		answer, err := guard.Fetch(context.Background(), "https://allowed.example/resource")
		if err != nil {
			t.Fatalf("a permitted destination was refused: %v", err)
		}
		if answer.StatusCode != http.StatusOK || answer.MediaType != "application/json" || string(answer.Body) != `{"answer":"permitted"}` {
			t.Fatalf("answer = %+v", answer)
		}
		// The connection went to the address the guard resolved, at the port
		// the policy admits, and to nothing else.
		if got := dialed.addresses(); len(got) != 1 || got[0] != net.JoinHostPort(permittedAddress, "443") {
			t.Fatalf("the exchange connected to %v", got)
		}
	})

	t.Run("a name that resolves elsewhere on the second look is still connected where it was decided", func(t *testing.T) {
		peer := newEgressPeer(t, func(response http.ResponseWriter, _ *http.Request) {
			_, _ = response.Write([]byte("pinned"))
		})
		// The resolver answers a public address once and the metadata service
		// afterwards, which is the whole of DNS rebinding. Only the first
		// answer was decided, so only the first answer may be connected to.
		resolving := &rebindingResolver{answers: [][]string{{permittedAddress}, {rebindAddress}}}
		guard, dialed := peer.guardWithResolver(t, resolving, func(policy *security.EgressPolicy) {})
		if _, err := guard.Fetch(context.Background(), "https://allowed.example/resource"); err != nil {
			t.Fatalf("the exchange failed: %v", err)
		}
		for _, address := range dialed.addresses() {
			if strings.HasPrefix(address, rebindAddress) {
				t.Fatalf("the exchange connected to the rebound address %s", address)
			}
		}
	})

	t.Run("a destination outside the allowlist never reaches the dialer", func(t *testing.T) {
		peer := newEgressPeer(t, func(response http.ResponseWriter, _ *http.Request) {
			_, _ = response.Write([]byte("unreachable"))
		})
		guard, dialed := peer.guard(t, map[string][]string{"allowed.example": {permittedAddress}}, func(policy *security.EgressPolicy) {})
		for _, target := range []string{
			"https://elsewhere.example/resource",
			"http://allowed.example/resource",
			"https://allowed.example:8443/resource",
			"https://user:secret@allowed.example/resource",
		} {
			if _, err := guard.Fetch(context.Background(), target); !isDenied(err) {
				t.Fatalf("fetching %s answered %v, want a governed denial", target, err)
			}
		}
		if got := dialed.addresses(); len(got) != 0 {
			t.Fatalf("a refused destination still reached the dialer: %v", got)
		}
	})

	t.Run("a name resolving only to an address the policy refuses never reaches the dialer", func(t *testing.T) {
		peer := newEgressPeer(t, func(response http.ResponseWriter, _ *http.Request) {})
		guard, dialed := peer.guard(t, map[string][]string{"allowed.example": {rebindAddress}}, func(policy *security.EgressPolicy) {})
		if _, err := guard.Fetch(context.Background(), "https://allowed.example/resource"); !isDenied(err) {
			t.Fatalf("a name resolving to the metadata service answered %v", err)
		}
		if got := dialed.addresses(); len(got) != 0 {
			t.Fatalf("a refused address still reached the dialer: %v", got)
		}
	})

	t.Run("a redirect is refused when the policy does not follow them", func(t *testing.T) {
		peer := newEgressPeer(t, func(response http.ResponseWriter, request *http.Request) {
			if request.URL.Path == "/resource" {
				http.Redirect(response, request, "https://allowed.example/moved", http.StatusFound)
				return
			}
			_, _ = response.Write([]byte("followed"))
		})
		guard, _ := peer.guard(t, map[string][]string{"allowed.example": {permittedAddress}}, func(policy *security.EgressPolicy) {})
		if _, err := guard.Fetch(context.Background(), "https://allowed.example/resource"); !isDenied(err) {
			t.Fatalf("a redirect was followed under a policy that does not follow them: %v", err)
		}
	})

	t.Run("a redirect leaving the decided host is refused even when redirects are followed", func(t *testing.T) {
		peer := newEgressPeer(t, func(response http.ResponseWriter, request *http.Request) {
			if request.URL.Path == "/resource" {
				http.Redirect(response, request, "https://elsewhere.example/moved", http.StatusFound)
				return
			}
			_, _ = response.Write([]byte("followed"))
		})
		guard, dialed := peer.guard(t, map[string][]string{"allowed.example": {permittedAddress}, "elsewhere.example": {permittedAddress}}, func(policy *security.EgressPolicy) {
			policy.AllowRedirects = true
		})
		if _, err := guard.Fetch(context.Background(), "https://allowed.example/resource"); !isDenied(err) {
			t.Fatalf("a redirect to another host was followed: %v", err)
		}
		// The first hop was permitted, so the dialer was used once and the
		// refusal is about where the redirect pointed rather than about the
		// exchange never starting.
		if len(dialed.addresses()) == 0 {
			t.Fatal("the refused redirect stopped the exchange before it began")
		}
	})

	t.Run("a redirect back to the decided host is followed and re-decided", func(t *testing.T) {
		peer := newEgressPeer(t, func(response http.ResponseWriter, request *http.Request) {
			if request.URL.Path == "/resource" {
				http.Redirect(response, request, "https://allowed.example/moved", http.StatusFound)
				return
			}
			_, _ = response.Write([]byte("followed"))
		})
		guard, _ := peer.guard(t, map[string][]string{"allowed.example": {permittedAddress}}, func(policy *security.EgressPolicy) {
			policy.AllowRedirects = true
		})
		answer, err := guard.Fetch(context.Background(), "https://allowed.example/resource")
		if err != nil {
			t.Fatalf("a permitted redirect was refused: %v", err)
		}
		if string(answer.Body) != "followed" {
			t.Fatalf("answer body = %q", answer.Body)
		}
	})

	t.Run("a response beyond the size bound is refused", func(t *testing.T) {
		peer := newEgressPeer(t, func(response http.ResponseWriter, _ *http.Request) {
			_, _ = response.Write([]byte(strings.Repeat("x", 4096)))
		})
		guard, _ := peer.guard(t, map[string][]string{"allowed.example": {permittedAddress}}, func(policy *security.EgressPolicy) {
			policy.MaximumBytes = 64
		})
		_, err := guard.Fetch(context.Background(), "https://allowed.example/resource")
		var details problem.Details
		if !errors.As(err, &details) || details.Code != string(problem.CodeProviderLimitExceeded) {
			t.Fatalf("an oversized response answered %v, want the bound refused", err)
		}
	})

	t.Run("a peer that never finishes is bounded by the policy's duration", func(t *testing.T) {
		release := make(chan struct{})
		t.Cleanup(func() { close(release) })
		peer := newEgressPeer(t, func(response http.ResponseWriter, request *http.Request) {
			select {
			case <-release:
			case <-request.Context().Done():
			case <-time.After(30 * time.Second):
			}
		})
		guard, _ := peer.guard(t, map[string][]string{"allowed.example": {permittedAddress}}, func(policy *security.EgressPolicy) {
			policy.MaximumDuration = 250 * time.Millisecond
		})
		started := time.Now()
		if _, err := guard.Fetch(context.Background(), "https://allowed.example/resource"); err == nil {
			t.Fatal("a peer that never answered was waited on indefinitely")
		}
		if elapsed := time.Since(started); elapsed > 5*time.Second {
			t.Fatalf("the exchange ran for %s, well past the policy's bound", elapsed)
		}
	})
}

// isDenied reports whether an error is the governed refusal the egress policy
// answers with.
func isDenied(err error) bool {
	var details problem.Details
	return errors.As(err, &details) && details.Code == string(problem.CodeAuthorizationDenied)
}

// egressPeer is a real TLS server the guard's own transport connects to,
// together with the certificate authority that makes its name verifiable.
type egressPeer struct {
	server *httptest.Server
	roots  *x509.CertPool
}

// newEgressPeer stands up an HTTPS peer whose certificate names the hosts this
// suite allows, so certificate verification is exercised rather than disabled.
func newEgressPeer(t *testing.T, handle http.HandlerFunc) *egressPeer {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "allowed.example"},
		DNSNames:              []string{"allowed.example", "elsewhere.example"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	encoded, err := x509.CreateCertificate(rand.Reader, &template, &template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(encoded)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	server := httptest.NewUnstartedServer(handle)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{encoded}, PrivateKey: private, Leaf: certificate}}}
	server.StartTLS()
	t.Cleanup(server.Close)
	return &egressPeer{server: server, roots: roots}
}

// guard composes an egress guard whose resolver answers the given addresses
// and whose dialer records every address the exchange asked for before
// connecting to the peer.
func (p *egressPeer) guard(t *testing.T, addresses map[string][]string, adjust func(*security.EgressPolicy)) (*security.EgressGuard, *dialRecorder) {
	t.Helper()
	return p.guardWithResolver(t, fixedResolver(addresses), adjust)
}

func (p *egressPeer) guardWithResolver(t *testing.T, resolver security.Resolver, adjust func(*security.EgressPolicy)) (*security.EgressGuard, *dialRecorder) {
	t.Helper()
	recorder := &dialRecorder{peer: p.server.Listener.Addr().String()}
	policy := security.EgressPolicy{
		AllowedHosts:    map[string]struct{}{"allowed.example": {}},
		MaximumBytes:    1 << 20,
		MaximumDuration: 5 * time.Second,
		Dial:            recorder.dial,
		TrustRoots:      p.roots,
	}
	adjust(&policy)
	guard, err := security.NewEgressGuard(policy, resolver)
	if err != nil {
		t.Fatal(err)
	}
	return guard, recorder
}

// dialRecorder records every address the guard asked to connect to and then
// connects to the peer. It is the seam that lets a test stand up a peer at
// all: the policy refuses every address a local listener can have, which is
// the point of the policy.
type dialRecorder struct {
	lock  sync.Mutex
	seen  []string
	peer  string
	dials int
}

func (r *dialRecorder) dial(ctx context.Context, network, address string) (net.Conn, error) {
	r.lock.Lock()
	r.seen = append(r.seen, address)
	r.dials++
	r.lock.Unlock()
	return (&net.Dialer{}).DialContext(ctx, network, r.peer)
}

func (r *dialRecorder) addresses() []string {
	r.lock.Lock()
	defer r.lock.Unlock()
	return append([]string(nil), r.seen...)
}

// fixedResolver answers the addresses this suite pretends a name has.
func fixedResolver(addresses map[string][]string) security.Resolver {
	return resolverFunc(func(_ context.Context, host string) ([]net.IPAddr, error) {
		values, known := addresses[host]
		if !known {
			return nil, fmt.Errorf("no address for %s", host)
		}
		answer := make([]net.IPAddr, 0, len(values))
		for _, value := range values {
			answer = append(answer, net.IPAddr{IP: net.ParseIP(value)})
		}
		return answer, nil
	})
}

// rebindingResolver answers a different address each time it is asked, which
// is what a name under an attacker's control does.
type rebindingResolver struct {
	lock    sync.Mutex
	answers [][]string
	asked   int
}

func (r *rebindingResolver) LookupIPAddr(_ context.Context, _ string) ([]net.IPAddr, error) {
	r.lock.Lock()
	defer r.lock.Unlock()
	values := r.answers[len(r.answers)-1]
	if r.asked < len(r.answers) {
		values = r.answers[r.asked]
	}
	r.asked++
	answer := make([]net.IPAddr, 0, len(values))
	for _, value := range values {
		answer = append(answer, net.IPAddr{IP: net.ParseIP(value)})
	}
	return answer, nil
}

type resolverFunc func(context.Context, string) ([]net.IPAddr, error)

func (f resolverFunc) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	return f(ctx, host)
}
