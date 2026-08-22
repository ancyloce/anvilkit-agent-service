package securityaudit

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/trust"
)

const (
	timeIssuer = "urn:anvilkit:issuer:time-authority"
	timeKeyID  = "urn:anvilkit:key:time-authority:verification"
)

// timeAuthority is a stand-in for the approved time authority: it answers the
// challenge it is sent with a statement signed by a key the trust root holds.
type timeAuthority struct {
	key      ed25519.PrivateKey
	keyID    string
	issuer   string
	audience string
	// answered is the instant every statement asserts, and nonce, when set,
	// replaces the challenge the client sent — which is how a replayed
	// statement is reproduced.
	answered time.Time
	nonce    string
	kind     string
	// corrupt flips one byte of the signature after signing.
	corrupt bool
}

func (a timeAuthority) statement(t *testing.T, challenge string) []byte {
	t.Helper()
	nonce := challenge
	if a.nonce != "" {
		nonce = a.nonce
	}
	kind := a.kind
	if kind == "" {
		kind = TimeStatementKind
	}
	payload, err := json.Marshal(TimeStatement{
		Kind:      kind,
		Algorithm: timeAlgorithm,
		Issuer:    a.issuer,
		Audience:  a.audience,
		KeyID:     a.keyID,
		Nonce:     nonce,
		UTC:       a.answered.UTC().Format(trust.Timestamp),
	})
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := trust.Seal(a.key, a.keyID, TimeStatementType, payload)
	if err != nil {
		t.Fatal(err)
	}
	if a.corrupt {
		signature := []byte(envelope.Signatures[0].Signature)
		signature[0] = 'A' + (signature[0]+1)%26
		envelope.Signatures[0].Signature = string(signature)
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// timeTrustRoot writes an operator trust root holding one key.
func timeTrustRoot(t *testing.T, public ed25519.PublicKey, mutate func(*trust.Root)) string {
	t.Helper()
	key := trust.Key{
		KeyID:      timeKeyID,
		Issuer:     timeIssuer,
		Audiences:  []string{TimeAudience},
		Algorithms: []string{timeAlgorithm},
		Status:     "active",
		NotBefore:  "2020-01-01T00:00:00.000Z",
		NotAfter:   "2099-01-01T00:00:00.000Z",
	}
	key.PublicKeyJwk.KeyType, key.PublicKeyJwk.Curve = "OKP", "Ed25519"
	key.PublicKeyJwk.X = base64.RawURLEncoding.EncodeToString(public)
	root := trust.Root{
		Kind:                    trust.RootKind,
		SnapshotID:              "snapshot.time.0001",
		IssuedAt:                "2026-01-01T00:00:00.000Z",
		NextUpdate:              "2099-01-01T00:00:00.000Z",
		MaximumClockSkewSeconds: 60,
		Keys:                    []trust.Key{key},
	}
	if mutate != nil {
		mutate(&root)
	}
	raw, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "time-trust-root.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// The time authority proves who it is. Before this the source believed
// whatever answered on the configured address, and every decision the service
// stamps, orders, and expires rested on that.
func TestAuthoritativeTimeIsAuthenticatedAgainstTheOperatorTrustRoot(t *testing.T) {
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	local := time.Date(2026, time.August, 14, 12, 34, 56, 0, time.UTC)
	authority := timeAuthority{key: private, keyID: timeKeyID, issuer: timeIssuer, audience: TimeAudience, answered: local}
	trustRoot := timeTrustRoot(t, public, nil)

	serve := func(t *testing.T, answer func(t *testing.T, challenge string) ([]byte, int)) *httptest.Server {
		t.Helper()
		server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			body, status := answer(t, request.Header.Get(NonceHeader))
			response.Header().Set("Content-Type", TimeStatementType)
			response.WriteHeader(status)
			_, _ = response.Write(body)
		}))
		t.Cleanup(server.Close)
		return server
	}
	sourceFor := func(t *testing.T, server *httptest.Server, root string) *HTTPTimeSource {
		t.Helper()
		source, err := NewHTTPTimeSource(server.URL, root, timeIssuer, server.Client(), &localTime{value: local})
		if err != nil {
			t.Fatal(err)
		}
		return source
	}

	t.Run("a signed statement answering the challenge is accepted", func(t *testing.T) {
		var challenges []string
		server := serve(t, func(t *testing.T, challenge string) ([]byte, int) {
			challenges = append(challenges, challenge)
			return authority.statement(t, challenge), http.StatusOK
		})
		source := sourceFor(t, server, trustRoot)
		got, err := source.Now(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if !got.Equal(local) {
			t.Fatalf("Now() = %s, want %s", got, local)
		}
		if _, err := source.Now(context.Background()); err != nil {
			t.Fatal(err)
		}
		// Every decision carries its own challenge, so no single recorded
		// answer is usable twice.
		if len(challenges) != 2 || challenges[0] == "" || challenges[0] == challenges[1] {
			t.Fatalf("the source reused its challenge: %v", challenges)
		}
	})

	// Every one of these is an answer that arrived. None of them is a reason
	// to ask again: the same answer fails the same way, and retrying only
	// gives whatever produced it another turn.
	for name, tampered := range map[string]timeAuthority{
		"a signature that does not verify":                  {key: private, keyID: timeKeyID, issuer: timeIssuer, audience: TimeAudience, answered: local, corrupt: true},
		"a key the trust root does not hold":                {key: private, keyID: "urn:anvilkit:key:impostor", issuer: timeIssuer, audience: TimeAudience, answered: local},
		"an authority this deployment does not trust":       {key: private, keyID: timeKeyID, issuer: "urn:anvilkit:issuer:somebody-else", audience: TimeAudience, answered: local},
		"a statement addressed elsewhere":                   {key: private, keyID: timeKeyID, issuer: timeIssuer, audience: "urn:anvilkit:audience:other", answered: local},
		"a statement of another kind":                       {key: private, keyID: timeKeyID, issuer: timeIssuer, audience: TimeAudience, answered: local, kind: "SomethingElse"},
		"a replayed statement answering an older challenge": {key: private, keyID: timeKeyID, issuer: timeIssuer, audience: TimeAudience, answered: local, nonce: "0123456789abcdef0123456789abcdef"},
	} {
		t.Run(name+" is refused and is never retryable", func(t *testing.T) {
			server := serve(t, func(t *testing.T, challenge string) ([]byte, int) {
				return tampered.statement(t, challenge), http.StatusOK
			})
			_, err := sourceFor(t, server, trustRoot).Now(context.Background())
			if err == nil {
				t.Fatal("an unauthenticated time statement was accepted")
			}
			var untrusted TimeUntrusted
			if !errors.As(err, &untrusted) {
				t.Fatalf("the refusal is not reported as untrusted time: %v", err)
			}
			if Retryable(err) {
				t.Fatalf("an untrusted time statement was reported as retryable: %v", err)
			}
			details, governed := GovernedTimeFailure(err)
			if !governed || details.Code != string(problem.CodeAuthorityStale) || details.Retryability != "never" {
				t.Fatalf("the governed answer for a tampered statement is %+v", details)
			}
		})
	}

	// A key the operator has withdrawn stops working on the next decision,
	// because the trust root is read on every one of them.
	t.Run("a withdrawn key stops being accepted without a restart", func(t *testing.T) {
		server := serve(t, func(t *testing.T, challenge string) ([]byte, int) {
			return authority.statement(t, challenge), http.StatusOK
		})
		withdrawn := timeTrustRoot(t, public, func(root *trust.Root) { root.Keys[0].Status = "revoked" })
		if _, err := sourceFor(t, server, withdrawn).Now(context.Background()); err == nil {
			t.Fatal("a statement signed by a withdrawn key was accepted")
		}
	})

	// And an authority that cannot be reached is a different answer
	// altogether: nothing is known about the time, waiting may fix it, and
	// the governed problem says so.
	for name, answer := range map[string]func(t *testing.T, challenge string) ([]byte, int){
		"an authority that answers an error": func(*testing.T, string) ([]byte, int) {
			return nil, http.StatusServiceUnavailable
		},
		"an authority that answers nothing": func(*testing.T, string) ([]byte, int) {
			return nil, http.StatusOK
		},
	} {
		t.Run(name+" is retryable", func(t *testing.T) {
			server := serve(t, answer)
			_, err := sourceFor(t, server, trustRoot).Now(context.Background())
			if err == nil {
				t.Fatal("an outage produced a time")
			}
			// An empty body is an answer that arrived and proves nothing, so
			// it is untrusted; a refused request never arrived at all.
			details, governed := GovernedTimeFailure(err)
			if !governed {
				t.Fatalf("an outage produced an ungoverned failure: %v", err)
			}
			if details.Code != string(problem.CodeInfrastructureUnavailable) && details.Code != string(problem.CodeAuthorityStale) {
				t.Fatalf("an outage produced %+v", details)
			}
		})
	}

	t.Run("an unreachable authority is retryable", func(t *testing.T) {
		server := serve(t, func(t *testing.T, challenge string) ([]byte, int) {
			return authority.statement(t, challenge), http.StatusOK
		})
		source := sourceFor(t, server, trustRoot)
		server.Close()
		_, err := source.Now(context.Background())
		if err == nil {
			t.Fatal("an unreachable authority produced a time")
		}
		if !Retryable(err) {
			t.Fatalf("an outage was not reported as retryable: %v", err)
		}
		details, governed := GovernedTimeFailure(err)
		if !governed || details.Code != string(problem.CodeInfrastructureUnavailable) || details.Retryability == "never" {
			t.Fatalf("the governed answer for an outage is %+v", details)
		}
	})

	// A source with no trust material, or no declared authority, is refused
	// at construction: a time source that cannot say which authority it
	// trusts is one that trusts whoever answers.
	t.Run("an unauthenticated source cannot be built", func(t *testing.T) {
		server := serve(t, func(t *testing.T, challenge string) ([]byte, int) {
			return authority.statement(t, challenge), http.StatusOK
		})
		if _, err := NewHTTPTimeSource(server.URL, "", timeIssuer, server.Client(), &localTime{value: local}); err == nil {
			t.Fatal("a time source with no trust root was built")
		}
		if _, err := NewHTTPTimeSource(server.URL, trustRoot, "", server.Client(), &localTime{value: local}); err == nil {
			t.Fatal("a time source with no declared authority was built")
		}
	})
}

// The clock separates a dependency that is down from an answer that is wrong,
// and the fail-closed adapter carries that distinction to callers that only
// see a zero instant.
func TestTheClockDistinguishesAnOutageFromATamperedAnswer(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	t.Run("an outage is retryable and says so through the adapter", func(t *testing.T) {
		source := &testTime{err: TimeUnavailable{Err: errors.New("dial: connection refused")}}
		authority, err := NewAuthoritativeClock(source, &localTime{value: now}, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		clock := NewFailClosedClock(authority)
		if value := clock.Now(); !value.IsZero() {
			t.Fatalf("an outage produced a time: %s", value)
		}
		if !Retryable(clock.LastFailure()) {
			t.Fatalf("the adapter lost the retryability of an outage: %v", clock.LastFailure())
		}
		var details problem.Details
		if !errors.As(TimeRefusal(clock), &details) || details.Code != string(problem.CodeInfrastructureUnavailable) {
			t.Fatalf("an outage refused as %+v", details)
		}
	})

	t.Run("skew beyond the bound is never retryable", func(t *testing.T) {
		source := &testTime{value: now.Add(time.Hour)}
		authority, err := NewAuthoritativeClock(source, &localTime{value: now}, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		clock := NewFailClosedClock(authority)
		if value := clock.Now(); !value.IsZero() {
			t.Fatalf("an answer beyond the skew bound produced a time: %s", value)
		}
		if Retryable(clock.LastFailure()) {
			t.Fatalf("skew was reported as retryable: %v", clock.LastFailure())
		}
		var details problem.Details
		if !errors.As(TimeRefusal(clock), &details) || details.Code != string(problem.CodeAuthorityStale) {
			t.Fatalf("skew refused as %+v", details)
		}
	})

	t.Run("an authority that answers earlier than it already had is never retryable", func(t *testing.T) {
		source := &testTime{value: now}
		authority, err := NewAuthoritativeClock(source, &localTime{value: now}, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		clock := NewFailClosedClock(authority)
		if value := clock.Now(); value.IsZero() {
			t.Fatal("the first reading was refused")
		}
		source.value = now.Add(-time.Minute)
		if value := clock.Now(); !value.IsZero() {
			t.Fatalf("a rolled-back answer produced a time: %s", value)
		}
		if Retryable(clock.LastFailure()) {
			t.Fatalf("a rollback was reported as retryable: %v", clock.LastFailure())
		}
	})

	t.Run("a clock that recovers stops reporting a failure", func(t *testing.T) {
		source := &testTime{err: TimeUnavailable{Err: errors.New("dial: connection refused")}}
		authority, err := NewAuthoritativeClock(source, &localTime{value: now}, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		clock := NewFailClosedClock(authority)
		clock.Now()
		source.err, source.value = nil, now
		if value := clock.Now(); value.IsZero() {
			t.Fatal("a recovered authority still refused")
		}
		if clock.LastFailure() != nil {
			t.Fatalf("a recovered clock still reports %v", clock.LastFailure())
		}
	})
}
