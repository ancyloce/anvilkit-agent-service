package securityaudit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/trust"
)

// TimeStatementType is the DSSE payload type of a signed time statement.
const TimeStatementType = "application/vnd.anvilkit.authoritative-time-statement+json"

// TimeAudience is the only audience an agent-service accepts a time statement
// for.
const TimeAudience = "urn:anvilkit:audience:agent-service"

const timeAlgorithm = "dsse-ed25519-v1"

// NonceHeader carries the client's challenge to the time authority, and the
// statement echoes it. Without it a recorded response is a usable answer
// forever: an attacker who can serve one old signed statement can hold the
// service's idea of the time still, which is precisely what the skew and
// rollback checks are there to notice and precisely what they would fail to
// notice if the statement were genuinely signed and merely old.
const NonceHeader = "X-AnvilKit-Time-Nonce"

// TimeStatement is the signed claim of what time it is.
type TimeStatement struct {
	Kind      string `json:"kind"`
	Algorithm string `json:"algorithm"`
	Issuer    string `json:"issuer"`
	Audience  string `json:"audience"`
	KeyID     string `json:"keyId"`
	Nonce     string `json:"nonce"`
	UTC       string `json:"utc"`
}

// TimeStatementKind is the only statement kind accepted.
const TimeStatementKind = "AuthoritativeTimeStatement"

// TimeUnavailable reports that the time authority could not be reached or
// could not answer. It is deliberately distinct from a statement that was
// answered and refused.
//
// The difference decides what a caller does next, and getting it wrong is how
// an outage becomes an incident. An unreachable authority says nothing about
// whether the service's decisions are sound; the right response is to stop,
// wait, and ask again, and the governed answer is a retryable one. A statement
// that arrived and failed its checks is the opposite: something answered for
// the time authority and could not prove it was the time authority, or proved
// it and gave an answer outside the bounds. Retrying that is not waiting for a
// network to recover — it is asking a possibly hostile answer again — so it is
// never retryable.
type TimeUnavailable struct{ Err error }

func (e TimeUnavailable) Error() string { return "authoritative time is unavailable: " + e.Err.Error() }
func (e TimeUnavailable) Unwrap() error { return e.Err }

// Problem renders the governed answer a temporary time-authority failure
// carries: the dependency is unavailable, and the caller may try again.
func (e TimeUnavailable) Problem() problem.Details {
	details := problem.New(problem.CodeInfrastructureUnavailable, "")
	details.Detail = "the approved time authority is unreachable"
	return details
}

// TimeUntrusted reports a statement that arrived and did not prove itself.
// It is never retryable: the same answer will fail the same way, and asking
// again only gives whatever produced it another chance.
type TimeUntrusted struct{ Err error }

func (e TimeUntrusted) Error() string { return "authoritative time is untrusted: " + e.Err.Error() }
func (e TimeUntrusted) Unwrap() error { return e.Err }

// Problem renders the governed answer an unauthenticated or tampered time
// statement carries.
func (e TimeUntrusted) Problem() problem.Details {
	details := problem.New(problem.CodeAuthorityStale, "")
	details.Detail = "the time authority's answer could not be authenticated"
	return details
}

// Retryable reports whether a time failure is one waiting can fix.
func Retryable(err error) bool {
	var unavailable TimeUnavailable
	return errors.As(err, &unavailable)
}

// GovernedTimeFailure renders the governed problem one time failure carries,
// and reports whether there was one to render. Callers use it so an outage
// reaches a client as a retryable dependency failure rather than as a denial
// the client can do nothing about.
func GovernedTimeFailure(err error) (problem.Details, bool) {
	var unavailable TimeUnavailable
	if errors.As(err, &unavailable) {
		return unavailable.Problem(), true
	}
	var untrusted TimeUntrusted
	if errors.As(err, &untrusted) {
		return untrusted.Problem(), true
	}
	return problem.Details{}, false
}

// HTTPTimeSource reads authenticated time from the approved time authority.
//
// The authority signs its answer and the service verifies it against an
// operator-distributed trust root, which is the same material the approved
// definition catalog is verified against. Before this, the source believed
// whatever answered on the configured address: the time came from a Date
// header, which any host — a misdirected DNS answer, a proxy, anything on the
// path — can produce. Every security decision the service stamps, orders, and
// expires is made on this value, so an unauthenticated answer is an
// unauthenticated authorization boundary.
//
// The endpoint is queried for every decision so an outage cannot silently
// fall back to the host clock.
type HTTPTimeSource struct {
	url           string
	client        *http.Client
	trustRootPath string
	// trustRef is the issuer identity the operator declared for this
	// endpoint. A statement signed by a key the trust root holds, but issued
	// by a different authority than the one this deployment was pointed at,
	// is refused: the trust root says who may sign, and this says which of
	// them this deployment is talking to.
	trustRef string
	local    LocalClock
}

// NewHTTPTimeSource builds the authenticated source. The trust root path and
// the declared authority identity are required: a time source that cannot say
// which authority it trusts is one that trusts whoever answers.
func NewHTTPTimeSource(endpoint, trustRootPath, trustRef string, client *http.Client, local LocalClock) (*HTTPTimeSource, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, fmt.Errorf("authoritative time endpoint must be an absolute HTTP URL")
	}
	if client == nil {
		return nil, fmt.Errorf("authoritative time HTTP client is required")
	}
	if trustRootPath == "" {
		return nil, fmt.Errorf("authoritative time requires the operator-distributed trust root that authenticates it")
	}
	if trustRef == "" {
		return nil, fmt.Errorf("authoritative time requires the declared authority identity its statements must assert")
	}
	if local == nil {
		return nil, fmt.Errorf("authoritative time requires a local clock to bound its trust material against")
	}
	return &HTTPTimeSource{url: parsed.String(), client: client, trustRootPath: trustRootPath, trustRef: trustRef, local: local}, nil
}

func (s *HTTPTimeSource) Now(ctx context.Context) (time.Time, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return time.Time{}, TimeUnavailable{Err: fmt.Errorf("open time challenge: %w", err)}
	}
	challenge := hex.EncodeToString(nonce)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		return time.Time{}, TimeUnavailable{Err: fmt.Errorf("create authoritative time request: %w", err)}
	}
	request.Header.Set(NonceHeader, challenge)
	request.Header.Set("Accept", TimeStatementType)
	response, err := s.client.Do(request)
	if err != nil {
		return time.Time{}, TimeUnavailable{Err: fmt.Errorf("query authoritative time: %w", err)}
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return time.Time{}, TimeUnavailable{Err: fmt.Errorf("query authoritative time: unexpected status %d", response.StatusCode)}
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, trust.MaximumEnvelopeBytes+1))
	if err != nil {
		return time.Time{}, TimeUnavailable{Err: fmt.Errorf("read authoritative time statement: %w", err)}
	}
	if len(body) > trust.MaximumEnvelopeBytes {
		return time.Time{}, TimeUntrusted{Err: fmt.Errorf("the time statement exceeds its bound")}
	}
	// The trust root is read on every decision rather than cached. An
	// operator who withdraws a key is withdrawing it now, and a source that
	// held its trust material in memory would keep honouring that key until
	// the process happened to restart.
	trustRootBytes, err := os.ReadFile(s.trustRootPath)
	if err != nil {
		return time.Time{}, TimeUnavailable{Err: fmt.Errorf("read authoritative time trust root: %w", err)}
	}
	// The trust material's own freshness and validity windows are bounded
	// against the local clock, because the authoritative one is exactly what
	// is being established. That is not circular: the local clock decides
	// only whether the operator's material has expired, never what time it is.
	value, err := VerifyTimeStatement(trustRootBytes, body, s.trustRef, challenge, s.local.Now().UTC())
	if err != nil {
		return time.Time{}, err
	}
	return value, nil
}

// VerifyTimeStatement authenticates one signed time statement and answers the
// instant it asserts. It fails closed on an unknown, inactive, expired, or
// wrong-purpose key, on a signature that does not verify, on a statement
// issued by an authority other than the one this deployment trusts, and on a
// statement that does not answer the challenge that was sent.
func VerifyTimeStatement(trustRootBytes, envelopeBytes []byte, trustRef, nonce string, materialNow time.Time) (time.Time, error) {
	if trustRef == "" || nonce == "" {
		return time.Time{}, TimeUntrusted{Err: fmt.Errorf("a declared authority and an issued challenge are required")}
	}
	root, skew, err := trust.ParseRoot(trustRootBytes, materialNow, "authoritative time")
	if err != nil {
		return time.Time{}, TimeUntrusted{Err: err}
	}
	payload, signature, envelopeKeyID, err := trust.OpenEnvelope(envelopeBytes, TimeStatementType, "authoritative time")
	if err != nil {
		return time.Time{}, TimeUntrusted{Err: err}
	}
	var statement TimeStatement
	if err := trust.DecodeJSON(payload, &statement); err != nil {
		return time.Time{}, TimeUntrusted{Err: fmt.Errorf("authoritative time: decode statement: %w", err)}
	}
	if statement.Kind != TimeStatementKind || statement.Algorithm != timeAlgorithm {
		return time.Time{}, TimeUntrusted{Err: fmt.Errorf("authoritative time: the statement kind or algorithm is outside the accepted profile")}
	}
	if statement.Audience != TimeAudience {
		return time.Time{}, TimeUntrusted{Err: fmt.Errorf("authoritative time: the statement is not addressed to this service")}
	}
	if statement.Issuer != trustRef {
		return time.Time{}, TimeUntrusted{Err: fmt.Errorf("authoritative time: the statement is issued by an authority this deployment does not trust")}
	}
	if statement.Nonce != nonce {
		return time.Time{}, TimeUntrusted{Err: fmt.Errorf("authoritative time: the statement does not answer the challenge that was sent")}
	}
	if statement.KeyID == "" || statement.KeyID != envelopeKeyID {
		return time.Time{}, TimeUntrusted{Err: fmt.Errorf("authoritative time: the envelope key identity does not match the statement")}
	}
	key, err := trust.ResolveKey(root, trust.KeyRequest{KeyID: statement.KeyID, Issuer: statement.Issuer, Audience: statement.Audience, Algorithm: timeAlgorithm}, materialNow, skew, "authoritative time")
	if err != nil {
		return time.Time{}, TimeUntrusted{Err: err}
	}
	if !trust.Verify(key, TimeStatementType, payload, signature) {
		return time.Time{}, TimeUntrusted{Err: fmt.Errorf("authoritative time: the statement signature does not verify")}
	}
	value, err := time.Parse(trust.Timestamp, statement.UTC)
	if err != nil {
		return time.Time{}, TimeUntrusted{Err: fmt.Errorf("authoritative time: the asserted instant is malformed")}
	}
	return value.UTC(), nil
}

var _ TimeSource = (*HTTPTimeSource)(nil)
