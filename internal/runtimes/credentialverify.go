package runtimes

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/contracts/generated/schema"
	"github.com/ancyloce/anvilkit-agent-service/internal/eligibility"
	"github.com/ancyloce/anvilkit-agent-service/internal/trust"
)

// maximumCredentialBytes bounds what a verifier will read as a credential. The
// claim set is fixed and small; anything larger is not a credential this format
// can produce.
const maximumCredentialBytes = 8192

// CredentialTrustSource supplies the trust root a presented task credential is
// resolved against.
type CredentialTrustSource interface {
	Root() ([]byte, error)
	eligibility.ProductionEligibility
}

// FileCredentialTrust reads the operator-distributed credential trust root from
// disk on every verification.
type FileCredentialTrust struct{ path string }

// NewFileCredentialTrust binds a verifier to the operator's document.
func NewFileCredentialTrust(path string) (*FileCredentialTrust, error) {
	if path == "" {
		return nil, fmt.Errorf("task credential trust: a trust root path is required")
	}
	return &FileCredentialTrust{path: path}, nil
}

// Eligibility declares this source fit for production: it reads real operator
// material distributed independently of the service that mints credentials.
func (*FileCredentialTrust) Eligibility() eligibility.Eligibility {
	return eligibility.ProductionEligible
}

func (f *FileCredentialTrust) Root() ([]byte, error) { return os.ReadFile(f.path) }

// CredentialTrust resolves the key a task credential was signed with.
//
// The trust root is operator-distributed material, read fresh on every
// verification rather than cached at start: a key is revoked, a snapshot passes
// its freshness bound, and a validity interval ends, all while a process keeps
// running. Verifying once at startup would only prove the material was good
// when the process began.
type CredentialTrust struct {
	source CredentialTrustSource
}

// NewCredentialTrust binds a verifier to a source of the operator's trust root.
func NewCredentialTrust(source CredentialTrustSource) (*CredentialTrust, error) {
	if source == nil {
		return nil, fmt.Errorf("task credential trust: a trust root source is required")
	}
	return &CredentialTrust{source: source}, nil
}

// Eligibility is the trust source's own declaration: a verifier is exactly as
// production-fit as the material it reads.
func (c *CredentialTrust) Eligibility() eligibility.Eligibility {
	return eligibility.EligibilityOf(c.source)
}

// VerifiedCredential is what a presented credential proved about itself.
type VerifiedCredential struct {
	KeyID    string
	Audience string
	Binding  Binding
	Expiry   time.Time
}

// Verify proves a presented credential and returns what it binds.
//
// Nothing about the token is believed before its signature verifies: the
// claimed key identity selects a candidate key from the operator's trust root,
// and only a signature that verifies under that key makes any claim readable.
// The audience is checked against the release the token was presented to, so a
// credential minted for one runtime cannot be replayed at another.
func (c *CredentialTrust) Verify(token, audience string, now time.Time) (VerifiedCredential, error) {
	if audience == "" {
		return VerifiedCredential{}, fmt.Errorf("task credential: the accepting release names no audience")
	}
	if len(token) == 0 || len(token) > maximumCredentialBytes {
		return VerifiedCredential{}, fmt.Errorf("task credential: the credential is empty or unbounded")
	}
	header, payload, signature, signingInput, err := splitCredential(token)
	if err != nil {
		return VerifiedCredential{}, err
	}
	var joseHeader struct {
		Algorithm string `json:"alg"`
		KeyID     string `json:"kid"`
		Type      string `json:"typ"`
	}
	if err := trust.DecodeJSON(header, &joseHeader); err != nil {
		return VerifiedCredential{}, fmt.Errorf("task credential: decode header: %w", err)
	}
	// The algorithm and type are fixed by the format. Reading them from the
	// token and then honouring whatever they said is how a verifier ends up
	// accepting "alg":"none"; here they must equal the only values this format
	// has, and the key is resolved for that algorithm and no other.
	if joseHeader.Algorithm != CredentialAlgorithm || joseHeader.Type != CredentialType {
		return VerifiedCredential{}, fmt.Errorf("task credential: the credential is not an %s %s", CredentialAlgorithm, CredentialType)
	}
	if joseHeader.KeyID == "" {
		return VerifiedCredential{}, fmt.Errorf("task credential: the credential names no signing key")
	}

	rootBytes, err := c.source.Root()
	if err != nil {
		return VerifiedCredential{}, fmt.Errorf("task credential: read trust root: %w", err)
	}
	root, skew, err := trust.ParseRoot(rootBytes, now, "task credential")
	if err != nil {
		return VerifiedCredential{}, err
	}
	key, err := trust.ResolveKey(root, trust.KeyRequest{
		KeyID:     joseHeader.KeyID,
		Issuer:    CredentialIssuer,
		Audience:  audience,
		Algorithm: CredentialAlgorithm,
	}, now, skew, "task credential")
	if err != nil {
		return VerifiedCredential{}, err
	}
	if !ed25519.Verify(key, []byte(signingInput), signature) {
		return VerifiedCredential{}, fmt.Errorf("task credential: the credential signature does not verify")
	}

	var claims struct {
		Issuer    string  `json:"iss"`
		Audience  string  `json:"aud"`
		Subject   string  `json:"sub"`
		TokenID   string  `json:"jti"`
		IssuedAt  int64   `json:"iat"`
		NotBefore int64   `json:"nbf"`
		Expiry    int64   `json:"exp"`
		Binding   Binding `json:"urn:anvilkit:claim:task-binding"`
	}
	if err := trust.DecodeJSON(payload, &claims); err != nil {
		return VerifiedCredential{}, fmt.Errorf("task credential: decode claims: %w", err)
	}
	if claims.Issuer != CredentialIssuer {
		return VerifiedCredential{}, fmt.Errorf("task credential: the credential was not issued by this control plane")
	}
	if claims.Audience != audience {
		return VerifiedCredential{}, fmt.Errorf("task credential: the credential was issued to another release")
	}
	if claims.Subject != "urn:anvilkit:attempt:"+claims.Binding.PhysicalAttemptID || claims.TokenID != claims.Binding.PhysicalAttemptID {
		return VerifiedCredential{}, fmt.Errorf("task credential: the credential subject is not the attempt it binds")
	}
	if claims.IssuedAt <= 0 || claims.NotBefore <= 0 || claims.Expiry <= claims.NotBefore {
		return VerifiedCredential{}, fmt.Errorf("task credential: the credential validity interval is malformed")
	}
	notBefore, expiry := time.Unix(claims.NotBefore, 0).UTC(), time.Unix(claims.Expiry, 0).UTC()
	if now.Add(skew).Before(notBefore) {
		return VerifiedCredential{}, fmt.Errorf("task credential: the credential is not yet valid")
	}
	if !now.Add(-skew).Before(expiry) {
		return VerifiedCredential{}, fmt.Errorf("task credential: the credential has expired")
	}
	switch claims.Binding.Operation {
	case OperationExecute, OperationCancel:
	default:
		return VerifiedCredential{}, fmt.Errorf("task credential: the credential authorizes no governed operation")
	}
	return VerifiedCredential{KeyID: joseHeader.KeyID, Audience: claims.Audience, Binding: claims.Binding, Expiry: expiry}, nil
}

// BindsTask reports why a verified credential is not authority for the task it
// was presented with, or the empty string when it is.
//
// A verified signature proves only that this control plane issued the token. It
// says nothing about whether the token was issued for the work now being asked
// for, which is the whole point of separating the two checks: a valid
// credential for another attempt is exactly what a replay looks like.
func BindsTask(verified VerifiedCredential, task schema.AgentTask, operation string) string {
	if verified.Binding.Operation != operation {
		return "the credential does not authorize this operation"
	}
	if verified.Audience != task.AuthorizationAudience {
		return "the credential and the task name different audiences"
	}
	if verified.Binding.WorkspaceID == "" || verified.Binding.ProjectID == "" {
		return "the credential names no tenant boundary to execute inside"
	}
	for _, comparison := range []struct{ credential, task string }{
		{verified.Binding.RunID, string(task.RunId)},
		{verified.Binding.RootRunID, string(task.RootRunId)},
		{verified.Binding.TaskID, string(task.TaskId)},
		{verified.Binding.PhysicalAttemptID, string(task.PhysicalAttemptId)},
		{verified.Binding.RuntimeUnitID, string(task.RuntimeBinding.RuntimeUnitId)},
		{verified.Binding.RuntimeManifestDigest, string(task.RuntimeBinding.RuntimeManifestDigest)},
		{verified.Binding.InvocationProtocolDigest, string(task.RuntimeBinding.InvocationProtocolDigest)},
	} {
		if comparison.credential != comparison.task {
			return "the credential was issued for a different attempt"
		}
	}
	for _, comparison := range []struct {
		credential uint64
		task       int
	}{
		{verified.Binding.AttemptNumber, task.AttemptNumber},
		{verified.Binding.ExecutionGeneration, task.ExecutionGeneration},
		{verified.Binding.LeaseEpoch, task.LeaseEpoch},
	} {
		if comparison.task < 0 || comparison.credential != uint64(comparison.task) {
			return "the credential was issued for a different attempt"
		}
	}
	return ""
}

// splitCredential takes a compact JWS apart without believing any of it. The
// signing input is returned as it arrived: a verifier that re-encoded the
// header and payload would prove a signature over bytes it built rather than
// over the bytes it received.
func splitCredential(token string) (header, payload, signature []byte, signingInput string, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return nil, nil, nil, "", fmt.Errorf("task credential: the credential is not a compact JWS")
	}
	if header, err = base64.RawURLEncoding.DecodeString(parts[0]); err != nil {
		return nil, nil, nil, "", fmt.Errorf("task credential: the credential header is not base64url")
	}
	if payload, err = base64.RawURLEncoding.DecodeString(parts[1]); err != nil {
		return nil, nil, nil, "", fmt.Errorf("task credential: the credential claims are not base64url")
	}
	if signature, err = base64.RawURLEncoding.DecodeString(parts[2]); err != nil || len(signature) != ed25519.SignatureSize {
		return nil, nil, nil, "", fmt.Errorf("task credential: the credential signature is malformed")
	}
	return header, payload, signature, parts[0] + "." + parts[1], nil
}
