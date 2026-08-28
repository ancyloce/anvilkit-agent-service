package runtimes

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/contracts/generated/schema"
	"github.com/ancyloce/anvilkit-agent-service/internal/canonical"
)

// Subject is the tenant boundary a task-scoped credential is issued inside.
// It is passed in rather than read from the task because the canonical task
// carries no tenancy: what a runtime is allowed to act on comes from the
// credential it was handed, not from the document it was handed.
type Subject struct{ WorkspaceID, ProjectID string }

// The canonical runtime boundary description declares the task credential as a
// bearer JWT. These constants are the whole of that format, and the runtime's
// verifier implements the same three of them independently — the two processes
// are in different repositories and cannot share code, so the known-answer
// vector in testdata is what holds the two implementations to one format.
const (
	// CredentialAlgorithm is the JWS algorithm (RFC 8037 Ed25519). It is
	// asymmetric on purpose: a symmetric credential would give every runtime
	// holding the verification key the ability to mint credentials for every
	// other runtime, which is precisely the authority expansion the execution
	// boundary exists to prevent.
	CredentialAlgorithm = "EdDSA"
	// CredentialType is the JOSE type header. A distinct type stops a token
	// minted for this purpose from being replayed as any other kind of JWT the
	// same key might one day sign.
	CredentialType = "anvilkit-task-credential+jwt"
	// CredentialIssuer is the Agent Service identity every task credential is
	// issued under. A runtime resolves the verification key against this
	// identity, so a key approved for a different issuer cannot mint tasks.
	CredentialIssuer = "urn:anvilkit:service:agent-service"
	// CredentialBindingClaim is the private claim carrying everything the
	// credential is bound to beyond the registered claims. It is namespaced so
	// it cannot collide with a registered claim name.
	CredentialBindingClaim = "urn:anvilkit:claim:task-binding"

	// OperationExecute and OperationCancel are the only operations a task
	// credential may authorize. A credential issued to execute an attempt
	// cannot cancel one, and neither can do anything else.
	OperationExecute = "execute"
	OperationCancel  = "cancel"
)

// TaskCredentials issues the short-lived authority one physical attempt is
// dispatched with.
//
// The credential is a signed statement about exactly one attempt: the audience
// of the release executing it, the run, logical task, physical attempt,
// generation and lease epoch it belongs to, the manifest and protocol digests
// that release must answer as, the tenant it acts inside, and the one operation
// it authorizes. It expires with the attempt.
//
// Nothing else is derivable from it, and it authenticates nothing else — a
// credential presented for another attempt verifies as a credential for the
// attempt it names, which is not the one being executed.
type TaskCredentials struct {
	key    ed25519.PrivateKey
	keyID  string
	ttl    time.Duration
	now    func() time.Time
	header string
}

// NewTaskCredentials binds the issuer to the deployment's own signing key.
//
// The seed is the private half of an Ed25519 key whose public half the operator
// distributes to runtimes in their credential trust root. A deployment that
// cannot name its key refuses to issue: a credential whose key a runtime cannot
// resolve is not verifiable, and an unverifiable credential is not authority.
func NewTaskCredentials(seed string, keyID string, ttl time.Duration, now func() time.Time) (*TaskCredentials, error) {
	material, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(seed))
	if err != nil || len(material) != ed25519.SeedSize {
		return nil, fmt.Errorf("task credentials: the signing key must be a base64url Ed25519 seed")
	}
	// The key identity is the governed urn:anvilkit:key shape every signing key
	// in this service uses, checked by the same predicate rather than a second
	// spelling of it.
	if !ValidKeyIdentity(keyID) {
		return nil, fmt.Errorf("task credentials: the signing key must carry a governed urn:anvilkit:key identity")
	}
	if ttl <= 0 || now == nil {
		return nil, fmt.Errorf("task credentials: a positive lifetime and a clock are both required")
	}
	// The header is fixed for the life of the issuer, so it is canonicalized
	// once. Its bytes are part of what is signed, which is why they are built
	// from a canonical form rather than from whatever order a marshaller
	// happened to choose.
	header, err := canonical.Bytes([]byte(fmt.Sprintf(
		`{"alg":%q,"kid":%q,"typ":%q}`, CredentialAlgorithm, keyID, CredentialType)))
	if err != nil {
		return nil, fmt.Errorf("task credentials: build the credential header: %w", err)
	}
	return &TaskCredentials{
		key:    ed25519.NewKeyFromSeed(material),
		keyID:  keyID,
		ttl:    ttl,
		now:    now,
		header: base64.RawURLEncoding.EncodeToString(header),
	}, nil
}

// NewSeededTaskCredentials derives the issuing key from arbitrary deployment
// material rather than taking a key directly.
//
// It exists for the same reason the stand-in runtime's signer does: a
// composition with no separate runtime process has no operator-distributed
// credential key to mount, and issuing unsigned credentials so that the
// admission path has something to not-verify would make the controlled
// composition prove less than production does. Production configures a real
// key; this derives a stable one so the same verification runs either way.
func NewSeededTaskCredentials(material, keyID string, ttl time.Duration, now func() time.Time) (*TaskCredentials, error) {
	if len(material) < 16 {
		return nil, fmt.Errorf("task credentials: seed material of at least 16 characters is required")
	}
	seed := sha256.Sum256([]byte("anvilkit/task-credential-issuer\x00" + material))
	return NewTaskCredentials(base64.RawURLEncoding.EncodeToString(seed[:]), keyID, ttl, now)
}

// PublicKey is the verification half a runtime resolves this issuer's
// credentials against. It is exported so a composition that runs both halves in
// one process can build the runtime's trust material from the same key rather
// than from a second copy that could drift.
func (t *TaskCredentials) PublicKey() ed25519.PublicKey {
	return t.key.Public().(ed25519.PublicKey)
}

// KeyID is the identity a verifier resolves the public key by.
func (t *TaskCredentials) KeyID() string { return t.keyID }

// Binding is what a credential binds beyond the registered JWT claims. Every
// field is compared against the task the runtime was handed: a credential is
// authority for one attempt of one task on one release, and a field that did
// not have to match would be a field an attacker could vary.
type Binding struct {
	Operation                string `json:"operation"`
	WorkspaceID              string `json:"workspaceId"`
	ProjectID                string `json:"projectId"`
	RunID                    string `json:"runId"`
	RootRunID                string `json:"rootRunId"`
	TaskID                   string `json:"taskId"`
	PhysicalAttemptID        string `json:"physicalAttemptId"`
	AttemptNumber            uint64 `json:"attemptNumber"`
	ExecutionGeneration      uint64 `json:"executionGeneration"`
	LeaseEpoch               uint64 `json:"leaseEpoch"`
	RuntimeUnitID            string `json:"runtimeUnitId"`
	RuntimeManifestDigest    string `json:"runtimeManifestDigest"`
	InvocationProtocolDigest string `json:"invocationProtocolDigest"`
}

// Claims are what a credential binds. A released unit reads them by verifying
// the token it was presented; an in-process one reads them here, which is the
// same information by a shorter path.
type Claims struct {
	Subject                               Subject
	RunID, TaskID, PhysicalAttemptID      string
	ExecutionGeneration, LeaseEpoch       uint64
	RuntimeManifestDigest, ProtocolDigest string
}

// Issue mints the credential for one dispatched attempt. It expires with the
// attempt: a credential that outlived the work it was issued for would be
// authority nobody is watching.
func (t *TaskCredentials) Issue(_ context.Context, task schema.AgentTask, subject Subject) (Credential, error) {
	if subject.WorkspaceID == "" || subject.ProjectID == "" {
		return Credential{}, fmt.Errorf("task credentials: a credential is issued inside a tenant boundary")
	}
	issuedAt := t.now().UTC().Truncate(time.Second)
	expiry := issuedAt.Add(t.ttl)
	// A credential never outlives the task it was issued for. The attempt's own
	// deadline is the ceiling: authority that survived the work would be
	// authority with nothing left to authorize.
	if deadline := time.Time(task.ExpiresAt); !deadline.IsZero() && deadline.Before(expiry) {
		expiry = deadline.UTC()
	}
	if !issuedAt.Before(expiry) {
		return Credential{}, fmt.Errorf("task credentials: the attempt has no admission window left to issue authority for")
	}
	binding := Binding{
		Operation:                OperationExecute,
		WorkspaceID:              subject.WorkspaceID,
		ProjectID:                subject.ProjectID,
		RunID:                    string(task.RunId),
		RootRunID:                string(task.RootRunId),
		TaskID:                   string(task.TaskId),
		PhysicalAttemptID:        string(task.PhysicalAttemptId),
		AttemptNumber:            uint64(task.AttemptNumber),
		ExecutionGeneration:      uint64(task.ExecutionGeneration),
		LeaseEpoch:               uint64(task.LeaseEpoch),
		RuntimeUnitID:            string(task.RuntimeBinding.RuntimeUnitId),
		RuntimeManifestDigest:    string(task.RuntimeBinding.RuntimeManifestDigest),
		InvocationProtocolDigest: string(task.RuntimeBinding.InvocationProtocolDigest),
	}
	value, err := t.sign(task.AuthorizationAudience, binding, issuedAt, expiry)
	if err != nil {
		return Credential{}, err
	}
	return Credential{
		Value:     value,
		Audience:  task.AuthorizationAudience,
		ExpiresAt: expiry,
		Claims: Claims{
			Subject:               subject,
			RunID:                 binding.RunID,
			TaskID:                binding.TaskID,
			PhysicalAttemptID:     binding.PhysicalAttemptID,
			ExecutionGeneration:   binding.ExecutionGeneration,
			LeaseEpoch:            binding.LeaseEpoch,
			RuntimeManifestDigest: binding.RuntimeManifestDigest,
			ProtocolDigest:        binding.InvocationProtocolDigest,
		},
	}, nil
}

// sign builds and signs the compact JWS. The signed bytes are the encoded
// header and payload exactly as they travel, which is what lets a verifier
// prove the signature over what it actually received rather than over a
// re-serialization it produced itself.
func (t *TaskCredentials) sign(audience string, binding Binding, issuedAt, expiry time.Time) (string, error) {
	if audience == "" {
		return "", fmt.Errorf("task credentials: a credential names the audience of the release it is issued to")
	}
	document, err := json.Marshal(map[string]any{
		"iss":                  CredentialIssuer,
		"aud":                  audience,
		"sub":                  "urn:anvilkit:attempt:" + binding.PhysicalAttemptID,
		"jti":                  binding.PhysicalAttemptID,
		"iat":                  issuedAt.Unix(),
		"nbf":                  issuedAt.Unix(),
		"exp":                  expiry.Unix(),
		CredentialBindingClaim: binding,
	})
	if err != nil {
		return "", fmt.Errorf("task credentials: encode claims: %w", err)
	}
	payload, err := canonical.Bytes(document)
	if err != nil {
		return "", fmt.Errorf("task credentials: canonicalize claims: %w", err)
	}
	signingInput := t.header + "." + base64.RawURLEncoding.EncodeToString(payload)
	signature := ed25519.Sign(t.key, []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

// ValidKeyIdentity reports whether a value is a governed urn:anvilkit:key
// identity: the shape every signing and credential key this service trusts or
// mints is named by.
func ValidKeyIdentity(value string) bool {
	const prefix = "urn:anvilkit:key:"
	if !strings.HasPrefix(value, prefix) || len(value) < len(prefix)+15 || len(value) > 256 {
		return false
	}
	for index, character := range value[len(prefix):] {
		switch {
		case character >= 'a' && character <= 'z':
		case character >= '0' && character <= '9':
		case (character == ':' || character == '-') && index > 0:
		default:
			return false
		}
	}
	return true
}
