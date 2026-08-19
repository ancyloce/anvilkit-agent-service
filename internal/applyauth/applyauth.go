// Package applyauth owns bounded apply-authorization issuance. It deliberately
// has no redemption or Pagix page-persistence API.
package applyauth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/canonical"
	contractguard "github.com/ancyloce/anvilkit-agent-service/internal/contracts"
	"github.com/ancyloce/anvilkit-agent-service/internal/journal"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
)

const (
	Issuer   = "urn:anvilkit:issuer:agent-service"
	Audience = "urn:anvilkit:audience:pagix"
	Type     = "anvilkit-apply-authorization+jws"
)

type AuthorizationID string

// Command is intentionally bounded to record identities. The signed payload is
// resolved from server-owned authority and cannot be supplied by a caller.
type Command struct {
	WorkspaceID, ProjectID, RunID, ApprovalRequestID, ArtifactID string
}

type Target struct {
	Type        string `json:"targetType"`
	ID          string `json:"targetId"`
	WorkspaceID string `json:"workspaceId"`
	ProjectID   string `json:"projectId"`
}

// Binding is the full approval/apply binding. Authority returns both the
// approved snapshot and current snapshot so issuance can fail closed on drift.
type Binding struct {
	RunID, ActionDigest, ArtifactDigest, BaseRevision string
	Target                                            Target
	ActorID, WorkspaceID                              string
	ApprovalVersion                                   uint64
	ContractBOMDigest, PolicyDigest, DefinitionDigest string
}

type Proof struct {
	Approved, Current Binding
	ApprovalCurrent   bool
	ArtifactEligible  bool
}

type Authority interface {
	Resolve(context.Context, Command) (Proof, error)
}

type IDs interface {
	AuthorizationID() (AuthorizationID, error)
}

// SigningPort exposes signing operations and public verification material, but
// never private key bytes.
type SigningPort interface {
	ActiveKeyID(context.Context) (string, error)
	Sign(context.Context, string, []byte) ([]byte, error)
	PublicKey(context.Context, string) (ed25519.PublicKey, error)
	Revoked(context.Context, string) (bool, error)
}

type Clock interface{ Now() time.Time }

type AuditRecord struct {
	AuthorizationID AuthorizationID
	WorkspaceID     string
	ProjectID       string
	RunID           string
	KeyID           string
	PayloadDigest   string
	TokenDigest     string
	IssuedAt        time.Time
	ExpiresAt       time.Time
}

type Audit interface {
	Record(context.Context, AuditRecord) error
}

type Authorization struct {
	ID        AuthorizationID
	KeyID     string
	Compact   string
	Payload   Payload
	IssuedAt  time.Time
	ExpiresAt time.Time
}

type Payload struct {
	Kind              string          `json:"kind"`
	AuthorizationID   AuthorizationID `json:"authorizationId"`
	KeyID             string          `json:"keyId"`
	Issuer            string          `json:"issuer"`
	Audience          string          `json:"audience"`
	IssuedAt          string          `json:"issuedAt"`
	NotBefore         string          `json:"notBefore"`
	ExpiresAt         string          `json:"expiresAt"`
	RunID             string          `json:"runId"`
	ActionDigest      string          `json:"actionDigest"`
	ArtifactDigest    string          `json:"artifactDigest"`
	Target            Target          `json:"target"`
	BaseRevision      string          `json:"baseRevision"`
	ActorID           string          `json:"actorId"`
	WorkspaceID       string          `json:"workspaceId"`
	ApprovalVersion   uint64          `json:"approvalVersion"`
	ContractBOMDigest string          `json:"contractBomDigest"`
	PolicyDigest      string          `json:"policyDigest"`
	DefinitionDigest  string          `json:"definitionDigest"`
}

type protectedHeader struct {
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
	Type      string `json:"typ"`
}

type IssuerService struct {
	authority Authority
	ids       IDs
	signer    SigningPort
	audit     Audit
	receipts  journal.Store
	guard     *contractguard.Guard
	clock     Clock
	ttl       time.Duration
}

func New(authority Authority, ids IDs, signer SigningPort, audit Audit, receipts journal.Store, guard *contractguard.Guard, clock Clock, ttl time.Duration) (*IssuerService, error) {
	if authority == nil || ids == nil || signer == nil || audit == nil || receipts == nil || guard == nil || clock == nil || ttl <= 0 || ttl > 5*time.Minute {
		return nil, fmt.Errorf("apply authorization dependencies and TTL are invalid")
	}
	return &IssuerService{authority: authority, ids: ids, signer: signer, audit: audit, receipts: receipts, guard: guard, clock: clock, ttl: ttl}, nil
}

func (s *IssuerService) Issue(ctx context.Context, command Command) (Authorization, error) {
	if !opaque(command.WorkspaceID) || !opaque(command.ProjectID) || !opaque(command.RunID) || !opaque(command.ApprovalRequestID) || !opaque(command.ArtifactID) {
		return Authorization{}, denied("bounded issuance command is incomplete")
	}
	proof, err := s.authority.Resolve(ctx, command)
	if err != nil {
		return Authorization{}, err
	}
	if !proof.ApprovalCurrent || !proof.ArtifactEligible || proof.Approved != proof.Current || proof.Current.RunID != command.RunID || proof.Current.WorkspaceID != command.WorkspaceID || proof.Current.Target.WorkspaceID != command.WorkspaceID || !validBinding(proof.Current) {
		return Authorization{}, denied("approval, artifact, target, BOM, or policy binding is stale")
	}
	id, err := s.ids.AuthorizationID()
	if err != nil {
		return Authorization{}, fmt.Errorf("allocate authorization identity: %w", err)
	}
	if !opaque(string(id)) {
		return Authorization{}, fmt.Errorf("allocate authorization identity: invalid identity")
	}
	keyID, err := s.signer.ActiveKeyID(ctx)
	if err != nil {
		return Authorization{}, fmt.Errorf("resolve active authorization key: %w", err)
	}
	if !validKeyID(keyID) {
		return Authorization{}, fmt.Errorf("resolve active authorization key: invalid key ID")
	}
	revoked, err := s.signer.Revoked(ctx, keyID)
	if err != nil || revoked {
		return Authorization{}, denied("active signing key is revoked")
	}
	now := s.clock.Now().UTC().Truncate(time.Millisecond)
	if now.IsZero() {
		return Authorization{}, denied("authoritative time is unavailable")
	}
	expires := now.Add(s.ttl)
	payload := payloadFor(id, keyID, proof.Current, now, expires)
	payloadBytes, err := canonicalJSON(payload)
	if err != nil {
		return Authorization{}, fmt.Errorf("canonicalize authorization payload: %w", err)
	}
	if err := s.guard.Require(ctx, contractguard.PagixOut, applyAuthorizationSchema, payloadBytes); err != nil {
		return Authorization{}, fmt.Errorf("validate apply authorization boundary: %w", err)
	}
	headerBytes, err := canonicalJSON(protectedHeader{Algorithm: "EdDSA", KeyID: keyID, Type: Type})
	if err != nil {
		return Authorization{}, fmt.Errorf("canonicalize authorization header: %w", err)
	}
	header := base64.RawURLEncoding.EncodeToString(headerBytes)
	body := base64.RawURLEncoding.EncodeToString(payloadBytes)
	signingInput := []byte(header + "." + body)
	signature, err := s.signer.Sign(ctx, keyID, signingInput)
	if err != nil {
		return Authorization{}, fmt.Errorf("sign authorization: %w", err)
	}
	if len(signature) != ed25519.SignatureSize {
		return Authorization{}, fmt.Errorf("sign authorization: invalid EdDSA signature size")
	}
	compact := header + "." + body + "." + base64.RawURLEncoding.EncodeToString(signature)
	record := AuditRecord{AuthorizationID: id, WorkspaceID: command.WorkspaceID, ProjectID: command.ProjectID, RunID: command.RunID, KeyID: keyID, PayloadDigest: hash(payloadBytes), TokenDigest: hash([]byte(compact)), IssuedAt: now, ExpiresAt: expires}
	if err := s.audit.Record(ctx, record); err != nil {
		return Authorization{}, fmt.Errorf("durably audit authorization issuance: %w", err)
	}
	authorization := Authorization{ID: id, KeyID: keyID, Compact: compact, Payload: payload, IssuedAt: now, ExpiresAt: expires}
	factBytes, err := canonicalJSON(struct {
		Command       Command       `json:"command"`
		Authorization Authorization `json:"authorization"`
	}{command, authorization})
	if err != nil {
		return Authorization{}, fmt.Errorf("canonicalize authorization receipt: %w", err)
	}
	projection, err := json.Marshal(authorization)
	if err != nil {
		return Authorization{}, fmt.Errorf("marshal authorization receipt projection: %w", err)
	}
	fact, err := journal.NewFact(command.WorkspaceID+":authorization:"+string(id), command.WorkspaceID, command.ProjectID, journal.FactAuthorization, factBytes, projection)
	if err != nil {
		return Authorization{}, err
	}
	if _, err := s.receipts.Append(ctx, fact); err != nil {
		return Authorization{}, fmt.Errorf("authorization fact remains unacknowledged: %w", err)
	}
	return authorization, nil
}

const applyAuthorizationSchema = "anvilkit://schema/apply-authorization?digest=sha256:ad07f9d74ca750dac5b682247ee8109501c4d165aea4d1024f1fa316b92e3e1b"

func payloadFor(id AuthorizationID, keyID string, binding Binding, issued, expires time.Time) Payload {
	return Payload{Kind: "ApplyAuthorization", AuthorizationID: id, KeyID: keyID, Issuer: Issuer, Audience: Audience, IssuedAt: timestamp(issued), NotBefore: timestamp(issued), ExpiresAt: timestamp(expires), RunID: binding.RunID, ActionDigest: binding.ActionDigest, ArtifactDigest: binding.ArtifactDigest, Target: binding.Target, BaseRevision: binding.BaseRevision, ActorID: binding.ActorID, WorkspaceID: binding.WorkspaceID, ApprovalVersion: binding.ApprovalVersion, ContractBOMDigest: binding.ContractBOMDigest, PolicyDigest: binding.PolicyDigest, DefinitionDigest: binding.DefinitionDigest}
}

func validBinding(value Binding) bool {
	return opaque(value.RunID) && validDigest(value.ActionDigest) && validDigest(value.ArtifactDigest) && targetType(value.Target.Type) && opaque(value.Target.ID) && value.Target.WorkspaceID == value.WorkspaceID && opaque(value.Target.ProjectID) && opaque(value.BaseRevision) && opaque(value.ActorID) && opaque(value.WorkspaceID) && value.ApprovalVersion > 0 && validDigest(value.ContractBOMDigest) && validDigest(value.PolicyDigest) && validDigest(value.DefinitionDigest)
}

func opaque(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for index, character := range value {
		if (character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || (index > 0 && strings.ContainsRune("._:-", character)) {
			continue
		}
		return false
	}
	return true
}
func validKeyID(value string) bool {
	if len(value) < 16 || len(value) > 256 || !strings.HasPrefix(value, "urn:anvilkit:key:") {
		return false
	}
	suffix := strings.TrimPrefix(value, "urn:anvilkit:key:")
	if suffix == "" || !((suffix[0] >= 'a' && suffix[0] <= 'z') || (suffix[0] >= '0' && suffix[0] <= '9')) {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == ':' || character == '-' {
			continue
		}
		return false
	}
	return true
}
func targetType(value string) bool {
	if len(value) < 1 || len(value) > 64 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '.' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func canonicalJSON(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return canonical.Bytes(raw)
}

func timestamp(value time.Time) string {
	return value.UTC().Truncate(time.Millisecond).Format("2006-01-02T15:04:05.000Z")
}

func hash(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func validDigest(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, character := range value[7:] {
		if !strings.ContainsRune("0123456789abcdef", character) {
			return false
		}
	}
	return true
}

func denied(detail string) problem.Details {
	value := problem.New(problem.CodeApplyAuthorizationDenied, "")
	value.Detail = detail
	return value
}

// Verify validates the compact profile, time/audience restrictions, and key
// revocation. It is exported for conformance tests and local Pagix doubles.
func Verify(ctx context.Context, compact string, keys SigningPort, now time.Time) (Payload, error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return Payload{}, denied("authorization is not compact JWS")
	}
	headerBytes, err := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	if err != nil {
		return Payload{}, denied("authorization header is not canonical base64url")
	}
	payloadBytes, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil {
		return Payload{}, denied("authorization payload is not canonical base64url")
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil {
		return Payload{}, denied("authorization signature is not canonical base64url")
	}
	var header protectedHeader
	if err := strict(headerBytes, &header); err != nil || header.Algorithm != "EdDSA" || header.Type != Type || !validKeyID(header.KeyID) {
		return Payload{}, denied("authorization protected header is invalid")
	}
	revoked, err := keys.Revoked(ctx, header.KeyID)
	if err != nil || revoked {
		return Payload{}, denied("authorization key is unavailable or revoked")
	}
	public, err := keys.PublicKey(ctx, header.KeyID)
	if err != nil || len(public) != ed25519.PublicKeySize || !ed25519.Verify(public, []byte(parts[0]+"."+parts[1]), signature) {
		return Payload{}, denied("authorization signature is invalid")
	}
	var payload Payload
	if err := strict(payloadBytes, &payload); err != nil || !opaque(string(payload.AuthorizationID)) || payload.KeyID != header.KeyID || payload.Issuer != Issuer || payload.Audience != Audience || payload.Kind != "ApplyAuthorization" {
		return Payload{}, denied("authorization claims are invalid")
	}
	nbf, nbfErr := time.Parse(time.RFC3339Nano, payload.NotBefore)
	iat, iatErr := time.Parse(time.RFC3339Nano, payload.IssuedAt)
	exp, expErr := time.Parse(time.RFC3339Nano, payload.ExpiresAt)
	if nbfErr != nil || iatErr != nil || expErr != nil || payload.NotBefore != timestamp(nbf) || payload.IssuedAt != timestamp(iat) || payload.ExpiresAt != timestamp(exp) || !iat.Equal(nbf) || now.IsZero() || now.Before(nbf) || !now.Before(exp) || exp.Sub(nbf) > 5*time.Minute || !validBinding(Binding{RunID: payload.RunID, ActionDigest: payload.ActionDigest, ArtifactDigest: payload.ArtifactDigest, Target: payload.Target, BaseRevision: payload.BaseRevision, ActorID: payload.ActorID, WorkspaceID: payload.WorkspaceID, ApprovalVersion: payload.ApprovalVersion, ContractBOMDigest: payload.ContractBOMDigest, PolicyDigest: payload.PolicyDigest, DefinitionDigest: payload.DefinitionDigest}) {
		return Payload{}, denied("authorization is expired, premature, or incompletely bound")
	}
	return payload, nil
}

func strict(raw []byte, target any) error {
	canonicalRaw, err := canonical.Bytes(raw)
	if err != nil || string(canonicalRaw) != string(raw) {
		return fmt.Errorf("JSON is not canonical")
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("authorization JSON contains trailing data")
	}
	return nil
}

// MemoryKeyRing is a private-key-hiding signing port for tests and local use.
type MemoryKeyRing struct {
	lock    sync.RWMutex
	active  string
	private map[string]ed25519.PrivateKey
	revoked map[string]bool
}

func NewMemoryKeyRing(keyID string) (*MemoryKeyRing, error) {
	if !validKeyID(keyID) {
		return nil, fmt.Errorf("key ID is invalid")
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &MemoryKeyRing{active: keyID, private: map[string]ed25519.PrivateKey{keyID: private}, revoked: map[string]bool{}}, nil
}

func (r *MemoryKeyRing) ActiveKeyID(context.Context) (string, error) {
	r.lock.RLock()
	defer r.lock.RUnlock()
	return r.active, nil
}
func (r *MemoryKeyRing) Sign(_ context.Context, keyID string, message []byte) ([]byte, error) {
	r.lock.RLock()
	defer r.lock.RUnlock()
	key, ok := r.private[keyID]
	if !ok || r.revoked[keyID] {
		return nil, fmt.Errorf("signing key unavailable")
	}
	return ed25519.Sign(key, message), nil
}
func (r *MemoryKeyRing) PublicKey(_ context.Context, keyID string) (ed25519.PublicKey, error) {
	r.lock.RLock()
	defer r.lock.RUnlock()
	key, ok := r.private[keyID]
	if !ok {
		return nil, fmt.Errorf("key unavailable")
	}
	public := key.Public().(ed25519.PublicKey)
	return append(ed25519.PublicKey(nil), public...), nil
}
func (r *MemoryKeyRing) Revoked(_ context.Context, keyID string) (bool, error) {
	r.lock.RLock()
	defer r.lock.RUnlock()
	_, ok := r.private[keyID]
	if !ok {
		return false, fmt.Errorf("key unavailable")
	}
	return r.revoked[keyID], nil
}
func (r *MemoryKeyRing) Rotate(keyID string) error {
	if !validKeyID(keyID) {
		return fmt.Errorf("key ID is invalid")
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	r.lock.Lock()
	defer r.lock.Unlock()
	r.private[keyID] = private
	r.active = keyID
	return nil
}
func (r *MemoryKeyRing) Revoke(keyID string) {
	r.lock.Lock()
	defer r.lock.Unlock()
	r.revoked[keyID] = true
}

type MemoryAudit struct {
	lock    sync.Mutex
	Records []AuditRecord
}

func (a *MemoryAudit) Record(_ context.Context, record AuditRecord) error {
	a.lock.Lock()
	defer a.lock.Unlock()
	a.Records = append(a.Records, record)
	return nil
}
