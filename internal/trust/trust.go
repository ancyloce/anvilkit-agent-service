// Package trust owns the operator-distributed trust root and the signed
// statements authenticated against it.
//
// The trust root is distributed independently of everything it verifies, so
// material being authenticated can never select the trust that authenticates
// it. Two things are verified against it today — the approved definition
// catalog and the authoritative time authority — and they share this code
// rather than each carrying their own reading of the same operator document,
// because two readings of one document are two places for them to disagree.
package trust

import (
	"bytes"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// Key is one operator-distributed verification key.
type Key struct {
	KeyID        string   `json:"keyId"`
	Issuer       string   `json:"issuer"`
	Audiences    []string `json:"audiences"`
	Algorithms   []string `json:"algorithms"`
	PublicKeyJwk struct {
		KeyType string `json:"kty"`
		Curve   string `json:"crv"`
		X       string `json:"x"`
	} `json:"publicKeyJwk"`
	Status    string `json:"status"`
	NotBefore string `json:"notBefore"`
	NotAfter  string `json:"notAfter"`
}

// Root is the pinned public trust snapshot.
type Root struct {
	Kind                    string `json:"kind"`
	SnapshotID              string `json:"snapshotId"`
	IssuedAt                string `json:"issuedAt"`
	NextUpdate              string `json:"nextUpdate"`
	MaximumClockSkewSeconds int    `json:"maximumClockSkewSeconds"`
	Keys                    []Key  `json:"keys"`
}

// Signature is one detached signature over an envelope's payload.
type Signature struct {
	KeyID     string `json:"keyid"`
	Signature string `json:"sig"`
}

// Envelope is the single-signature DSSE envelope carrying a statement.
type Envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"`
	Signatures  []Signature `json:"signatures"`
}

// Seal builds one single-signature envelope over a payload. It is what a
// signing authority does; the service only ever verifies.
func Seal(key ed25519.PrivateKey, keyID, payloadType string, payload []byte) (Envelope, error) {
	if len(key) != ed25519.PrivateKeySize || keyID == "" || payloadType == "" || len(payload) == 0 {
		return Envelope{}, fmt.Errorf("seal statement: a key, key identity, payload type, and payload are required")
	}
	return Envelope{
		PayloadType: payloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures:  []Signature{{KeyID: keyID, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, EncodePAE(payloadType, payload)))}},
	}, nil
}

// RootKind is the only trust root document kind accepted.
const RootKind = "ContractTrustRoot"

// Timestamp is the layout every timestamp in the trust material uses.
const Timestamp = "2006-01-02T15:04:05.000Z"

const (
	// MaximumRootBytes and MaximumEnvelopeBytes bound what is read from the
	// operator's material and from the wire.
	MaximumRootBytes     = 262144
	MaximumEnvelopeBytes = 65536
)

// ParseRoot decodes and freshness-checks one trust root, returning it and the
// clock skew it declares.
//
// The freshness bound is the operator's own statement of how long this
// snapshot may be believed. A root past it is refused rather than used with a
// warning: a trust root that outlives its declared life is how a revoked key
// keeps working.
func ParseRoot(raw []byte, now time.Time, context string) (Root, time.Duration, error) {
	if len(raw) == 0 || len(raw) > MaximumRootBytes {
		return Root{}, 0, fmt.Errorf("%s: the trust root is empty or unbounded", context)
	}
	var root Root
	if err := DecodeJSON(raw, &root); err != nil {
		return Root{}, 0, fmt.Errorf("%s: decode trust root: %w", context, err)
	}
	if root.Kind != RootKind || root.SnapshotID == "" || len(root.Keys) == 0 || len(root.Keys) > 32 || root.MaximumClockSkewSeconds < 0 || root.MaximumClockSkewSeconds > 300 {
		return Root{}, 0, fmt.Errorf("%s: the trust root is incomplete", context)
	}
	nextUpdate, err := time.Parse(Timestamp, root.NextUpdate)
	if err != nil {
		return Root{}, 0, fmt.Errorf("%s: the trust root freshness bound is malformed", context)
	}
	skew := time.Duration(root.MaximumClockSkewSeconds) * time.Second
	if now.After(nextUpdate.Add(skew)) {
		return Root{}, 0, fmt.Errorf("%s: the trust root is past its declared freshness bound", context)
	}
	return root, skew, nil
}

// KeyRequest is what a statement claims about the key that signed it. Every
// field is matched against the trust root: a key is usable for the issuer,
// audience, and algorithm the operator approved it for and for nothing else.
type KeyRequest struct {
	KeyID, Issuer, Audience, Algorithm string
}

// ResolveKey answers the verification key for one statement, or refuses.
func ResolveKey(root Root, want KeyRequest, now time.Time, skew time.Duration, context string) (ed25519.PublicKey, error) {
	for _, candidate := range root.Keys {
		if candidate.KeyID != want.KeyID {
			continue
		}
		if candidate.Status != "active" && candidate.Status != "overlap" {
			return nil, fmt.Errorf("%s: the signing key is not usable", context)
		}
		if candidate.Issuer != want.Issuer {
			return nil, fmt.Errorf("%s: the signing key does not belong to the statement issuer", context)
		}
		if !contains(candidate.Audiences, want.Audience) || !contains(candidate.Algorithms, want.Algorithm) {
			return nil, fmt.Errorf("%s: the signing key is not approved for this audience and algorithm", context)
		}
		notBefore, err := time.Parse(Timestamp, candidate.NotBefore)
		if err != nil {
			return nil, fmt.Errorf("%s: the signing key validity start is malformed", context)
		}
		notAfter, err := time.Parse(Timestamp, candidate.NotAfter)
		if err != nil {
			return nil, fmt.Errorf("%s: the signing key validity end is malformed", context)
		}
		if now.Add(skew).Before(notBefore) || now.After(notAfter.Add(skew)) {
			return nil, fmt.Errorf("%s: the signing key is outside its validity interval", context)
		}
		if candidate.PublicKeyJwk.KeyType != "OKP" || candidate.PublicKeyJwk.Curve != "Ed25519" {
			return nil, fmt.Errorf("%s: the signing key is not an Ed25519 key", context)
		}
		material, err := base64.RawURLEncoding.DecodeString(candidate.PublicKeyJwk.X)
		if err != nil || len(material) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%s: the signing key material is malformed", context)
		}
		return ed25519.PublicKey(material), nil
	}
	return nil, fmt.Errorf("%s: the statement key is not in the pinned trust root", context)
}

// OpenEnvelope decodes one single-signature DSSE envelope of the declared
// payload type and returns its payload bytes, its signature, and the key
// identity the envelope claims. Nothing is trusted yet: this only takes the
// envelope apart.
func OpenEnvelope(raw []byte, payloadType, context string) (payload, signature []byte, keyID string, err error) {
	if len(raw) == 0 || len(raw) > MaximumEnvelopeBytes {
		return nil, nil, "", fmt.Errorf("%s: the signature envelope is empty or unbounded", context)
	}
	var envelope Envelope
	if err := DecodeJSON(raw, &envelope); err != nil {
		return nil, nil, "", fmt.Errorf("%s: decode signature envelope: %w", context, err)
	}
	if envelope.PayloadType != payloadType || len(envelope.Signatures) != 1 {
		return nil, nil, "", fmt.Errorf("%s: only one single-signature statement of the declared payload type is accepted", context)
	}
	payload, decodeErr := base64.StdEncoding.DecodeString(envelope.Payload)
	if decodeErr != nil {
		return nil, nil, "", fmt.Errorf("%s: the statement payload is not base64: %w", context, decodeErr)
	}
	signature, decodeErr = base64.StdEncoding.DecodeString(envelope.Signatures[0].Signature)
	if decodeErr != nil || len(signature) != ed25519.SignatureSize {
		return nil, nil, "", fmt.Errorf("%s: the statement signature is malformed", context)
	}
	return payload, signature, envelope.Signatures[0].KeyID, nil
}

// Verify proves one envelope's signature over its payload.
func Verify(key ed25519.PublicKey, payloadType string, payload, signature []byte) bool {
	return ed25519.Verify(key, EncodePAE(payloadType, payload), signature)
}

// EncodePAE builds the DSSE pre-authentication encoding.
func EncodePAE(payloadType string, payload []byte) []byte {
	var builder strings.Builder
	builder.WriteString("DSSEv1 ")
	builder.WriteString(strconv.Itoa(len(payloadType)))
	builder.WriteString(" ")
	builder.WriteString(payloadType)
	builder.WriteString(" ")
	builder.WriteString(strconv.Itoa(len(payload)))
	builder.WriteString(" ")
	return append([]byte(builder.String()), payload...)
}

// DecodeJSON decodes exactly one JSON value with no unknown fields.
func DecodeJSON(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("the document must contain exactly one JSON value")
	}
	return nil
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// Statement is the signed claim that one digest is approved material. Both the
// approved definition catalog and the approved runtime release catalog are
// attested with this shape; the profile below says which kind of statement is
// being read, so the two can never be mistaken for each other.
type Statement struct {
	Kind      string `json:"kind"`
	Algorithm string `json:"algorithm"`
	Issuer    string `json:"issuer"`
	Audience  string `json:"audience"`
	KeyID     string `json:"keyId"`
	Subject   struct {
		Digest    string `json:"digest"`
		MediaType string `json:"mediaType"`
	} `json:"subject"`
	IssuedAt  string `json:"issuedAt"`
	NotBefore string `json:"notBefore"`
	ExpiresAt string `json:"expiresAt"`
}

// StatementProfile is the exact statement one caller will accept. Every field
// is required: a verifier that accepted any kind, payload type, media type, or
// audience would accept a statement written to attest something else.
type StatementProfile struct {
	Context     string
	Kind        string
	PayloadType string
	MediaType   string
	Audience    string
	Algorithm   string
}

// VerifyStatement authenticates one signed statement against an
// operator-distributed trust root. It fails closed on an unknown, inactive,
// expired, or wrong-purpose key, on a signature that does not verify, and on a
// statement that binds any digest other than the material the caller loaded.
func VerifyStatement(rootBytes, envelopeBytes []byte, profile StatementProfile, subjectDigest string, now time.Time) error {
	root, skew, err := ParseRoot(rootBytes, now, profile.Context)
	if err != nil {
		return err
	}
	payload, signature, envelopeKeyID, err := OpenEnvelope(envelopeBytes, profile.PayloadType, profile.Context)
	if err != nil {
		return err
	}
	var statement Statement
	if err := DecodeJSON(payload, &statement); err != nil {
		return fmt.Errorf("%s: decode statement: %w", profile.Context, err)
	}
	if statement.Kind != profile.Kind || statement.Algorithm != profile.Algorithm {
		return fmt.Errorf("%s: the statement kind or algorithm is outside the accepted profile", profile.Context)
	}
	if statement.Audience != profile.Audience {
		return fmt.Errorf("%s: the statement is not addressed to this service", profile.Context)
	}
	if statement.Subject.MediaType != profile.MediaType ||
		len(statement.Subject.Digest) != len(subjectDigest) ||
		subtle.ConstantTimeCompare([]byte(statement.Subject.Digest), []byte(subjectDigest)) != 1 {
		return fmt.Errorf("%s: the statement does not bind the material this process loaded", profile.Context)
	}
	if statement.KeyID == "" || statement.KeyID != envelopeKeyID {
		return fmt.Errorf("%s: the envelope key identity does not match the statement", profile.Context)
	}
	notBefore, err := time.Parse(Timestamp, statement.NotBefore)
	if err != nil {
		return fmt.Errorf("%s: the statement validity start is malformed", profile.Context)
	}
	expiresAt, err := time.Parse(Timestamp, statement.ExpiresAt)
	if err != nil {
		return fmt.Errorf("%s: the statement validity end is malformed", profile.Context)
	}
	if now.Add(skew).Before(notBefore) || now.After(expiresAt.Add(skew)) {
		return fmt.Errorf("%s: the statement is outside its validity interval", profile.Context)
	}
	key, err := ResolveKey(root, KeyRequest{KeyID: statement.KeyID, Issuer: statement.Issuer, Audience: statement.Audience, Algorithm: profile.Algorithm}, now, skew, profile.Context)
	if err != nil {
		return err
	}
	if !Verify(key, profile.PayloadType, payload, signature) {
		return fmt.Errorf("%s: the statement signature does not verify", profile.Context)
	}
	return nil
}
