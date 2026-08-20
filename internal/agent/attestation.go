package agent

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strings"
	"time"
)

// TrustRootKey is one operator-distributed verification key.
type TrustRootKey struct {
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

// TrustRoot is the pinned public trust snapshot used to authenticate the
// approved definition catalog. It is distributed independently of the
// catalog it verifies, so the material being authenticated can never select
// its own trust.
type TrustRoot struct {
	Kind                    string         `json:"kind"`
	SnapshotID              string         `json:"snapshotId"`
	IssuedAt                string         `json:"issuedAt"`
	NextUpdate              string         `json:"nextUpdate"`
	MaximumClockSkewSeconds int            `json:"maximumClockSkewSeconds"`
	Keys                    []TrustRootKey `json:"keys"`
}

// CatalogStatement is the signed claim that one catalog digest is approved.
type CatalogStatement struct {
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

type envelopeSignature struct {
	KeyID     string `json:"keyid"`
	Signature string `json:"sig"`
}

// Envelope is the single-signature DSSE envelope carrying the statement.
type Envelope struct {
	PayloadType string              `json:"payloadType"`
	Payload     string              `json:"payload"`
	Signatures  []envelopeSignature `json:"signatures"`
}

const (
	// CatalogStatementType is the DSSE payload type of a catalog statement.
	CatalogStatementType = "application/vnd.anvilkit.agent-definition-catalog-statement+json"
	// CatalogMediaType is the media type of the catalog the statement binds.
	CatalogMediaType = "application/vnd.anvilkit.agent-definition-catalog+json"
	// CatalogAudience is the only audience an agent-service accepts.
	CatalogAudience = "urn:anvilkit:audience:agent-service"

	catalogAlgorithm      = "dsse-ed25519-v1"
	maximumTrustRootBytes = 262144
	maximumEnvelopeBytes  = 65536
	timestampLayout       = "2006-01-02T15:04:05.000Z"
)

// VerifyCatalogAttestation authenticates the approved definition catalog
// against an operator-distributed trust root. It fails closed on an unknown,
// inactive, expired, or wrong-purpose key, on a signature that does not
// verify, and on a statement that binds any digest other than the catalog
// the service actually loaded.
func VerifyCatalogAttestation(trustRootBytes, envelopeBytes []byte, catalogDigest string, now time.Time) error {
	if len(trustRootBytes) == 0 || len(trustRootBytes) > maximumTrustRootBytes {
		return fmt.Errorf("catalog attestation: the trust root is empty or unbounded")
	}
	if len(envelopeBytes) == 0 || len(envelopeBytes) > maximumEnvelopeBytes {
		return fmt.Errorf("catalog attestation: the signature envelope is empty or unbounded")
	}
	if !validDigest(catalogDigest) {
		return fmt.Errorf("catalog attestation: the catalog digest is malformed")
	}
	var root TrustRoot
	if err := decodeJSON(trustRootBytes, &root); err != nil {
		return fmt.Errorf("catalog attestation: decode trust root: %w", err)
	}
	if root.Kind != "ContractTrustRoot" || root.SnapshotID == "" || len(root.Keys) == 0 || len(root.Keys) > 32 || root.MaximumClockSkewSeconds < 0 || root.MaximumClockSkewSeconds > 300 {
		return fmt.Errorf("catalog attestation: the trust root is incomplete")
	}
	nextUpdate, err := time.Parse(timestampLayout, root.NextUpdate)
	if err != nil {
		return fmt.Errorf("catalog attestation: the trust root freshness bound is malformed")
	}
	skew := time.Duration(root.MaximumClockSkewSeconds) * time.Second
	if now.After(nextUpdate.Add(skew)) {
		return fmt.Errorf("catalog attestation: the trust root is past its declared freshness bound")
	}

	var envelope Envelope
	if err := decodeJSON(envelopeBytes, &envelope); err != nil {
		return fmt.Errorf("catalog attestation: decode signature envelope: %w", err)
	}
	if envelope.PayloadType != CatalogStatementType || len(envelope.Signatures) != 1 {
		return fmt.Errorf("catalog attestation: only one single-signature statement of the declared payload type is accepted")
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return fmt.Errorf("catalog attestation: the statement payload is not base64: %w", err)
	}
	signature, err := base64.StdEncoding.DecodeString(envelope.Signatures[0].Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("catalog attestation: the statement signature is malformed")
	}
	var statement CatalogStatement
	if err := decodeJSON(payload, &statement); err != nil {
		return fmt.Errorf("catalog attestation: decode statement: %w", err)
	}
	if statement.Kind != "AgentDefinitionCatalogStatement" || statement.Algorithm != catalogAlgorithm {
		return fmt.Errorf("catalog attestation: the statement kind or algorithm is outside the accepted profile")
	}
	if statement.Audience != CatalogAudience {
		return fmt.Errorf("catalog attestation: the statement is not addressed to this service")
	}
	if statement.Subject.MediaType != CatalogMediaType || !equalDigest(statement.Subject.Digest, catalogDigest) {
		return fmt.Errorf("catalog attestation: the statement does not bind the loaded definition catalog")
	}
	if statement.KeyID == "" || statement.KeyID != envelope.Signatures[0].KeyID {
		return fmt.Errorf("catalog attestation: the envelope key identity does not match the statement")
	}
	notBefore, err := time.Parse(timestampLayout, statement.NotBefore)
	if err != nil {
		return fmt.Errorf("catalog attestation: the statement validity start is malformed")
	}
	expiresAt, err := time.Parse(timestampLayout, statement.ExpiresAt)
	if err != nil {
		return fmt.Errorf("catalog attestation: the statement validity end is malformed")
	}
	if now.Add(skew).Before(notBefore) || now.After(expiresAt.Add(skew)) {
		return fmt.Errorf("catalog attestation: the statement is outside its validity interval")
	}

	key, err := resolveTrustKey(root, statement, now, skew)
	if err != nil {
		return err
	}
	if !ed25519.Verify(key, encodePAE(envelope.PayloadType, payload), signature) {
		return fmt.Errorf("catalog attestation: the statement signature does not verify")
	}
	return nil
}

func resolveTrustKey(root TrustRoot, statement CatalogStatement, now time.Time, skew time.Duration) (ed25519.PublicKey, error) {
	for _, candidate := range root.Keys {
		if candidate.KeyID != statement.KeyID {
			continue
		}
		if candidate.Status != "active" && candidate.Status != "overlap" {
			return nil, fmt.Errorf("catalog attestation: the signing key is not usable")
		}
		if candidate.Issuer != statement.Issuer {
			return nil, fmt.Errorf("catalog attestation: the signing key does not belong to the statement issuer")
		}
		if !containsValue(candidate.Audiences, statement.Audience) || !containsValue(candidate.Algorithms, catalogAlgorithm) {
			return nil, fmt.Errorf("catalog attestation: the signing key is not approved for this audience and algorithm")
		}
		notBefore, err := time.Parse(timestampLayout, candidate.NotBefore)
		if err != nil {
			return nil, fmt.Errorf("catalog attestation: the signing key validity start is malformed")
		}
		notAfter, err := time.Parse(timestampLayout, candidate.NotAfter)
		if err != nil {
			return nil, fmt.Errorf("catalog attestation: the signing key validity end is malformed")
		}
		if now.Add(skew).Before(notBefore) || now.After(notAfter.Add(skew)) {
			return nil, fmt.Errorf("catalog attestation: the signing key is outside its validity interval")
		}
		if candidate.PublicKeyJwk.KeyType != "OKP" || candidate.PublicKeyJwk.Curve != "Ed25519" {
			return nil, fmt.Errorf("catalog attestation: the signing key is not an Ed25519 key")
		}
		material, err := base64.RawURLEncoding.DecodeString(candidate.PublicKeyJwk.X)
		if err != nil || len(material) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("catalog attestation: the signing key material is malformed")
		}
		return ed25519.PublicKey(material), nil
	}
	return nil, fmt.Errorf("catalog attestation: the statement key is not in the pinned trust root")
}

// encodePAE builds the DSSE pre-authentication encoding.
func encodePAE(payloadType string, payload []byte) []byte {
	var builder strings.Builder
	builder.WriteString("DSSEv1 ")
	fmt.Fprintf(&builder, "%d %s %d ", len(payloadType), payloadType, len(payload))
	return append([]byte(builder.String()), payload...)
}

func containsValue(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
