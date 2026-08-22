package agent

import (
	"fmt"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/trust"
)

// TrustRootKey is one operator-distributed verification key.
type TrustRootKey = trust.Key

// TrustRoot is the pinned public trust snapshot used to authenticate the
// approved definition catalog. It is distributed independently of the
// catalog it verifies, so the material being authenticated can never select
// its own trust. It is the same operator document the authoritative time
// authority is verified against, read by the same code.
type TrustRoot = trust.Root

// Envelope is the single-signature DSSE envelope carrying the statement.
type Envelope = trust.Envelope

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

const (
	// CatalogStatementType is the DSSE payload type of a catalog statement.
	CatalogStatementType = "application/vnd.anvilkit.agent-definition-catalog-statement+json"
	// CatalogMediaType is the media type of the catalog the statement binds.
	CatalogMediaType = "application/vnd.anvilkit.agent-definition-catalog+json"
	// CatalogAudience is the only audience an agent-service accepts.
	CatalogAudience = "urn:anvilkit:audience:agent-service"

	catalogAlgorithm = "dsse-ed25519-v1"
	timestampLayout  = trust.Timestamp
)

// VerifyCatalogAttestation authenticates the approved definition catalog
// against an operator-distributed trust root. It fails closed on an unknown,
// inactive, expired, or wrong-purpose key, on a signature that does not
// verify, and on a statement that binds any digest other than the catalog
// the service actually loaded.
func VerifyCatalogAttestation(trustRootBytes, envelopeBytes []byte, catalogDigest string, now time.Time) error {
	if !validDigest(catalogDigest) {
		return fmt.Errorf("catalog attestation: the catalog digest is malformed")
	}
	root, skew, err := trust.ParseRoot(trustRootBytes, now, "catalog attestation")
	if err != nil {
		return err
	}
	payload, signature, envelopeKeyID, err := trust.OpenEnvelope(envelopeBytes, CatalogStatementType, "catalog attestation")
	if err != nil {
		return err
	}
	var statement CatalogStatement
	if err := trust.DecodeJSON(payload, &statement); err != nil {
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
	if statement.KeyID == "" || statement.KeyID != envelopeKeyID {
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
	key, err := trust.ResolveKey(root, trust.KeyRequest{KeyID: statement.KeyID, Issuer: statement.Issuer, Audience: statement.Audience, Algorithm: catalogAlgorithm}, now, skew, "catalog attestation")
	if err != nil {
		return err
	}
	if !trust.Verify(key, CatalogStatementType, payload, signature) {
		return fmt.Errorf("catalog attestation: the statement signature does not verify")
	}
	return nil
}
