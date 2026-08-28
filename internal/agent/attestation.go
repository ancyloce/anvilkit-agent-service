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
	return trust.VerifyStatement(trustRootBytes, envelopeBytes, trust.StatementProfile{
		Context:     "catalog attestation",
		Kind:        "AgentDefinitionCatalogStatement",
		PayloadType: CatalogStatementType,
		MediaType:   CatalogMediaType,
		Audience:    CatalogAudience,
		Algorithm:   catalogAlgorithm,
	}, catalogDigest, now)
}
