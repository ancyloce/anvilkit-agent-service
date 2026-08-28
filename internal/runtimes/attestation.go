package runtimes

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/trust"
)

const (
	// CatalogStatementType is the DSSE payload type of a release catalog
	// statement. It is distinct from every other statement type this service
	// accepts, so a statement attesting other material can never be read as an
	// approval of runtime releases.
	CatalogStatementType = "application/vnd.anvilkit.agent-runtime-release-catalog-statement+json"
	// CatalogMediaType is the media type of the catalog the statement binds.
	CatalogMediaType = "application/vnd.anvilkit.agent-runtime-release-catalog+json"
	// CatalogAudience is the only audience an agent-service accepts.
	CatalogAudience = "urn:anvilkit:audience:agent-service"
	// CatalogStatementKind is the statement kind a release approval declares.
	CatalogStatementKind = "AgentRuntimeReleaseCatalogStatement"

	catalogAlgorithm = "dsse-ed25519-v1"
)

func statementProfile() trust.StatementProfile {
	return trust.StatementProfile{
		Context:     "release catalog attestation",
		Kind:        CatalogStatementKind,
		PayloadType: CatalogStatementType,
		MediaType:   CatalogMediaType,
		Audience:    CatalogAudience,
		Algorithm:   catalogAlgorithm,
	}
}

// VerifyCatalogAttestation authenticates the approved release catalog against
// an operator-distributed trust root, which is distributed independently of the
// catalog it verifies so the material being authenticated can never select its
// own trust.
func VerifyCatalogAttestation(trustRootBytes, envelopeBytes []byte, catalogDigest string, now time.Time) error {
	if !validDigest(catalogDigest) {
		return fmt.Errorf("release catalog attestation: the catalog digest is malformed")
	}
	return trust.VerifyStatement(trustRootBytes, envelopeBytes, statementProfile(), catalogDigest, now)
}

// CatalogTrust revalidates the operator-distributed material that authenticates
// the approved release catalog. Verifying once at startup proves only that the
// material was valid when the process began: a trust root passes its freshness
// bound, a statement leaves its validity interval, and a signing key is
// revoked, all while the process keeps running. Every check re-reads both
// documents and re-verifies from scratch, so a release approval that stops
// being valid stops new runs.
type CatalogTrust struct {
	trustRootPath, statementPath string
	catalogDigest                string

	lock    sync.Mutex
	lastErr error
}

// NewCatalogTrust binds the trust material locations to the catalog digest they
// must attest. Both documents are required: a catalog attested by only one half
// of the material is not attested.
func NewCatalogTrust(trustRootPath, statementPath, catalogDigest string) (*CatalogTrust, error) {
	if trustRootPath == "" || statementPath == "" {
		return nil, fmt.Errorf("release catalog trust: both a trust root and a signature statement are required")
	}
	if !validDigest(catalogDigest) {
		return nil, fmt.Errorf("release catalog trust: the approved catalog digest is malformed")
	}
	return &CatalogTrust{trustRootPath: trustRootPath, statementPath: statementPath, catalogDigest: catalogDigest}, nil
}

// Verify re-reads and re-verifies the trust material at the given instant.
func (t *CatalogTrust) Verify(now time.Time) error {
	t.lock.Lock()
	defer t.lock.Unlock()
	rootBytes, err := os.ReadFile(t.trustRootPath)
	if err != nil {
		t.lastErr = fmt.Errorf("release catalog trust: read trust root: %w", err)
		return t.lastErr
	}
	envelopeBytes, err := os.ReadFile(t.statementPath)
	if err != nil {
		t.lastErr = fmt.Errorf("release catalog trust: read signature statement: %w", err)
		return t.lastErr
	}
	t.lastErr = VerifyCatalogAttestation(rootBytes, envelopeBytes, t.catalogDigest, now)
	return t.lastErr
}
