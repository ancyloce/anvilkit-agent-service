package agent

import (
	"fmt"
	"os"
	"sync"
	"time"
)

// CatalogTrust revalidates the operator-distributed trust material that
// authenticates the approved definition catalog. Verifying once at startup
// proves only that the material was valid when the process began: a trust root
// passes its declared freshness bound, a statement leaves its validity
// interval, and a signing key is revoked, all while the process keeps running.
// Every check re-reads both documents from their configured locations and
// re-verifies from scratch, so readiness and every new run observe the trust
// material as it is now rather than as it was at startup.
type CatalogTrust struct {
	trustRootPath, statementPath string
	catalogDigest                string

	lock    sync.Mutex
	lastErr error
}

// NewCatalogTrust binds the trust material locations to the catalog digest
// they must attest. Both documents are required: a catalog attested by only
// one half of the material is not attested.
func NewCatalogTrust(trustRootPath, statementPath, catalogDigest string) (*CatalogTrust, error) {
	if trustRootPath == "" || statementPath == "" {
		return nil, fmt.Errorf("catalog trust: both a trust root and a signature statement are required")
	}
	if !validDigest(catalogDigest) {
		return nil, fmt.Errorf("catalog trust: the approved catalog digest is malformed")
	}
	return &CatalogTrust{trustRootPath: trustRootPath, statementPath: statementPath, catalogDigest: catalogDigest}, nil
}

// Verify re-reads and re-verifies the trust material at the given instant. It
// fails closed on every reason the material can stop being valid: an
// unreadable or replaced document, a trust root past its declared freshness
// bound, a statement outside its validity interval, a signing key that is no
// longer active, and a statement that no longer binds the catalog this process
// loaded.
func (t *CatalogTrust) Verify(now time.Time) error {
	trustRoot, err := os.ReadFile(t.trustRootPath)
	if err != nil {
		return t.record(fmt.Errorf("read definition trust root: %w", err))
	}
	statement, err := os.ReadFile(t.statementPath)
	if err != nil {
		return t.record(fmt.Errorf("read definition catalog attestation: %w", err))
	}
	return t.record(VerifyCatalogAttestation(trustRoot, statement, t.catalogDigest, now))
}

// LastError returns the most recent verification outcome, so an operator
// surface can report why work is being refused without re-reading the files.
func (t *CatalogTrust) LastError() error {
	t.lock.Lock()
	defer t.lock.Unlock()
	return t.lastErr
}

func (t *CatalogTrust) record(err error) error {
	t.lock.Lock()
	t.lastErr = err
	t.lock.Unlock()
	return err
}
