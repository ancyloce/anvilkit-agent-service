// Package contracts makes runtime validation mandatory and observable at each
// trust boundary. It consumes only the service's pinned contract copy.
package contracts

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/ancyloce/anvilkit-agent-service/contracts/validator"
)

type Boundary string

const (
	APIIn              Boundary = "api-in"
	ProviderOut        Boundary = "provider-out"
	ProviderIn         Boundary = "provider-in"
	WorkerIn           Boundary = "worker-in"
	PagixOut           Boundary = "pagix-out"
	PagixIn            Boundary = "pagix-in"
	ContractRuntimeOut Boundary = "contract-runtime-out"
	ContractRuntimeIn  Boundary = "contract-runtime-in"
	EventIn            Boundary = "event-in"
)

func RequiredBoundaries() []Boundary {
	return []Boundary{APIIn, ProviderOut, ProviderIn, WorkerIn, PagixOut, PagixIn, ContractRuntimeOut, ContractRuntimeIn, EventIn}
}

type Guard struct {
	adapter  *validator.Adapter
	lock     sync.Mutex
	observed map[Boundary]uint64
}

func NewGuard(repositoryRoot string) (*Guard, error) {
	if err := VerifyPinnedMaterial(repositoryRoot); err != nil {
		return nil, fmt.Errorf("verify pinned contract material: %w", err)
	}
	adapter, err := validator.New(repositoryRoot)
	if err != nil {
		return nil, fmt.Errorf("load pinned runtime validator: %w", err)
	}
	return &Guard{adapter: adapter, observed: make(map[Boundary]uint64)}, nil
}

func (g *Guard) Validate(_ context.Context, boundary Boundary, schemaURI string, raw []byte) []validator.Finding {
	if !isRequired(boundary) {
		return []validator.Finding{{Code: "VALIDATION_BOUNDARY_UNKNOWN", InstancePath: "/", SchemaPath: "/trustBoundary"}}
	}
	g.lock.Lock()
	g.observed[boundary]++
	g.lock.Unlock()
	return g.adapter.Validate(schemaURI, raw)
}

// Require validates one concrete trust-boundary payload and fails before an
// adapter can perform an external or durable side effect.
func (g *Guard) Require(ctx context.Context, boundary Boundary, schemaURI string, raw []byte) error {
	findings := g.Validate(ctx, boundary, schemaURI, raw)
	if len(findings) != 0 {
		return fmt.Errorf("contract validation failed at %s: %v", boundary, findings)
	}
	return nil
}

func (g *Guard) AssertCoverage() error {
	g.lock.Lock()
	defer g.lock.Unlock()
	var missing []string
	for _, boundary := range RequiredBoundaries() {
		if g.observed[boundary] == 0 {
			missing = append(missing, string(boundary))
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		return fmt.Errorf("runtime validation missing at trust boundaries: %v", missing)
	}
	return nil
}

func isRequired(candidate Boundary) bool {
	for _, boundary := range RequiredBoundaries() {
		if candidate == boundary {
			return true
		}
	}
	return false
}
