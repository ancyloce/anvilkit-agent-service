// Package journal defines the independent logical-RPO-0 receipt boundary.
package journal

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"sort"
	"sync"
)

type FactClass string

const (
	FactCreate          FactClass = "create"
	FactInput           FactClass = "input-response"
	FactApproval        FactClass = "approval-decision"
	FactCancel          FactClass = "cancel"
	FactRetry           FactClass = "retry"
	FactDiscard         FactClass = "discard"
	FactAuthorization   FactClass = "authorization-issuance"
	FactPrivilegedAudit FactClass = "privileged-audit"
)

func Classes() []FactClass {
	return []FactClass{FactCreate, FactInput, FactApproval, FactCancel, FactRetry, FactDiscard, FactAuthorization, FactPrivilegedAudit}
}

type Fact struct {
	ID, WorkspaceID, ProjectID string
	Class                      FactClass
	OperationOrder             uint64
	Canonical                  []byte
	Digest                     [32]byte
	Projection                 []byte
}

func NewFact(id, workspaceID, projectID string, class FactClass, canonical, projection []byte) (Fact, error) {
	if id == "" || workspaceID == "" || projectID == "" || !knownClass(class) || len(canonical) == 0 {
		return Fact{}, fmt.Errorf("journal fact: identity, scope, known class, and canonical bytes are required")
	}
	digest := sha256.Sum256(canonical)
	return Fact{ID: id, WorkspaceID: workspaceID, ProjectID: projectID, Class: class, Canonical: append([]byte(nil), canonical...), Digest: digest, Projection: append([]byte(nil), projection...)}, nil
}

func knownClass(class FactClass) bool {
	for _, candidate := range Classes() {
		if class == candidate {
			return true
		}
	}
	return false
}

type Store interface {
	Append(context.Context, Fact) (Fact, error)
	List(context.Context) ([]Fact, error)
	Check(context.Context) error
}
type Commit func(context.Context) ([]byte, error)
type Coordinator struct{ store Store }

func NewCoordinator(store Store) *Coordinator { return &Coordinator{store: store} }
func (c *Coordinator) Acknowledge(ctx context.Context, fact Fact, commit Commit) ([]byte, error) {
	projection, err := commit(ctx)
	if err != nil {
		return nil, fmt.Errorf("commit authority fact: %w", err)
	}
	fact.Projection = append([]byte(nil), projection...)
	retained, err := c.store.Append(ctx, fact)
	if err != nil {
		return nil, fmt.Errorf("authority fact remains unacknowledged: %w", err)
	}
	return append([]byte(nil), retained.Projection...), nil
}

type ApplyResult string

const (
	Reconstructed ApplyResult = "reconstructed"
	Conflict      ApplyResult = "conflict"
)

type Reconstructor interface {
	Apply(context.Context, Fact) (ApplyResult, error)
}

func Reconstruct(ctx context.Context, store Store, target Reconstructor) (map[string]ApplyResult, error) {
	facts, err := store.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list journal facts: %w", err)
	}
	sort.Slice(facts, func(i, j int) bool { return facts[i].OperationOrder < facts[j].OperationOrder })
	results := make(map[string]ApplyResult, len(facts))
	var previous uint64
	for _, fact := range facts {
		if fact.OperationOrder == 0 || fact.OperationOrder <= previous || !knownClass(fact.Class) || sha256.Sum256(fact.Canonical) != fact.Digest {
			return nil, fmt.Errorf("reconstruct fact %s: invalid retained envelope", fact.ID)
		}
		previous = fact.OperationOrder
		outcome, err := target.Apply(ctx, fact)
		if err != nil {
			return nil, fmt.Errorf("reconstruct fact %s: %w", fact.ID, err)
		}
		if outcome != Reconstructed && outcome != Conflict {
			return nil, fmt.Errorf("reconstruct fact %s: silent outcome is forbidden", fact.ID)
		}
		results[fact.ID] = outcome
	}
	return results, nil
}

type MemoryStore struct {
	lock      sync.Mutex
	available bool
	facts     map[string]Fact
	nextOrder uint64
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{available: true, facts: make(map[string]Fact)}
}
func (s *MemoryStore) SetAvailable(available bool) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.available = available
}
func (s *MemoryStore) Check(context.Context) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	if !s.available {
		return fmt.Errorf("journal unavailable")
	}
	return nil
}
func (s *MemoryStore) Append(_ context.Context, fact Fact) (Fact, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	if !s.available {
		return Fact{}, fmt.Errorf("journal unavailable")
	}
	if existing, ok := s.facts[fact.ID]; ok {
		if existing.WorkspaceID != fact.WorkspaceID || existing.ProjectID != fact.ProjectID || existing.Class != fact.Class || existing.Digest != fact.Digest || !bytes.Equal(existing.Canonical, fact.Canonical) || !bytes.Equal(existing.Projection, fact.Projection) {
			return Fact{}, fmt.Errorf("journal conflict: fact identity reused with different bytes")
		}
		return cloneFact(existing), nil
	}
	s.nextOrder++
	fact.OperationOrder = s.nextOrder
	s.facts[fact.ID] = fact
	return cloneFact(fact), nil
}
func (s *MemoryStore) List(context.Context) ([]Fact, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	if !s.available {
		return nil, fmt.Errorf("journal unavailable")
	}
	result := make([]Fact, 0, len(s.facts))
	for _, fact := range s.facts {
		result = append(result, cloneFact(fact))
	}
	return result, nil
}

func cloneFact(fact Fact) Fact {
	fact.Canonical = append([]byte(nil), fact.Canonical...)
	fact.Projection = append([]byte(nil), fact.Projection...)
	return fact
}
