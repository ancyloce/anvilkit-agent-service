package artifacts

import (
	"context"
	"sync"

	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
)

// Store is the durable artifact metadata record. Create is insert-once by
// identity; Update is a compare-and-set on the record version, so two racing
// lifecycle transitions resolve to one winner. Snapshot serves reconciliation,
// which reads every live record; kernel-scale corpora make that bounded.
type Store interface {
	Create(context.Context, Record) (Record, bool, error)
	Get(ctx context.Context, workspace, project string, id ID) (Record, bool, error)
	Update(ctx context.Context, next Record, expectedVersion uint64) (Record, error)
	// ClaimDeletion takes durable ownership of one artifact's destruction and
	// carries the artifact out of every live state in the same compare-and-set,
	// before any grant is revoked or any content removed. It succeeds only when
	// the record still stands at the expected version, carries no legal hold,
	// and is not already owned by another decision. A claim already held by the
	// same decision is returned unchanged, which is what lets an interrupted
	// destruction resume rather than restart.
	ClaimDeletion(ctx context.Context, workspace, project string, id ID, expectedVersion uint64, claim DeletionClaim) (Record, error)
	Snapshot(context.Context) ([]Record, error)
}

// MemoryStore is the in-memory metadata store for tests.
type MemoryStore struct {
	lock    sync.Mutex
	records map[string]Record
}

func NewMemoryStore() *MemoryStore { return &MemoryStore{records: map[string]Record{}} }

func (s *MemoryStore) Create(_ context.Context, record Record) (Record, bool, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	identity := key(record.WorkspaceID, record.ProjectID, record.ID)
	if prior, ok := s.records[identity]; ok {
		return clone(prior), false, nil
	}
	s.records[identity] = clone(record)
	return clone(record), true, nil
}

func (s *MemoryStore) Get(_ context.Context, workspace, project string, id ID) (Record, bool, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	value, ok := s.records[key(workspace, project, id)]
	if !ok {
		return Record{}, false, nil
	}
	return clone(value), true, nil
}

func (s *MemoryStore) Update(_ context.Context, next Record, expectedVersion uint64) (Record, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	identity := key(next.WorkspaceID, next.ProjectID, next.ID)
	value, ok := s.records[identity]
	if !ok {
		return Record{}, problem.New(problem.CodeResourceNotFound, "")
	}
	if value.Version != expectedVersion {
		return Record{}, problem.New(problem.CodeVersionConflict, "")
	}
	s.records[identity] = clone(next)
	return clone(next), nil
}

func (s *MemoryStore) ClaimDeletion(_ context.Context, workspace, project string, id ID, expectedVersion uint64, claim DeletionClaim) (Record, error) {
	if !claim.Valid() {
		return Record{}, problem.New(problem.CodeRequestInvalid, "")
	}
	s.lock.Lock()
	defer s.lock.Unlock()
	value, ok := s.records[key(workspace, project, id)]
	if !ok {
		return Record{}, problem.New(problem.CodeResourceNotFound, "")
	}
	if value.DeletionClaim == claim.Decision {
		return clone(value), nil
	}
	if value.DeletionClaim != "" {
		return Record{}, problem.New(problem.CodeVersionConflict, "")
	}
	if value.LegalHold {
		return Record{}, problem.New(problem.CodeArtifactAccessDenied, "")
	}
	if expectedVersion == 0 || value.Version != expectedVersion {
		return Record{}, problem.New(problem.CodeVersionConflict, "")
	}
	next := value
	next.State = claim.Terminal
	next.Version++
	next.SecurityGeneration++
	next.UpdatedAt = claim.At
	next.DeletionClaim = claim.Decision
	claimedAt := claim.At
	next.DeletionClaimedAt = &claimedAt
	s.records[key(workspace, project, id)] = clone(next)
	return clone(next), nil
}

func (s *MemoryStore) Snapshot(context.Context) ([]Record, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	values := make([]Record, 0, len(s.records))
	for _, value := range s.records {
		values = append(values, clone(value))
	}
	return values, nil
}

// Force overwrites one record unconditionally. It exists for tests that place
// an artifact into an arbitrary lifecycle state.
func (s *MemoryStore) Force(record Record) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.records[key(record.WorkspaceID, record.ProjectID, record.ID)] = clone(record)
}
