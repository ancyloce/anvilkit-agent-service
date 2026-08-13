package securityaudit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
)

type Scope struct{ WorkspaceID, ProjectID, ResourceID string }

type Record struct {
	ID, Action, Actor, Workload, Reason, Ticket string
	OldDigest, NewDigest, Traceparent, Outcome  string
	Scope                                       Scope
	UTC                                         time.Time
	PreviousDigest, Digest                      string
}

type ProtectedSink interface {
	Append(context.Context, Record) (Record, error)
	Read(context.Context) ([]Record, error)
	Verify(context.Context) error
}
type AlertSink interface {
	Alert(context.Context, string, string) error
}
type Mutation func(context.Context) error

type Service struct {
	sink   ProtectedSink
	clock  *AuthoritativeClock
	alerts AlertSink
}

func NewService(sink ProtectedSink, clock *AuthoritativeClock, alerts AlertSink) (*Service, error) {
	if sink == nil || clock == nil || alerts == nil {
		return nil, fmt.Errorf("protected sink, authoritative clock, and alerts are required")
	}
	return &Service{sink: sink, clock: clock, alerts: alerts}, nil
}

func (s *Service) PrivilegedMutation(ctx context.Context, record Record, mutation Mutation) error {
	if mutation == nil || !complete(record) {
		return problem.New(problem.CodeRequestInvalid, "")
	}
	now, err := s.clock.Now(ctx)
	if err != nil {
		return err
	}
	record.UTC = now
	record.Outcome = "authorized-to-apply"
	if _, err := s.sink.Append(ctx, record); err != nil {
		return fmt.Errorf("protected audit unavailable: %w", err)
	}
	return mutation(ctx)
}

// Read records audit access in the protected sink before returning records.
func (s *Service) Read(ctx context.Context, access Record) ([]Record, error) {
	access.Action = "audit-access"
	if err := s.PrivilegedMutation(ctx, access, func(context.Context) error { return nil }); err != nil {
		return nil, err
	}
	return s.sink.Read(ctx)
}

func (s *Service) Verify(ctx context.Context) error {
	if err := s.sink.Verify(ctx); err != nil {
		_ = s.alerts.Alert(ctx, "PROTECTED_AUDIT_TAMPERED", err.Error())
		return err
	}
	return nil
}

func complete(record Record) bool {
	return record.ID != "" && record.Action != "" && record.Actor != "" && record.Workload != "" && record.Reason != "" && record.Ticket != "" && record.Traceparent != "" && record.Scope.ResourceID != "" && (record.OldDigest != "" || record.NewDigest != "")
}

type MemorySink struct {
	lock        sync.Mutex
	records     []Record
	unavailable bool
}

func (s *MemorySink) Append(_ context.Context, record Record) (Record, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.unavailable {
		return Record{}, problem.New(problem.CodeInfrastructureUnavailable, "")
	}
	for _, prior := range s.records {
		if prior.ID == record.ID {
			if prior == record {
				return prior, nil
			}
			return Record{}, problem.New(problem.CodeIdempotencyConflict, "")
		}
	}
	if len(s.records) > 0 {
		record.PreviousDigest = s.records[len(s.records)-1].Digest
	}
	record.Digest = digestRecord(record)
	s.records = append(s.records, record)
	return record, nil
}

func (s *MemorySink) Read(context.Context) ([]Record, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.unavailable {
		return nil, problem.New(problem.CodeInfrastructureUnavailable, "")
	}
	return append([]Record(nil), s.records...), nil
}

func (s *MemorySink) Verify(context.Context) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	previous := ""
	for index, record := range s.records {
		if record.PreviousDigest != previous || record.Digest != digestRecord(record) {
			return fmt.Errorf("protected audit chain mismatch at record %d", index)
		}
		previous = record.Digest
	}
	return nil
}

func (s *MemorySink) SetUnavailable(value bool) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.unavailable = value
}

// Corrupt is test-only behavior of the in-memory conformance stand-in.
func (s *MemorySink) Corrupt(index int) {
	s.lock.Lock()
	defer s.lock.Unlock()
	if index >= 0 && index < len(s.records) {
		s.records[index].Outcome = "rewritten"
	}
}

func digestRecord(record Record) string {
	copyRecord := record
	copyRecord.Digest = ""
	encoded, _ := json.Marshal(copyRecord)
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:])
}

type MemoryAlerts struct {
	lock   sync.Mutex
	Values []string
}

func (a *MemoryAlerts) Alert(_ context.Context, code, detail string) error {
	a.lock.Lock()
	defer a.lock.Unlock()
	a.Values = append(a.Values, code+":"+detail)
	return nil
}
