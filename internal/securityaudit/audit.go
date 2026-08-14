package securityaudit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/canonical"
	"github.com/ancyloce/anvilkit-agent-service/internal/journal"
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
	Append(context.Context, Record) (Record, bool, error)
	Read(context.Context) ([]Record, error)
	Verify(context.Context) error
}
type AlertSink interface {
	Alert(context.Context, string, string) error
}
type Mutation func(context.Context) error

type Service struct {
	sink     ProtectedSink
	clock    *AuthoritativeClock
	alerts   AlertSink
	receipts journal.Store
}

func NewService(sink ProtectedSink, clock *AuthoritativeClock, alerts AlertSink, receipts journal.Store) (*Service, error) {
	if sink == nil || clock == nil || alerts == nil || receipts == nil {
		return nil, fmt.Errorf("protected sink, authoritative clock, alerts, and receipt journal are required")
	}
	return &Service{sink: sink, clock: clock, alerts: alerts, receipts: receipts}, nil
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
	_, inserted, err := s.sink.Append(ctx, record)
	if err != nil {
		return fmt.Errorf("protected audit unavailable: %w", err)
	}
	if !inserted {
		return problem.New(problem.CodeIdempotencyConflict, "")
	}
	mutationErr := mutation(ctx)
	outcome := record
	outcome.ID += ":outcome"
	if mutationErr != nil {
		outcome.Outcome = "failed"
	} else {
		outcome.Outcome = "applied"
	}
	retained, inserted, err := s.sink.Append(ctx, outcome)
	if err != nil {
		return fmt.Errorf("privileged mutation outcome is unknown: %w", err)
	}
	if !inserted {
		return problem.New(problem.CodeIdempotencyConflict, "")
	}
	if err := s.appendReceipt(ctx, retained); err != nil {
		return err
	}
	if mutationErr != nil {
		return mutationErr
	}
	return nil
}

func (s *Service) appendReceipt(ctx context.Context, retained Record) error {
	raw, err := json.Marshal(retained)
	if err != nil {
		return fmt.Errorf("marshal privileged audit receipt: %w", err)
	}
	canonicalBytes, err := canonical.Bytes(raw)
	if err != nil {
		return fmt.Errorf("canonicalize privileged audit receipt: %w", err)
	}
	fact, err := journal.NewFact(retained.Scope.WorkspaceID+":privileged-audit:"+retained.ID, retained.Scope.WorkspaceID, retained.Scope.ProjectID, journal.FactPrivilegedAudit, canonicalBytes, raw)
	if err != nil {
		return err
	}
	if _, err := s.receipts.Append(ctx, fact); err != nil {
		return fmt.Errorf("privileged audit fact remains unacknowledged: %w", err)
	}
	return nil
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
	if record.UTC != (time.Time{}) || record.Outcome != "" || record.PreviousDigest != "" || record.Digest != "" || !opaque(record.ID, 120) || !opaque(record.Action, 128) || !opaque(record.Actor, 128) || !opaque(record.Workload, 128) || !opaque(record.Ticket, 128) || !opaque(record.Scope.WorkspaceID, 128) || !opaque(record.Scope.ProjectID, 128) || !opaque(record.Scope.ResourceID, 128) || len(record.Reason) < 1 || len(record.Reason) > 1024 || !printable(record.Reason) || !trace(record.Traceparent) {
		return false
	}
	if record.OldDigest == "" && record.NewDigest == "" {
		return false
	}
	return (record.OldDigest == "" || digest(record.OldDigest)) && (record.NewDigest == "" || digest(record.NewDigest))
}

type MemorySink struct {
	lock        sync.Mutex
	records     []Record
	unavailable bool
}

func (s *MemorySink) Append(_ context.Context, record Record) (Record, bool, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.unavailable {
		return Record{}, false, problem.New(problem.CodeInfrastructureUnavailable, "")
	}
	for _, prior := range s.records {
		if prior.ID == record.ID {
			if sameRecordContent(prior, record) {
				return prior, false, nil
			}
			return Record{}, false, problem.New(problem.CodeIdempotencyConflict, "")
		}
	}
	if len(s.records) > 0 {
		record.PreviousDigest = s.records[len(s.records)-1].Digest
	}
	record.Digest = digestRecord(record)
	s.records = append(s.records, record)
	return record, true, nil
}

func sameRecordContent(left, right Record) bool {
	left.PreviousDigest, left.Digest = "", ""
	right.PreviousDigest, right.Digest = "", ""
	return left == right
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

func opaque(value string, maximum int) bool {
	if len(value) < 1 || len(value) > maximum {
		return false
	}
	for index, character := range value {
		if (character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || (index > 0 && (character == '.' || character == '_' || character == ':' || character == '-')) {
			continue
		}
		return false
	}
	return true
}
func printable(value string) bool {
	for _, character := range value {
		if character < 0x20 || character > 0x7e {
			return false
		}
	}
	return true
}
func digest(value string) bool {
	if len(value) != 71 || value[:7] != "sha256:" {
		return false
	}
	for _, character := range value[7:] {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}
func trace(value string) bool {
	if len(value) != 55 || value[:3] != "00-" || value[35] != '-' || value[52] != '-' || value[3:35] == "00000000000000000000000000000000" || value[36:52] == "0000000000000000" {
		return false
	}
	for index, character := range value {
		if index == 2 || index == 35 || index == 52 {
			continue
		}
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
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
