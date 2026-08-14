// Package usage records every physical attempt independently of result acceptance.
package usage

import (
	"context"
	"fmt"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

type Observation struct {
	WorkspaceID, ProjectID, ObservationID, RootRunID, RunID, TaskID                    string
	RecoveryEpoch, ExecutionGeneration                                                 uint64
	PhysicalAttemptID, ReservationID, ProviderEventID, Meter, Quantity, Unit, Currency string
	CostMicros                                                                         int64
	MeterSequence                                                                      uint64
	Final                                                                              bool
	ObservedAt                                                                         time.Time
	Provider, BuildIdentity, Traceparent                                               string
}
type Record struct {
	Observation
	DedupKey string
	Repaired bool
}
type Store interface {
	Append(context.Context, Record) (bool, error)
	ForAttempt(context.Context, string, string, string, uint64, uint64, string) ([]Record, error)
}
type Sink interface {
	Observe(context.Context, Observation) error
}
type Pipeline struct {
	store Store
	sink  Sink
}

func New(store Store, sink Sink) (*Pipeline, error) {
	if store == nil || sink == nil {
		return nil, fmt.Errorf("usage store and authoritative sink are required")
	}
	return &Pipeline{store, sink}, nil
}
func (p *Pipeline) Accept(ctx context.Context, value Observation) (bool, error) {
	if err := Validate(value); err != nil {
		return false, err
	}
	record := Record{Observation: value, DedupKey: dedup(value)}
	accepted, err := p.store.Append(ctx, record)
	if err != nil {
		return false, err
	}
	// The sink is idempotent on observation identity. Retrying it even when
	// the durable append already exists closes the write-before-forward gap.
	if err := p.sink.Observe(ctx, value); err != nil {
		return false, fmt.Errorf("forward authoritative usage: %w", err)
	}
	return accepted, nil
}

// RepairFinal appends a billing-authoritative final high-water mark. It does
// not mutate tasks, artifacts, runs, or reservations locally.
func (p *Pipeline) RepairFinal(ctx context.Context, value Observation) (bool, error) {
	value.Final = true
	if value.ProviderEventID == "" {
		return false, problem.New(problem.CodeRequestInvalid, "")
	}
	if err := Validate(value); err != nil {
		return false, err
	}
	record := Record{Observation: value, DedupKey: dedup(value), Repaired: true}
	accepted, err := p.store.Append(ctx, record)
	if err != nil {
		return false, err
	}
	if err := p.sink.Observe(ctx, value); err != nil {
		return false, err
	}
	return accepted, nil
}
func (p *Pipeline) FinalKnown(ctx context.Context, value Observation) (bool, error) {
	if err := Validate(value); err != nil {
		return false, err
	}
	records, err := p.store.ForAttempt(ctx, value.WorkspaceID, value.ProjectID, value.TaskID, value.RecoveryEpoch, value.ExecutionGeneration, value.PhysicalAttemptID)
	if err != nil {
		return false, err
	}
	for _, record := range records {
		if record.Final {
			return true, nil
		}
	}
	return false, nil
}
func dedup(v Observation) string {
	scope := v.WorkspaceID + "\x00" + v.ProjectID + "\x00"
	if v.ProviderEventID != "" {
		return scope + "provider\x00" + v.Provider + "\x00" + v.ProviderEventID
	}
	return scope + fmt.Sprintf("attempt\x00%s\x00%d\x00%d\x00%s\x00%s\x00%d", v.TaskID, v.RecoveryEpoch, v.ExecutionGeneration, v.PhysicalAttemptID, v.Meter, v.MeterSequence)
}
func Validate(v Observation) error {
	ids := []string{v.WorkspaceID, v.ProjectID, v.ObservationID, v.RootRunID, v.RunID, v.TaskID, v.PhysicalAttemptID, v.ReservationID, v.Provider, v.BuildIdentity}
	for _, id := range ids {
		if !matches(opaqueIDPattern, id) {
			return problem.New(problem.CodeRequestInvalid, "")
		}
	}
	if v.ProviderEventID != "" && !matches(opaqueIDPattern, v.ProviderEventID) {
		return problem.New(problem.CodeRequestInvalid, "")
	}
	if v.ExecutionGeneration == 0 || v.MeterSequence > 9007199254740991 || len(v.Quantity) > 96 || !matches(decimalPattern, v.Quantity) || !validMeter(v.Meter) || !validUnit(v.Unit) || !matches(currencyPattern, v.Currency) || v.CostMicros < 0 || v.ObservedAt.IsZero() || !trace(v.Traceparent) {
		return problem.New(problem.CodeRequestInvalid, "")
	}
	return nil
}

const (
	opaqueIDPattern = `^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`
	decimalPattern  = `^(0|[1-9][0-9]*)(\.[0-9]+)?$`
	currencyPattern = `^[A-Z]{3}$`
)

func matches(pattern, value string) bool {
	matched, err := regexp.MatchString(pattern, value)
	return err == nil && matched
}
func validMeter(value string) bool {
	switch value {
	case "input-tokens", "output-tokens", "worker-duration", "gpu-duration", "provider-cost":
		return true
	default:
		return false
	}
}
func validUnit(value string) bool {
	switch value {
	case "token", "millisecond", "byte", "count", "usd-micro":
		return true
	default:
		return false
	}
}

func trace(value string) bool {
	if len(value) != 55 || value[:2] != "00" || value[2] != '-' || value[35] != '-' || value[52] != '-' || value[3:35] == strings.Repeat("0", 32) || value[36:52] == strings.Repeat("0", 16) {
		return false
	}
	for i, c := range value {
		if i == 2 || i == 35 || i == 52 {
			continue
		}
		if !strings.ContainsRune("0123456789abcdef", c) {
			return false
		}
	}
	return true
}

type MemoryStore struct {
	lock        sync.Mutex
	records     map[string]Record
	observation map[string]string
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{records: map[string]Record{}, observation: map[string]string{}}
}
func (s *MemoryStore) Append(_ context.Context, value Record) (bool, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	observationKey := value.WorkspaceID + "\x00" + value.ProjectID + "\x00" + value.ObservationID
	if priorKey, ok := s.observation[observationKey]; ok {
		prior := s.records[priorKey]
		if prior != value {
			return false, problem.New(problem.CodeIdempotencyConflict, "")
		}
		return false, nil
	}
	if prior, ok := s.records[value.DedupKey]; ok {
		if prior.Observation != value.Observation {
			return false, problem.New(problem.CodeIdempotencyConflict, "")
		}
		return false, nil
	}
	s.records[value.DedupKey] = value
	s.observation[observationKey] = value.DedupKey
	return true, nil
}
func (s *MemoryStore) ForAttempt(_ context.Context, workspace, project, task string, recovery, generation uint64, attempt string) ([]Record, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	var values []Record
	for _, v := range s.records {
		if v.WorkspaceID == workspace && v.ProjectID == project && v.TaskID == task && v.RecoveryEpoch == recovery && v.ExecutionGeneration == generation && v.PhysicalAttemptID == attempt {
			values = append(values, v)
		}
	}
	sort.Slice(values, func(i, j int) bool {
		if values[i].MeterSequence != values[j].MeterSequence {
			return values[i].MeterSequence < values[j].MeterSequence
		}
		if !values[i].ObservedAt.Equal(values[j].ObservedAt) {
			return values[i].ObservedAt.Before(values[j].ObservedAt)
		}
		return values[i].ObservationID < values[j].ObservationID
	})
	return values, nil
}
func (s *MemoryStore) Count() int { s.lock.Lock(); defer s.lock.Unlock(); return len(s.records) }

type MemorySink struct {
	lock   sync.Mutex
	Values []Observation
	seen   map[string]Observation
}

func (s *MemorySink) Observe(_ context.Context, v Observation) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.seen == nil {
		s.seen = map[string]Observation{}
	}
	key := v.WorkspaceID + "\x00" + v.ProjectID + "\x00" + v.ObservationID
	if prior, ok := s.seen[key]; ok {
		if prior != v {
			return problem.New(problem.CodeIdempotencyConflict, "")
		}
		return nil
	}
	s.seen[key] = v
	s.Values = append(s.Values, v)
	return nil
}
