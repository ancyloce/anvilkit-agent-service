// Package queue implements at-least-once write-then-ack handoffs with inbox dedup.
package queue

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sync"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
)

type Message struct {
	ID, WorkspaceID, ProjectID, RunID, TaskID, Topic string
	Payload                                          []byte
	Attempts                                         int
	AvailableAt                                      time.Time
}
type DLQ struct {
	Message                    Message
	Code, Stage, RunID, Detail string
	CreatedAt                  time.Time
	Replayed                   bool
}
type Broker interface {
	Publish(context.Context, Message) error
	Ack(context.Context, Message) error
	DeadLetter(context.Context, DLQ) error
}
type Inbox interface {
	Begin(context.Context, Message) (bool, error)
	Commit(context.Context, Message) error
}
type Effect interface {
	Write(context.Context, Message) error
}
type FailurePoint string

const (
	AfterEffect      FailurePoint = "after-effect"
	AfterInboxCommit FailurePoint = "after-inbox-commit"
	BeforeAck        FailurePoint = "before-ack"
)

type Processor struct {
	broker      Broker
	inbox       Inbox
	effect      Effect
	inject      func(FailurePoint) error
	maxAttempts int
	clock       Clock
}
type Clock interface{ Now() time.Time }
type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now().UTC() }

func New(b Broker, i Inbox, e Effect, max int, inject func(FailurePoint) error) (*Processor, error) {
	return NewWithClock(b, i, e, systemClock{}, max, inject)
}
func NewWithClock(b Broker, i Inbox, e Effect, clock Clock, max int, inject func(FailurePoint) error) (*Processor, error) {
	if b == nil || i == nil || e == nil || clock == nil || max < 1 || max > 100 {
		return nil, fmt.Errorf("queue processor dependencies are invalid")
	}
	return &Processor{broker: b, inbox: i, effect: e, inject: inject, maxAttempts: max, clock: clock}, nil
}
func (p *Processor) Handle(ctx context.Context, m Message) error {
	if err := Validate(m); err != nil {
		return err
	}
	fresh, err := p.inbox.Begin(ctx, m)
	if err != nil {
		return err
	}
	if fresh {
		if err := p.effect.Write(ctx, m); err != nil {
			return p.failOrDLQ(ctx, m, err)
		}
		if err := p.fail(AfterEffect); err != nil {
			return err
		}
		if err := p.inbox.Commit(ctx, m); err != nil {
			return err
		}
		if err := p.fail(AfterInboxCommit); err != nil {
			return err
		}
	}
	if err := p.fail(BeforeAck); err != nil {
		return err
	}
	return p.broker.Ack(ctx, m)
}
func Validate(m Message) error {
	if !validID(m.ID) || !validID(m.WorkspaceID) || !validID(m.ProjectID) || !validID(m.RunID) || !validID(m.TaskID) || !validID(m.Topic) || len(m.Payload) == 0 || len(m.Payload) > 1<<20 || m.Attempts < 0 || m.Attempts > 100 {
		return problem.New(problem.CodeRequestInvalid, "")
	}
	return nil
}
func (p *Processor) failOrDLQ(ctx context.Context, m Message, cause error) error {
	if m.Attempts < p.maxAttempts {
		return cause
	}
	now := p.clock.Now().UTC()
	if now.IsZero() {
		return problem.New(problem.CodeInfrastructureUnavailable, "")
	}
	detail := cause.Error()
	if len(detail) > 2048 {
		detail = detail[:2048]
	}
	if err := p.broker.DeadLetter(ctx, DLQ{Message: m, Code: string(problem.CodeWorkerFailed), Stage: "queue-consume", RunID: m.RunID, Detail: detail, CreatedAt: now}); err != nil {
		return err
	}
	return p.broker.Ack(ctx, m)
}
func (p *Processor) fail(point FailurePoint) error {
	if p.inject == nil {
		return nil
	}
	return p.inject(point)
}
func validID(value string) bool {
	if len(value) < 1 || len(value) > 128 {
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

type Memory struct {
	lock      sync.Mutex
	messages  map[string]Message
	acked     map[string]bool
	dlq       []DLQ
	inbox     map[string][32]byte
	committed map[string]bool
	effects   map[string][32]byte
}

func NewMemory() *Memory {
	return &Memory{messages: map[string]Message{}, acked: map[string]bool{}, inbox: map[string][32]byte{}, committed: map[string]bool{}, effects: map[string][32]byte{}}
}
func messageKey(v Message) string {
	return v.WorkspaceID + "\x00" + v.ProjectID + "\x00" + v.ID
}
func (m *Memory) Publish(_ context.Context, v Message) error {
	if err := Validate(v); err != nil {
		return err
	}
	m.lock.Lock()
	defer m.lock.Unlock()
	identity := messageKey(v)
	if prior, ok := m.messages[identity]; ok {
		if messageDigest(prior) != messageDigest(v) {
			return problem.New(problem.CodeIdempotencyConflict, "")
		}
		return nil
	}
	m.messages[identity] = v
	return nil
}
func (m *Memory) Ack(_ context.Context, message Message) error {
	m.lock.Lock()
	defer m.lock.Unlock()
	identity := messageKey(message)
	prior, exists := m.inbox[identity]
	if !exists || prior != messageDigest(message) || (!m.committed[identity] && !m.deadLettered(identity)) {
		return problem.New(problem.CodeWorkerFenceStale, "")
	}
	m.acked[identity] = true
	return nil
}
func (m *Memory) DeadLetter(_ context.Context, v DLQ) error {
	if err := Validate(v.Message); err != nil {
		return err
	}
	if v.RunID != v.Message.RunID || v.Code == "" || v.Stage == "" || len(v.Code) > 128 || len(v.Stage) > 128 || len(v.Detail) > 2048 || v.CreatedAt.IsZero() {
		return problem.New(problem.CodeRequestInvalid, "")
	}
	m.lock.Lock()
	defer m.lock.Unlock()
	for _, prior := range m.dlq {
		if messageKey(prior.Message) != messageKey(v.Message) {
			continue
		}
		if prior.Code != v.Code || prior.Stage != v.Stage || prior.RunID != v.RunID || prior.Detail != v.Detail || messageDigest(prior.Message) != messageDigest(v.Message) {
			return problem.New(problem.CodeIdempotencyConflict, "")
		}
		return nil
	}
	m.dlq = append(m.dlq, v)
	return nil
}
func (m *Memory) Begin(_ context.Context, v Message) (bool, error) {
	if err := Validate(v); err != nil {
		return false, err
	}
	m.lock.Lock()
	defer m.lock.Unlock()
	sum := messageDigest(v)
	identity := messageKey(v)
	if prior, ok := m.inbox[identity]; ok {
		if prior != sum {
			return false, problem.New(problem.CodeIdempotencyConflict, "")
		}
		return !m.committed[identity], nil
	}
	m.inbox[identity] = sum
	return true, nil
}
func (m *Memory) Commit(_ context.Context, v Message) error {
	m.lock.Lock()
	defer m.lock.Unlock()
	identity := messageKey(v)
	prior, exists := m.inbox[identity]
	if !exists || prior != messageDigest(v) {
		return problem.New(problem.CodeIdempotencyConflict, "")
	}
	m.committed[identity] = true
	return nil
}
func (m *Memory) Write(_ context.Context, v Message) error {
	m.lock.Lock()
	defer m.lock.Unlock()
	sum := sha256.Sum256(v.Payload)
	identity := messageKey(v)
	if prior, ok := m.effects[identity]; ok && prior != sum {
		return problem.New(problem.CodeIdempotencyConflict, "")
	}
	m.effects[identity] = sum
	return nil
}
func (m *Memory) Stats() (int, int, int) {
	m.lock.Lock()
	defer m.lock.Unlock()
	return len(m.effects), len(m.acked), len(m.dlq)
}
func (m *Memory) Replay(ctx context.Context, index int, p *Processor) error {
	m.lock.Lock()
	if index < 0 || index >= len(m.dlq) {
		m.lock.Unlock()
		return problem.New(problem.CodeResourceNotFound, "")
	}
	if m.dlq[index].Replayed {
		m.lock.Unlock()
		return nil
	}
	m.dlq[index].Replayed = true
	message := m.dlq[index].Message
	message.Attempts = 0
	m.lock.Unlock()
	if err := p.Handle(ctx, message); err != nil {
		m.lock.Lock()
		m.dlq[index].Replayed = false
		m.lock.Unlock()
		return err
	}
	return nil
}

func messageDigest(value Message) [32]byte {
	bytes := make([]byte, 0, len(value.Topic)+len(value.RunID)+len(value.TaskID)+len(value.Payload)+3)
	bytes = append(bytes, value.Topic...)
	bytes = append(bytes, 0)
	bytes = append(bytes, value.RunID...)
	bytes = append(bytes, 0)
	bytes = append(bytes, value.TaskID...)
	bytes = append(bytes, 0)
	bytes = append(bytes, value.Payload...)
	return sha256.Sum256(bytes)
}
func (m *Memory) deadLettered(identity string) bool {
	for _, value := range m.dlq {
		if messageKey(value.Message) == identity {
			return true
		}
	}
	return false
}
