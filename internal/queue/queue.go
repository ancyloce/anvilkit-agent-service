// Package queue implements at-least-once write-then-ack handoffs with inbox dedup.
package queue

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"sync"
	"time"
)

type Message struct {
	ID, WorkspaceID, ProjectID, Topic string
	Payload                           []byte
	Attempts                          int
	AvailableAt                       time.Time
}
type DLQ struct {
	Message            Message
	Code, Stage, RunID string
	CreatedAt          time.Time
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
}

func New(b Broker, i Inbox, e Effect, max int, inject func(FailurePoint) error) (*Processor, error) {
	if b == nil || i == nil || e == nil || max < 1 {
		return nil, fmt.Errorf("queue processor dependencies are invalid")
	}
	return &Processor{b, i, e, inject, max}, nil
}
func (p *Processor) Handle(ctx context.Context, m Message) error {
	if m.ID == "" || m.WorkspaceID == "" || m.ProjectID == "" || m.Topic == "" || len(m.Payload) == 0 {
		return problem.New(problem.CodeRequestInvalid, "")
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
func (p *Processor) failOrDLQ(ctx context.Context, m Message, cause error) error {
	if m.Attempts < p.maxAttempts {
		return cause
	}
	if err := p.broker.DeadLetter(ctx, DLQ{Message: m, Code: string(problem.CodeWorkerFailed), Stage: "queue-consume", RunID: runID(m.Payload), CreatedAt: time.Now()}); err != nil {
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
func runID(payload []byte) string {
	const prefix = `"runId":"`
	index := bytes.Index(payload, []byte(prefix))
	if index < 0 {
		return "unknown"
	}
	rest := payload[index+len(prefix):]
	end := bytes.IndexByte(rest, '"')
	if end < 0 {
		return "unknown"
	}
	return string(rest[:end])
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
	m.lock.Lock()
	defer m.lock.Unlock()
	identity := messageKey(v)
	if prior, ok := m.messages[identity]; ok {
		if prior.Topic != v.Topic || !bytes.Equal(prior.Payload, v.Payload) {
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
	m.acked[messageKey(message)] = true
	return nil
}
func (m *Memory) DeadLetter(_ context.Context, v DLQ) error {
	m.lock.Lock()
	defer m.lock.Unlock()
	for _, prior := range m.dlq {
		if messageKey(prior.Message) != messageKey(v.Message) {
			continue
		}
		if prior.Code != v.Code || prior.Stage != v.Stage || prior.RunID != v.RunID || !bytes.Equal(prior.Message.Payload, v.Message.Payload) {
			return problem.New(problem.CodeIdempotencyConflict, "")
		}
		return nil
	}
	m.dlq = append(m.dlq, v)
	return nil
}
func (m *Memory) Begin(_ context.Context, v Message) (bool, error) {
	m.lock.Lock()
	defer m.lock.Unlock()
	sum := sha256.Sum256(v.Payload)
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
	m.committed[messageKey(v)] = true
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
	message := m.dlq[index].Message
	m.lock.Unlock()
	return p.Handle(ctx, message)
}
