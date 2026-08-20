package execution

import (
	"context"
	"fmt"
	"sync"
)

// ScriptProposal is what the controlled adapter would consume for one new
// provider operation, together with the script bounds the settlement decision
// needs. The decision itself is made inside the ledger's durable transaction,
// so two processes racing on the same operation identity cannot both advance
// the script.
type ScriptProposal struct {
	Key                                   string
	RetryableFailures                     int
	ScriptLength                          int
	InputTokens, OutputTokens, CostMicros int64
}

// ScriptOperation is the durable record of one settled provider operation:
// the script position it consumed, whether it settled as a provider failure,
// and the usage it caused.
type ScriptOperation struct {
	Key                                   string
	Position                              int
	Failure                               bool
	InputTokens, OutputTokens, CostMicros int64
}

// ScriptLedger is the durable, process-external record of the controlled
// model adapter's settled provider operations. Provider idempotency, the
// settled outcome, the script position, and the usage evidence all live here
// rather than in adapter memory, so a replay after a real process or adapter
// restart reads what already happened instead of calling the provider again,
// advancing the script again, or duplicating billing.
type ScriptLedger interface {
	// Settled returns the recorded outcome for one operation identity.
	Settled(context.Context, string) (ScriptOperation, bool, error)
	// Settle records one operation exactly once, assigning its failure
	// decision and script position from the operations already recorded. When
	// the identity is already settled it returns the stored record unchanged.
	Settle(context.Context, ScriptProposal) (ScriptOperation, error)
	// Count reports how many distinct provider operations have settled.
	Count(context.Context) (int, error)
}

// MemoryScriptLedger is the in-process implementation of the durable ledger.
// It is a test double for the durable store, not a substitute for it: it is
// shared explicitly between adapter instances so a restart can be modelled,
// and production composition never selects it.
type MemoryScriptLedger struct {
	lock       sync.Mutex
	operations map[string]ScriptOperation
	order      []string
}

func NewMemoryScriptLedger() *MemoryScriptLedger {
	return &MemoryScriptLedger{operations: make(map[string]ScriptOperation)}
}

func (l *MemoryScriptLedger) Settled(_ context.Context, key string) (ScriptOperation, bool, error) {
	l.lock.Lock()
	defer l.lock.Unlock()
	operation, settled := l.operations[key]
	return operation, settled, nil
}

func (l *MemoryScriptLedger) Settle(_ context.Context, proposal ScriptProposal) (ScriptOperation, error) {
	if proposal.Key == "" || proposal.ScriptLength < 1 {
		return ScriptOperation{}, fmt.Errorf("script ledger: an operation identity and a loaded script are required")
	}
	l.lock.Lock()
	defer l.lock.Unlock()
	if operation, settled := l.operations[proposal.Key]; settled {
		return operation, nil
	}
	failures, advanced := 0, 0
	for _, recorded := range l.operations {
		if recorded.Failure {
			failures++
			continue
		}
		advanced++
	}
	operation := SettlementFor(proposal, failures, advanced)
	l.operations[proposal.Key] = operation
	l.order = append(l.order, proposal.Key)
	return operation, nil
}

func (l *MemoryScriptLedger) Count(context.Context) (int, error) {
	l.lock.Lock()
	defer l.lock.Unlock()
	return len(l.operations), nil
}

// SettlementFor is the one settlement rule every ledger implementation
// applies: the configured number of retryable failures settle first, and every
// later operation takes the next script position, holding at the last output
// once the script is exhausted. It is exported so the durable implementation
// decides exactly as the in-process one does.
func SettlementFor(proposal ScriptProposal, failures, advanced int) ScriptOperation {
	operation := ScriptOperation{Key: proposal.Key, InputTokens: proposal.InputTokens, OutputTokens: proposal.OutputTokens, CostMicros: proposal.CostMicros}
	if failures < proposal.RetryableFailures {
		operation.Failure = true
		operation.Position = -1
		return operation
	}
	position := advanced
	if position >= proposal.ScriptLength {
		position = proposal.ScriptLength - 1
	}
	operation.Position = position
	return operation
}

var _ ScriptLedger = (*MemoryScriptLedger)(nil)
