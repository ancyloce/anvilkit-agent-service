// Package agent owns the pure Agent runtime domain: digest-pinned
// AgentDefinitions, the deterministic AgentRegistry, and the explicit
// TurnDecision contract. It holds no durable state and calls no engine,
// provider, or transport code.
package agent

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Usage accumulates model consumption deterministically across turns.
type Usage struct {
	ModelCalls   int64 `json:"modelCalls"`
	InputTokens  int64 `json:"inputTokens"`
	OutputTokens int64 `json:"outputTokens"`
	CostMicros   int64 `json:"costMicros"`
}

func (u Usage) Add(other Usage) Usage {
	return Usage{
		ModelCalls:   u.ModelCalls + other.ModelCalls,
		InputTokens:  u.InputTokens + other.InputTokens,
		OutputTokens: u.OutputTokens + other.OutputTokens,
		CostMicros:   u.CostMicros + other.CostMicros,
	}
}

// DecisionKind enumerates the only legal turn decisions. Every turn resolves
// to exactly one kind with exactly one matching payload; there is no default
// or fallthrough decision.
type DecisionKind string

const (
	DecisionContinue  DecisionKind = "continue"
	DecisionToolCall  DecisionKind = "tool_call"
	DecisionDelegate  DecisionKind = "delegate_agent"
	DecisionNeedInput DecisionKind = "need_input"
	DecisionFinal     DecisionKind = "final"
	DecisionRefuse    DecisionKind = "refuse"
)

func DecisionKinds() []DecisionKind {
	return []DecisionKind{DecisionContinue, DecisionToolCall, DecisionDelegate, DecisionNeedInput, DecisionFinal, DecisionRefuse}
}

const (
	maximumNoteBytes      = 4096
	maximumQuestionBytes  = 4096
	maximumReasonBytes    = 4096
	maximumArgumentBytes  = 65536
	maximumCandidateBytes = 262144
)

type ContinueDecision struct {
	Note string `json:"note,omitempty"`
}

type ToolCallDecision struct {
	ToolID    string          `json:"toolId"`
	Arguments json.RawMessage `json:"arguments"`
}

type DelegateDecision struct {
	DelegateID string          `json:"delegateId"`
	Input      json.RawMessage `json:"input"`
}

type NeedInputDecision struct {
	Question string `json:"question"`
}

type FinalDecision struct {
	Candidate json.RawMessage `json:"candidate"`
	Summary   string          `json:"summary,omitempty"`
}

type RefuseDecision struct {
	Reason string `json:"reason"`
}

// TurnDecision is the explicit, serializable decision contract every turn
// produces. Exactly one payload matching Kind must be present.
type TurnDecision struct {
	Kind      DecisionKind       `json:"kind"`
	Continue  *ContinueDecision  `json:"continue,omitempty"`
	ToolCall  *ToolCallDecision  `json:"toolCall,omitempty"`
	Delegate  *DelegateDecision  `json:"delegate,omitempty"`
	NeedInput *NeedInputDecision `json:"needInput,omitempty"`
	Final     *FinalDecision     `json:"final,omitempty"`
	Refuse    *RefuseDecision    `json:"refuse,omitempty"`
}

// Validate enforces the exactly-one-payload invariant and every payload
// bound. A decision that fails validation must never reach an effect.
func (d TurnDecision) Validate() error {
	payloads := 0
	for _, present := range []bool{d.Continue != nil, d.ToolCall != nil, d.Delegate != nil, d.NeedInput != nil, d.Final != nil, d.Refuse != nil} {
		if present {
			payloads++
		}
	}
	if payloads != 1 {
		return fmt.Errorf("turn decision: exactly one payload is required, found %d", payloads)
	}
	switch d.Kind {
	case DecisionContinue:
		if d.Continue == nil {
			return payloadMismatch(d.Kind)
		}
		if !boundedText(d.Continue.Note, maximumNoteBytes) {
			return fmt.Errorf("turn decision: continue note exceeds the bounded contract")
		}
	case DecisionToolCall:
		if d.ToolCall == nil {
			return payloadMismatch(d.Kind)
		}
		if !validComponentID(d.ToolCall.ToolID) {
			return fmt.Errorf("turn decision: tool identity is required and bounded")
		}
		if len(d.ToolCall.Arguments) == 0 || len(d.ToolCall.Arguments) > maximumArgumentBytes || !json.Valid(d.ToolCall.Arguments) {
			return fmt.Errorf("turn decision: tool arguments must be bounded JSON")
		}
	case DecisionDelegate:
		if d.Delegate == nil {
			return payloadMismatch(d.Kind)
		}
		if !validComponentID(d.Delegate.DelegateID) {
			return fmt.Errorf("turn decision: delegate identity is required and bounded")
		}
		if len(d.Delegate.Input) == 0 || len(d.Delegate.Input) > maximumArgumentBytes || !json.Valid(d.Delegate.Input) {
			return fmt.Errorf("turn decision: delegate input must be bounded JSON")
		}
	case DecisionNeedInput:
		if d.NeedInput == nil {
			return payloadMismatch(d.Kind)
		}
		if d.NeedInput.Question == "" || !boundedText(d.NeedInput.Question, maximumQuestionBytes) {
			return fmt.Errorf("turn decision: input question is required and bounded")
		}
	case DecisionFinal:
		if d.Final == nil {
			return payloadMismatch(d.Kind)
		}
		if len(d.Final.Candidate) == 0 || len(d.Final.Candidate) > maximumCandidateBytes || !json.Valid(d.Final.Candidate) {
			return fmt.Errorf("turn decision: final candidate must be bounded JSON")
		}
		if !boundedText(d.Final.Summary, maximumNoteBytes) {
			return fmt.Errorf("turn decision: final summary exceeds the bounded contract")
		}
	case DecisionRefuse:
		if d.Refuse == nil {
			return payloadMismatch(d.Kind)
		}
		if d.Refuse.Reason == "" || !boundedText(d.Refuse.Reason, maximumReasonBytes) {
			return fmt.Errorf("turn decision: refusal reason is required and bounded")
		}
	default:
		return fmt.Errorf("turn decision: unknown kind %q", d.Kind)
	}
	return nil
}

func payloadMismatch(kind DecisionKind) error {
	return fmt.Errorf("turn decision: payload does not match kind %q", kind)
}

func boundedText(value string, maximum int) bool {
	return len(value) <= maximum && utf8.ValidString(value)
}

func validComponentID(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	if !asciiAlphaNumeric(value[0]) {
		return false
	}
	for index := 1; index < len(value); index++ {
		character := value[index]
		if !asciiAlphaNumeric(character) && character != '.' && character != '_' && character != ':' && character != '-' {
			return false
		}
	}
	return true
}

func asciiAlphaNumeric(character byte) bool {
	return character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' || character >= '0' && character <= '9'
}

// CostMicros converts a governed decimal cost string into the micros this
// service accounts in. It is here, beside Usage, because the wire carries a
// decimal and every consumer of usage needs the same conversion: a second
// parser would eventually disagree with this one about a fraction.
func CostMicros(amount string) (int64, error) {
	if amount == "" || len(amount) > 20 {
		return 0, fmt.Errorf("cost amount is required and bounded")
	}
	whole, fraction, split := strings.Cut(amount, ".")
	units, err := strconv.ParseInt(whole, 10, 64)
	if err != nil || units < 0 {
		return 0, fmt.Errorf("cost amount must be a non-negative decimal")
	}
	micros := units * 1_000_000
	if split {
		if fraction == "" || len(fraction) > 6 {
			return 0, fmt.Errorf("cost amount fraction must contain 1-6 digits")
		}
		padded := fraction + strings.Repeat("0", 6-len(fraction))
		part, err := strconv.ParseInt(padded, 10, 64)
		if err != nil || part < 0 {
			return 0, fmt.Errorf("cost amount fraction must be numeric")
		}
		micros += part
	}
	return micros, nil
}
