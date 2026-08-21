// Package events owns per-run sequence allocation, outbox, and replay.
package events

import (
	"context"
	"fmt"
)

type Sequence uint64

type Scope struct{ WorkspaceID, ProjectID string }

func (s Scope) Validate() error {
	if s.WorkspaceID == "" || s.ProjectID == "" {
		return fmt.Errorf("event scope requires workspace and project")
	}
	return nil
}

// A durable public event has no caller-supplied write shape. Every one is
// produced by the repository-owned projector from an authoritative
// AgentEvidence record (ADR-020 §2), so there is no transition type here for a
// caller to hand this package event bytes, a source evidence reference, or a
// projector identity of its own choosing.

type InboxMessage struct {
	Scope               Scope
	Consumer, MessageID string
	Digest              []byte
}
type InboxResult string

const (
	InboxAccepted  InboxResult = "accepted"
	InboxDuplicate InboxResult = "duplicate"
)

type Inbox interface {
	Accept(context.Context, InboxMessage) (InboxResult, error)
}
