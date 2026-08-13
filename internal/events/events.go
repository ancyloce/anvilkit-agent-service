// Package events owns per-run sequence allocation, outbox, and replay.
package events

import (
	"context"
	"encoding/json"
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

type Transition struct {
	Scope           Scope
	RunID           string
	ExpectedVersion int64
	NextState       string
	Snapshot        json.RawMessage
	EventID         string
	EventBytes      []byte
	OutboxID        string
	Topic           string
	OutboxBytes     []byte
	WorkflowID      string
	WorkflowVersion int
	Checkpoint      string
	CheckpointBytes []byte
	ProblemBytes    []byte
}

type Committed struct {
	Version  int64
	Sequence Sequence
}

type Repository interface {
	Commit(context.Context, Transition) (Committed, error)
}

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
