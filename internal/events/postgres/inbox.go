// Package postgres implements the durable public event store: the projection
// writer that is the only path from an internal fact to a public event, the
// replay reader that proves every stored event against its provenance, and
// the consumer inbox below.
package postgres

import (
	"bytes"
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ancyloce/anvilkit-agent-service/internal/events"
)

// Inbox deduplicates inbound messages by consumer and message identity. It
// writes no public event: a consumed message is a delivery fact, and turning
// one into a public event is the projector's decision, made from recorded
// evidence, never a side effect of accepting a message.
type Inbox struct {
	database *pgxpool.Pool
}

func NewInbox(database *pgxpool.Pool) (*Inbox, error) {
	if database == nil {
		return nil, fmt.Errorf("event inbox: a database is required")
	}
	return &Inbox{database: database}, nil
}

var _ events.Inbox = (*Inbox)(nil)

func (i *Inbox) Accept(ctx context.Context, message events.InboxMessage) (events.InboxResult, error) {
	if err := message.Scope.Validate(); err != nil {
		return "", err
	}
	result, err := i.database.Exec(ctx, `INSERT INTO agent_events.inbox(workspace_id, project_id, consumer, message_id, payload_digest) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING`, message.Scope.WorkspaceID, message.Scope.ProjectID, message.Consumer, message.MessageID, message.Digest)
	if err != nil {
		return "", fmt.Errorf("record inbox message: %w", err)
	}
	if result.RowsAffected() == 1 {
		return events.InboxAccepted, nil
	}
	var existing []byte
	if err := i.database.QueryRow(ctx, `SELECT payload_digest FROM agent_events.inbox WHERE workspace_id=$1 AND project_id=$2 AND consumer=$3 AND message_id=$4`, message.Scope.WorkspaceID, message.Scope.ProjectID, message.Consumer, message.MessageID).Scan(&existing); err != nil {
		return "", fmt.Errorf("read inbox duplicate: %w", err)
	}
	if !bytes.Equal(existing, message.Digest) {
		return "", fmt.Errorf("inbox conflict: message ID reused with different digest")
	}
	return events.InboxDuplicate, nil
}
