package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ancyloce/anvilkit-agent-service/internal/events"
)

// StreamCursors durably records the last successfully sent public cursor of
// every ended stream connection, so a disconnect — a slow consumer above all
// — leaves an operational record of exactly what the client had.
type StreamCursors struct {
	database *pgxpool.Pool
}

func NewStreamCursors(database *pgxpool.Pool) (*StreamCursors, error) {
	if database == nil {
		return nil, fmt.Errorf("stream cursors: a database is required")
	}
	return &StreamCursors{database: database}, nil
}

var _ events.CursorRecorder = (*StreamCursors)(nil)

func (s *StreamCursors) RecordCursor(ctx context.Context, scope events.Scope, runID, connectionID, lastEventID, reason string) error {
	if scope.WorkspaceID == "" || scope.ProjectID == "" || runID == "" || connectionID == "" || reason == "" {
		return fmt.Errorf("stream cursors: a complete connection record is required")
	}
	if _, err := s.database.Exec(ctx, `INSERT INTO agent_events.stream_cursors(workspace_id,project_id,run_id,connection_id,last_event_id,reason,recorded_at) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (workspace_id,project_id,connection_id) DO NOTHING`, scope.WorkspaceID, scope.ProjectID, runID, connectionID, lastEventID, reason, time.Now().UTC()); err != nil {
		return fmt.Errorf("record stream cursor: %w", err)
	}
	return nil
}
