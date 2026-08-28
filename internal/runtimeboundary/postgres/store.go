// Package postgres is the durable store behind the runtime boundary: the
// offered tasks a callback is bound against, and the immutable candidate
// submissions a committed result's document is read back from.
package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ancyloce/anvilkit-agent-service/contracts/generated/schema"
	"github.com/ancyloce/anvilkit-agent-service/internal/runtimeboundary"
)

// Store implements the boundary's TaskRegister and SubmissionStore over the
// durable schema.
type Store struct {
	database *pgxpool.Pool
}

// New binds the store to its pool.
func New(database *pgxpool.Pool) (*Store, error) {
	if database == nil {
		return nil, fmt.Errorf("runtime boundary store: a database pool is required")
	}
	return &Store{database: database}, nil
}

// Offer durably records the dispatched task and its compiled disclosure under
// the physical attempt identity. Re-offering the same attempt — a recovered
// dispatch step re-executing — refreshes the record idempotently. The record
// keeps no fence token: see Offered.
func (s *Store) Offer(ctx context.Context, task schema.AgentTask, compiled []byte) error {
	if task.PhysicalAttemptId == "" {
		return fmt.Errorf("runtime boundary store: a task with no physical attempt identity cannot be offered")
	}
	document, err := json.Marshal(runtimeboundary.Offered(task))
	if err != nil {
		return fmt.Errorf("runtime boundary store: encode task: %w", err)
	}
	if compiled == nil {
		compiled = []byte{}
	}
	_, err = s.database.Exec(ctx, `
		INSERT INTO agent_workflow.runtime_task_offers
		 (physical_attempt_id, task_document, compiled_context, offered_at)
		VALUES ($1, $2, $3, now())
		ON CONFLICT (physical_attempt_id)
		DO UPDATE SET task_document = EXCLUDED.task_document,
		              compiled_context = EXCLUDED.compiled_context,
		              offered_at = EXCLUDED.offered_at`,
		string(task.PhysicalAttemptId), document, compiled)
	if err != nil {
		return fmt.Errorf("runtime boundary store: offer task: %w", err)
	}
	return nil
}

// Task resolves one offered task by its physical attempt identity.
func (s *Store) Task(ctx context.Context, physicalAttemptID string) (schema.AgentTask, bool, error) {
	var document []byte
	err := s.database.QueryRow(ctx, `
		SELECT task_document FROM agent_workflow.runtime_task_offers
		WHERE physical_attempt_id = $1`, physicalAttemptID).Scan(&document)
	if errors.Is(err, pgx.ErrNoRows) {
		return schema.AgentTask{}, false, nil
	}
	if err != nil {
		return schema.AgentTask{}, false, fmt.Errorf("runtime boundary store: read offer: %w", err)
	}
	var task schema.AgentTask
	if err := json.Unmarshal(document, &task); err != nil {
		return schema.AgentTask{}, false, fmt.Errorf("runtime boundary store: decode offered task: %w", err)
	}
	return task, true, nil
}

// Record stores one submission with the boundary's idempotency semantics: one
// immutable record per (run, digest), one submission per attempt, and a
// conflict when an attempt re-submits different bytes.
func (s *Store) Record(ctx context.Context, submission runtimeboundary.Submission) (runtimeboundary.Submission, bool, error) {
	transaction, err := s.database.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return runtimeboundary.Submission{}, false, fmt.Errorf("runtime boundary store: begin submission: %w", err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()

	var registeredDigest string
	err = transaction.QueryRow(ctx, `
		SELECT digest FROM agent_workflow.runtime_submission_attempts
		WHERE physical_attempt_id = $1`, submission.PhysicalAttemptID).Scan(&registeredDigest)
	replayed := err == nil
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return runtimeboundary.Submission{}, false, fmt.Errorf("runtime boundary store: read replay register: %w", err)
	}
	if replayed && registeredDigest != submission.Digest {
		return runtimeboundary.Submission{}, false, runtimeboundary.SubmissionConflictError{}
	}
	if !replayed {
		if _, err := transaction.Exec(ctx, `
			INSERT INTO agent_workflow.runtime_artifact_submissions
			 (workspace_id, project_id, run_id, task_id, physical_attempt_id, artifact_id,
			  digest, media_type, size_bytes, content,
			  execution_generation, attempt_number, lease_epoch, submitted_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
			ON CONFLICT (run_id, digest) DO NOTHING`,
			submission.WorkspaceID, submission.ProjectID, submission.RunID, submission.TaskID,
			submission.PhysicalAttemptID, submission.ArtifactID, submission.Digest,
			submission.MediaType, submission.SizeBytes, submission.Content,
			submission.ExecutionGeneration, submission.AttemptNumber, submission.LeaseEpoch,
			submission.SubmittedAt.UTC()); err != nil {
			return runtimeboundary.Submission{}, false, fmt.Errorf("runtime boundary store: record submission: %w", err)
		}
		if _, err := transaction.Exec(ctx, `
			INSERT INTO agent_workflow.runtime_submission_attempts (physical_attempt_id, run_id, digest)
			VALUES ($1,$2,$3)`,
			submission.PhysicalAttemptID, submission.RunID, submission.Digest); err != nil {
			return runtimeboundary.Submission{}, false, fmt.Errorf("runtime boundary store: register attempt submission: %w", err)
		}
	}
	recorded, err := readSubmission(ctx, transaction, submission.RunID, submission.Digest)
	if err != nil {
		return runtimeboundary.Submission{}, false, err
	}
	if err := transaction.Commit(ctx); err != nil {
		return runtimeboundary.Submission{}, false, fmt.Errorf("runtime boundary store: commit submission: %w", err)
	}
	return recorded, replayed, nil
}

// Content reads back one recorded submission by its reference.
func (s *Store) Content(ctx context.Context, reference schema.SharedPrimitivesArtifactReference) ([]byte, error) {
	var content []byte
	err := s.database.QueryRow(ctx, `
		SELECT content FROM agent_workflow.runtime_artifact_submissions
		WHERE artifact_id = $1 AND digest = $2`,
		string(reference.ArtifactId), string(reference.Digest)).Scan(&content)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("runtime boundary store: no recorded submission matches the reference")
	}
	if err != nil {
		return nil, fmt.Errorf("runtime boundary store: read submission: %w", err)
	}
	return content, nil
}

func readSubmission(ctx context.Context, transaction pgx.Tx, runID, digest string) (runtimeboundary.Submission, error) {
	var recorded runtimeboundary.Submission
	err := transaction.QueryRow(ctx, `
		SELECT workspace_id, project_id, run_id, task_id, physical_attempt_id, artifact_id,
		       digest, media_type, size_bytes, content,
		       execution_generation, attempt_number, lease_epoch, submitted_at
		FROM agent_workflow.runtime_artifact_submissions
		WHERE run_id = $1 AND digest = $2`, runID, digest).Scan(
		&recorded.WorkspaceID, &recorded.ProjectID, &recorded.RunID, &recorded.TaskID,
		&recorded.PhysicalAttemptID, &recorded.ArtifactID, &recorded.Digest,
		&recorded.MediaType, &recorded.SizeBytes, &recorded.Content,
		&recorded.ExecutionGeneration, &recorded.AttemptNumber, &recorded.LeaseEpoch,
		&recorded.SubmittedAt)
	if err != nil {
		return runtimeboundary.Submission{}, fmt.Errorf("runtime boundary store: read recorded submission: %w", err)
	}
	return recorded, nil
}
