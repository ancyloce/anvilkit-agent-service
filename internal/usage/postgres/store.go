// Package postgres persists append-only all-attempt usage observations.
package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/usage"
)

type Store struct{ database *pgxpool.Pool }

func New(database *pgxpool.Pool) (*Store, error) {
	if database == nil {
		return nil, fmt.Errorf("usage database required")
	}
	return &Store{database: database}, nil
}

func (s *Store) Append(ctx context.Context, value usage.Record) (bool, error) {
	if err := usage.Validate(value.Observation); err != nil {
		return false, err
	}
	if value.DedupKey == "" {
		return false, problem.New(problem.CodeRequestInvalid, "")
	}
	fingerprint, err := observationDigest(value)
	if err != nil {
		return false, err
	}
	tag, err := s.database.Exec(ctx, `
		INSERT INTO agent_control.usage_observations(
			workspace_id,project_id,root_run_id,run_id,reservation_id,observation_id,
			task_id,physical_attempt_id,recovery_epoch,execution_generation,meter_sequence,
			cost_micros,final,provider_event_id,meter,quantity,unit,currency,provider,
			build_identity,traceparent,repaired,observed_at,observation_digest
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,NULLIF($14,''),
		         $15,$16,$17,$18,$19,$20,$21,$22,$23,$24)
		ON CONFLICT DO NOTHING`,
		value.WorkspaceID, value.ProjectID, value.RootRunID, value.RunID,
		value.ReservationID, value.ObservationID, value.TaskID, value.PhysicalAttemptID,
		value.RecoveryEpoch, value.ExecutionGeneration, value.MeterSequence,
		value.CostMicros, value.Final, value.ProviderEventID, value.Meter, value.Quantity,
		value.Unit, value.Currency, value.Provider, value.BuildIdentity, value.Traceparent,
		value.Repaired, value.ObservedAt, fingerprint)
	if err != nil {
		return false, fmt.Errorf("append usage: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return true, nil
	}

	var matches int
	var allMatch bool
	err = s.database.QueryRow(ctx, `
		SELECT count(*),COALESCE(bool_and(observation_digest=$12),false)
		FROM agent_control.usage_observations
		WHERE workspace_id=$1 AND project_id=$2
		  AND (observation_id=$3
		       OR (provider_event_id IS NOT NULL AND provider=$4 AND provider_event_id=$5)
		       OR (provider_event_id IS NULL AND task_id=$6 AND recovery_epoch=$7
		           AND execution_generation=$8 AND physical_attempt_id=$9
		           AND meter=$10 AND meter_sequence=$11))
		`,
		value.WorkspaceID, value.ProjectID, value.ObservationID, value.Provider,
		value.ProviderEventID, value.TaskID, value.RecoveryEpoch, value.ExecutionGeneration,
		value.PhysicalAttemptID, value.Meter, value.MeterSequence, fingerprint).Scan(&matches, &allMatch)
	if err != nil {
		return false, err
	}
	if matches != 1 || !allMatch {
		return false, problem.New(problem.CodeIdempotencyConflict, "")
	}
	return false, nil
}

func (s *Store) ForAttempt(ctx context.Context, workspace, project, task string, recovery, generation uint64, attempt string) ([]usage.Record, error) {
	rows, err := s.database.Query(ctx, `
		SELECT observation_id,root_run_id,run_id,reservation_id,
		       COALESCE(provider_event_id,''),meter,quantity,unit,currency,cost_micros,
		       meter_sequence,final,observed_at,provider,build_identity,traceparent,repaired
		FROM agent_control.usage_observations
		WHERE workspace_id=$1 AND project_id=$2 AND task_id=$3
		  AND recovery_epoch=$4 AND execution_generation=$5 AND physical_attempt_id=$6
		ORDER BY meter_sequence,observed_at,observation_id`,
		workspace, project, task, recovery, generation, attempt)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []usage.Record
	for rows.Next() {
		value := usage.Record{Observation: usage.Observation{
			WorkspaceID: workspace, ProjectID: project, TaskID: task,
			RecoveryEpoch: recovery, ExecutionGeneration: generation,
			PhysicalAttemptID: attempt,
		}}
		if err := rows.Scan(
			&value.ObservationID, &value.RootRunID, &value.RunID, &value.ReservationID,
			&value.ProviderEventID, &value.Meter, &value.Quantity, &value.Unit,
			&value.Currency, &value.CostMicros, &value.MeterSequence, &value.Final,
			&value.ObservedAt, &value.Provider, &value.BuildIdentity, &value.Traceparent,
			&value.Repaired,
		); err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func observationDigest(value usage.Record) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("encode usage observation: %w", err)
	}
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

var _ usage.Store = (*Store)(nil)
