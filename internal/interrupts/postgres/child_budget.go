package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ancyloce/anvilkit-agent-service/internal/interrupts"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/runs"
)

// ChildBudgetReservation atomically serializes child holds at the root run.
// Unknown-final or expired reservations remain held until an authorized
// settlement explicitly releases them.
type ChildBudgetReservation struct {
	database              *pgxpool.Pool
	childUpperBoundMicros int64
	maximumHeldMicros     int64
	lifetime              time.Duration
}

func NewChildBudgetReservation(database *pgxpool.Pool, childUpperBoundMicros, maximumHeldMicros int64, lifetime time.Duration) (*ChildBudgetReservation, error) {
	if database == nil || childUpperBoundMicros < 1 || maximumHeldMicros < 1 || childUpperBoundMicros > maximumHeldMicros || lifetime <= 0 || lifetime > 7*24*time.Hour {
		return nil, fmt.Errorf("child budget reservation configuration is invalid")
	}
	return &ChildBudgetReservation{database: database, childUpperBoundMicros: childUpperBoundMicros, maximumHeldMicros: maximumHeldMicros, lifetime: lifetime}, nil
}

func (r *ChildBudgetReservation) ReserveChild(ctx context.Context, request interrupts.ChildBudgetRequest) error {
	if err := validateChildBudgetRequest(request); err != nil {
		return err
	}
	reservationID := childReservationID(request)
	tx, err := r.database.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return fmt.Errorf("begin child budget reservation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var existingRoot, existingBudgetVersion string
	err = tx.QueryRow(ctx, `SELECT root_run_id,budget_version FROM agent_control.budget_reservations WHERE workspace_id=$1 AND project_id=$2 AND reservation_id=$3 FOR UPDATE`, request.Write.Scope.WorkspaceID, request.Write.Scope.ProjectID, reservationID).Scan(&existingRoot, &existingBudgetVersion)
	if err == nil {
		if existingBudgetVersion != request.Digest {
			return problem.New(problem.CodeIdempotencyConflict, "")
		}
		return tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("read child budget replay: %w", err)
	}

	parent, generation, parentVersion, err := lockBudgetRun(ctx, tx, request.Write.Scope, request.Write.RunID)
	if err != nil {
		return err
	}
	if parentVersion != request.Write.ExpectedVersion {
		return problem.New(problem.CodeVersionConflict, "")
	}
	rootID := parent.RootRunID
	if rootID == "" {
		return budgetDenied("parent run has no root budget authority")
	}
	root := parent
	if rootID != parent.RunID {
		root, generation, _, err = lockBudgetRun(ctx, tx, request.Write.Scope, rootID)
		if err != nil {
			return err
		}
	}
	if root.RunID != rootID || root.RootRunID != rootID {
		return budgetDenied("root budget authority is inconsistent")
	}
	authority, err := decodeRootBudget(root.Budget)
	if err != nil {
		return budgetDenied("root budget authority is invalid")
	}
	maximumMicros, err := currencyMicros(authority.CurrencyLimits.MaximumCost.Amount)
	if err != nil {
		return budgetDenied("root maximum cost is invalid")
	}
	reservedMicros, err := currencyMicros(authority.CurrencyLimits.ReservedCost.Amount)
	if err != nil || authority.CurrencyLimits.MaximumCost.Currency != authority.CurrencyLimits.ReservedCost.Currency || authority.CurrencyLimits.MaximumCost.Currency != "USD" || reservedMicros > maximumMicros {
		return budgetDenied("root reserved cost is inconsistent")
	}
	limit := minimumInt64(maximumMicros, r.maximumHeldMicros)
	if reservedMicros > limit {
		return budgetDenied("root budget has no child headroom")
	}
	var durableHeld int64
	err = tx.QueryRow(ctx, `SELECT COALESCE(SUM(upper_bound_micros),0)::bigint FROM agent_control.budget_reservations WHERE workspace_id=$1 AND project_id=$2 AND root_run_id=$3 AND reservation_id<>$4 AND released=false`, request.Write.Scope.WorkspaceID, request.Write.Scope.ProjectID, rootID, authority.ReservationID).Scan(&durableHeld)
	if err != nil || durableHeld < 0 {
		return budgetDenied("durable root reservation total is unavailable")
	}
	if durableHeld > limit-reservedMicros || r.childUpperBoundMicros > limit-reservedMicros-durableHeld {
		return budgetDenied("root budget is exhausted")
	}
	expiresAt := request.RequestedAt.Add(r.lifetime)
	_, err = tx.Exec(ctx, `INSERT INTO agent_control.budget_reservations(workspace_id,project_id,root_run_id,run_id,reservation_id,controller_generation,policy_version,budget_version,upper_bound_micros,expires_at,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$11)`, request.Write.Scope.WorkspaceID, request.Write.Scope.ProjectID, rootID, request.ChildRunID, reservationID, generation, authority.Policy.Version, request.Digest, r.childUpperBoundMicros, expiresAt, request.RequestedAt)
	if err != nil {
		return fmt.Errorf("record child budget reservation: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit child budget reservation: %w", err)
	}
	return nil
}

func lockBudgetRun(ctx context.Context, tx pgx.Tx, scope runs.Scope, id runs.ID) (runs.Snapshot, uint64, uint64, error) {
	var raw []byte
	var generation, version uint64
	if err := tx.QueryRow(ctx, `SELECT snapshot,execution_generation,version FROM agent_control.agent_runs WHERE workspace_id=$1 AND project_id=$2 AND run_id=$3 FOR UPDATE`, scope.WorkspaceID, scope.ProjectID, id).Scan(&raw, &generation, &version); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return runs.Snapshot{}, 0, 0, problem.New(problem.CodeResourceNotFound, "")
		}
		return runs.Snapshot{}, 0, 0, fmt.Errorf("lock run budget authority: %w", err)
	}
	var snapshot runs.Snapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		return runs.Snapshot{}, 0, 0, budgetDenied("run budget authority cannot be decoded")
	}
	return snapshot, generation, version, nil
}

type rootBudget struct {
	Kind           string          `json:"kind"`
	ModelLimits    json.RawMessage `json:"modelLimits"`
	TokenLimits    json.RawMessage `json:"tokenLimits"`
	WorkerLimits   json.RawMessage `json:"workerLimits"`
	GPULimits      json.RawMessage `json:"gpuLimits"`
	CurrencyLimits struct {
		MaximumCost  cost `json:"maximumCost"`
		ReservedCost cost `json:"reservedCost"`
	} `json:"currencyLimits"`
	ReservationID  string `json:"reservationId"`
	ExceedBehavior string `json:"exceedBehavior"`
	Policy         struct {
		PolicyID string `json:"policyId"`
		Version  string `json:"version"`
		Digest   string `json:"digest"`
	} `json:"policy"`
}

type cost struct {
	Amount   string `json:"amount"`
	Currency string `json:"currency"`
}

func decodeRootBudget(raw []byte) (rootBudget, error) {
	var value rootBudget
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return rootBudget{}, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return rootBudget{}, fmt.Errorf("trailing budget JSON")
	}
	if value.Kind != "AgentBudget" || value.ReservationID == "" || value.Policy.PolicyID == "" || value.Policy.Version == "" || value.Policy.Digest == "" || len(value.ModelLimits) == 0 || len(value.TokenLimits) == 0 || len(value.WorkerLimits) == 0 || len(value.GPULimits) == 0 {
		return rootBudget{}, fmt.Errorf("incomplete root budget")
	}
	return value, nil
}

func currencyMicros(amount string) (int64, error) {
	if amount == "" || strings.HasPrefix(amount, "-") || strings.HasPrefix(amount, "+") {
		return 0, fmt.Errorf("cost must be non-negative")
	}
	parts := strings.Split(amount, ".")
	if len(parts) > 2 || parts[0] == "" {
		return 0, fmt.Errorf("cost is not decimal")
	}
	whole, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || whole < 0 || whole > math.MaxInt64/1_000_000 {
		return 0, fmt.Errorf("cost exceeds micro-unit range")
	}
	fraction := ""
	if len(parts) == 2 {
		fraction = parts[1]
		if fraction == "" {
			return 0, fmt.Errorf("cost has an empty fraction")
		}
	}
	if len(fraction) > 6 {
		if strings.Trim(fraction[6:], "0") != "" {
			return 0, fmt.Errorf("cost cannot be represented in micros")
		}
		fraction = fraction[:6]
	}
	fraction += strings.Repeat("0", 6-len(fraction))
	fractionMicros := int64(0)
	if fraction != "" {
		fractionMicros, err = strconv.ParseInt(fraction, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("cost fraction is invalid")
		}
	}
	return whole*1_000_000 + fractionMicros, nil
}

func validateChildBudgetRequest(request interrupts.ChildBudgetRequest) error {
	if err := request.Write.Scope.Validate(); err != nil || request.Write.RunID == "" || request.ChildRunID == "" || request.Write.ExpectedVersion == 0 || request.Write.IdempotencyKey == "" || len(request.Write.IdempotencyKey) > 256 || request.RequestedAt.IsZero() || (request.Mode != interrupts.ChildRequired && request.Mode != interrupts.ChildOptional && request.Mode != interrupts.ChildFallback) || len(request.Digest) != 71 || !strings.HasPrefix(request.Digest, "sha256:") {
		return problem.New(problem.CodeRequestInvalid, "")
	}
	if _, err := hex.DecodeString(request.Digest[7:]); err != nil {
		return problem.New(problem.CodeRequestInvalid, "")
	}
	return nil
}

func childReservationID(request interrupts.ChildBudgetRequest) string {
	identity := request.Write.Scope.WorkspaceID + "\x00" + request.Write.Scope.ProjectID + "\x00" + string(request.Write.RunID) + "\x00" + request.Write.IdempotencyKey
	digest := sha256.Sum256([]byte(identity))
	return "child-reservation-" + hex.EncodeToString(digest[:])
}

func budgetDenied(detail string) problem.Details {
	value := problem.New(problem.CodeBudgetDenied, "")
	value.Detail = detail
	return value
}

func minimumInt64(left, right int64) int64 {
	if left < right {
		return left
	}
	return right
}

var _ interrupts.Reservation = (*ChildBudgetReservation)(nil)
