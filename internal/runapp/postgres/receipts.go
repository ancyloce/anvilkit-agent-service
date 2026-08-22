// Package postgres persists the application boundary's ADR-021 §4 command
// receipts for commands whose work is not a single database transaction.
package postgres

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ancyloce/anvilkit-agent-service/internal/runapp"
)

// Receipts is the durable command receipt store over
// agent_control.write_idempotency.
//
// A command that spans several durable stores cannot record its outcome in the
// transaction that performs it, so the receipt is two-phase: the key is
// claimed in its own committed transaction, the command runs, and the outcome
// is written onto the claim. The claim is what makes concurrency
// deterministic — the primary key admits exactly one claimant, and a duplicate
// blocks on it rather than racing past it — and the claim time is what keeps a
// command that died mid-flight from holding its own key for ever. Ownership
// across those two transactions is fenced by a monotonic claim epoch, so a
// holder that returns after its lease was taken over cannot record over, or
// release, the claim that replaced it.
type Receipts struct {
	database  *pgxpool.Pool
	retention time.Duration
	lease     time.Duration
	now       func() time.Time
}

// NewReceipts builds the durable receipt store. The lease must be shorter than
// retention: a claim nobody completes has to become reclaimable long before
// the receipt that would answer its replay is swept.
func NewReceipts(database *pgxpool.Pool, retention, lease time.Duration, now func() time.Time) (*Receipts, error) {
	if database == nil || now == nil {
		return nil, fmt.Errorf("command receipts require a database and a clock")
	}
	if retention <= 0 || lease <= 0 || lease >= retention {
		return nil, fmt.Errorf("command receipts require a positive retention and a claim lease shorter than it")
	}
	return &Receipts{database: database, retention: retention, lease: lease, now: now}, nil
}

var _ runapp.CommandReceipts = (*Receipts)(nil)

// receiptStatus is the response status a recorded receipt carries. A claim
// that has not yet recorded an outcome carries zero, which is what
// distinguishes the two phases on the row itself.
const receiptStatus = 200

const receiptContentType = "application/json"

func (r *Receipts) Begin(ctx context.Context, request runapp.CommandReceiptRequest) (runapp.CommandReceipt, runapp.ReceiptClaim, bool, error) {
	if !request.Valid() {
		return runapp.CommandReceipt{}, runapp.ReceiptClaim{}, false, fmt.Errorf("command receipt: scope, subject, method, route, key, run, digest, and revision are required")
	}
	now := r.now().UTC()
	tx, err := r.database.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return runapp.CommandReceipt{}, runapp.ReceiptClaim{}, false, fmt.Errorf("begin command receipt: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// A duplicate arriving concurrently blocks on the primary key until the
	// first claim commits, then reads it back. That is what makes the outcome
	// deterministic rather than a race: exactly one caller inserts.
	claim, err := tx.Exec(ctx, `INSERT INTO agent_control.write_idempotency(workspace_id,project_id,subject,method,operation,idempotency_key,resource_id,request_digest,version_bound,response_status,response_content_type,response_body,response_etag,reserved_at,claim_epoch,expires_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,0,'',decode('','hex'),'',$10,1,$11) ON CONFLICT DO NOTHING`,
		request.WorkspaceID, request.ProjectID, request.Subject, request.Method, request.Route, request.Key, request.ResourceID,
		[]byte(request.Digest), int64(request.Version), now, now.Add(r.retention))
	if err != nil {
		return runapp.CommandReceipt{}, runapp.ReceiptClaim{}, false, fmt.Errorf("claim command receipt: %w", err)
	}
	if claim.RowsAffected() == 1 {
		if err := tx.Commit(ctx); err != nil {
			return runapp.CommandReceipt{}, runapp.ReceiptClaim{}, false, fmt.Errorf("commit command receipt claim: %w", err)
		}
		return runapp.CommandReceipt{}, runapp.ReceiptClaim{Epoch: 1}, false, nil
	}
	var digest, body []byte
	var resourceID, etag string
	var status int
	var versionBound, epoch int64
	var reservedAt time.Time
	if err := tx.QueryRow(ctx, `SELECT request_digest,resource_id,version_bound,response_status,response_body,response_etag,reserved_at,claim_epoch
		FROM agent_control.write_idempotency
		WHERE workspace_id=$1 AND project_id=$2 AND subject=$3 AND method=$4 AND operation=$5 AND idempotency_key=$6 FOR UPDATE`,
		request.WorkspaceID, request.ProjectID, request.Subject, request.Method, request.Route, request.Key).
		Scan(&digest, &resourceID, &versionBound, &status, &body, &etag, &reservedAt, &epoch); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// The holder rolled back between the failed insert and this read.
			// Nothing is claimed, so this request is told to retry rather than
			// executing against a claim it does not hold.
			return runapp.CommandReceipt{}, runapp.ReceiptClaim{}, false, runapp.ReceiptConflict(runapp.ReceiptInFlight)
		}
		return runapp.CommandReceipt{}, runapp.ReceiptClaim{}, false, fmt.Errorf("read command receipt: %w", err)
	}
	if conflict := receiptConflict(request, digest, resourceID, versionBound); conflict != nil {
		return runapp.CommandReceipt{}, runapp.ReceiptClaim{}, false, conflict
	}
	if status != 0 {
		if err := tx.Commit(ctx); err != nil {
			return runapp.CommandReceipt{}, runapp.ReceiptClaim{}, false, fmt.Errorf("commit command receipt replay: %w", err)
		}
		return runapp.CommandReceipt{Body: body, ETag: etag}, runapp.ReceiptClaim{}, true, nil
	}
	if now.Before(reservedAt.Add(r.lease)) {
		return runapp.CommandReceipt{}, runapp.ReceiptClaim{}, false, runapp.ReceiptConflict(runapp.ReceiptInFlight)
	}
	// The claiming command died before it recorded anything and its lease has
	// elapsed. This request takes the claim over and executes: the command
	// behind it converges on its own durable state, which is what makes
	// re-execution a repair rather than a second effect. The claim epoch
	// advances with the takeover, so the previous holder's token is retired
	// and a claimant that was merely slow cannot write over this one.
	if err := tx.QueryRow(ctx, `UPDATE agent_control.write_idempotency SET reserved_at=$7,claim_epoch=claim_epoch+1
		WHERE workspace_id=$1 AND project_id=$2 AND subject=$3 AND method=$4 AND operation=$5 AND idempotency_key=$6
		RETURNING claim_epoch`,
		request.WorkspaceID, request.ProjectID, request.Subject, request.Method, request.Route, request.Key, now).Scan(&epoch); err != nil {
		return runapp.CommandReceipt{}, runapp.ReceiptClaim{}, false, fmt.Errorf("reclaim command receipt: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return runapp.CommandReceipt{}, runapp.ReceiptClaim{}, false, fmt.Errorf("commit command receipt reclaim: %w", err)
	}
	return runapp.CommandReceipt{}, runapp.ReceiptClaim{Epoch: uint64(epoch)}, false, nil
}

func (r *Receipts) Record(ctx context.Context, request runapp.CommandReceiptRequest, claim runapp.ReceiptClaim, receipt runapp.CommandReceipt) error {
	// A command whose outcome is a revision rather than a representation
	// records no body. The stored outcome is an empty body rather than an
	// absent one, so "recorded with nothing to replay" stays distinguishable
	// from "not recorded" in the column that holds it.
	if receipt.Body == nil {
		receipt.Body = []byte{}
	}
	if !request.Valid() {
		return fmt.Errorf("command receipt: scope, subject, method, route, key, run, digest, and revision are required")
	}
	if !claim.Held() {
		return fmt.Errorf("command receipt: recording an outcome requires the claim Begin issued")
	}
	// The claim epoch is part of the predicate, so the write lands only while
	// this caller still owns the claim. A holder whose lease lapsed and was
	// taken over updates nothing here rather than overwriting its successor.
	tag, err := r.database.Exec(ctx, `UPDATE agent_control.write_idempotency
		SET response_status=$7,response_content_type=$8,response_body=$9,response_etag=$10
		WHERE workspace_id=$1 AND project_id=$2 AND subject=$3 AND method=$4 AND operation=$5 AND idempotency_key=$6
		  AND request_digest=$11 AND version_bound=$12 AND resource_id=$13 AND response_status=0 AND claim_epoch=$14`,
		request.WorkspaceID, request.ProjectID, request.Subject, request.Method, request.Route, request.Key,
		receiptStatus, receiptContentType, receipt.Body, receipt.ETag, []byte(request.Digest), int64(request.Version), request.ResourceID, int64(claim.Epoch))
	if err != nil {
		return fmt.Errorf("record command receipt: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	// Nothing was updated. Either this holder already recorded — the command
	// is idempotent, so its own recorded outcome converges — or the claim has
	// moved on, which is a lost claim the caller must be told about rather
	// than silently ignore.
	var digest []byte
	var resourceID string
	var status int
	var versionBound, epoch int64
	if err := r.database.QueryRow(ctx, `SELECT request_digest,resource_id,version_bound,response_status,claim_epoch FROM agent_control.write_idempotency
		WHERE workspace_id=$1 AND project_id=$2 AND subject=$3 AND method=$4 AND operation=$5 AND idempotency_key=$6`,
		request.WorkspaceID, request.ProjectID, request.Subject, request.Method, request.Route, request.Key).
		Scan(&digest, &resourceID, &versionBound, &status, &epoch); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return runapp.ReceiptConflict(runapp.ReceiptClaimLost)
		}
		return fmt.Errorf("read command receipt after recording: %w", err)
	}
	if conflict := receiptConflict(request, digest, resourceID, versionBound); conflict != nil {
		return conflict
	}
	if uint64(epoch) != claim.Epoch || status == 0 {
		return runapp.ReceiptConflict(runapp.ReceiptClaimLost)
	}
	return nil
}

// Abandon releases the claim without forgetting it. Backdating the claim time
// makes it immediately reclaimable, so the same command can be retried under
// the same key as soon as its cause is corrected — but the bytes the key was
// used with are still recorded, so reusing it for a different command stays
// the conflict ADR-021 §4 requires rather than becoming a fresh key.
//
// Only the current holder may release, which is why the claim epoch is part of
// the predicate: a claimant whose lease lapsed and was taken over would
// otherwise hand its successor's live claim to the next arrival. The release
// advances the epoch for the same reason a takeover does — the releasing
// holder's token stops being valid the moment it lets go.
func (r *Receipts) Abandon(ctx context.Context, request runapp.CommandReceiptRequest, claim runapp.ReceiptClaim) error {
	if !request.Valid() || !claim.Held() {
		return nil
	}
	if _, err := r.database.Exec(ctx, `UPDATE agent_control.write_idempotency SET reserved_at='epoch',claim_epoch=claim_epoch+1
		WHERE workspace_id=$1 AND project_id=$2 AND subject=$3 AND method=$4 AND operation=$5 AND idempotency_key=$6
		  AND request_digest=$7 AND response_status=0 AND claim_epoch=$8`,
		request.WorkspaceID, request.ProjectID, request.Subject, request.Method, request.Route, request.Key, []byte(request.Digest), int64(claim.Epoch)); err != nil {
		return fmt.Errorf("abandon command receipt: %w", err)
	}
	return nil
}

// receiptConflict reports why a held receipt cannot answer this request, or
// nil when it can. The three checks are the difference between replay and
// reuse: same key with different bytes, aimed at a different resource, or made
// against a different observed revision.
func receiptConflict(request runapp.CommandReceiptRequest, digest []byte, resourceID string, versionBound int64) error {
	switch {
	case !bytes.Equal(digest, []byte(request.Digest)):
		return runapp.ReceiptConflict(runapp.ReceiptBytesReused)
	case resourceID != request.ResourceID:
		return runapp.ReceiptConflict(runapp.ReceiptResourceReused)
	case versionBound != int64(request.Version):
		return runapp.ReceiptConflict(runapp.ReceiptRevisionReused)
	}
	return nil
}
