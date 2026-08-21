package runapp

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
)

// ResolveDomainOperationRoute is the normalized route an operator-recovery
// receipt is scoped to (ADR-021 §4). It is the route template rather than a
// resolved path: normalization is what makes the key isolation a property of
// the operation being invoked instead of an accident of which identifiers the
// path happened to carry. Which effect is being decided is already covered —
// exactly and canonically — by the request digest the receipt is checked
// against.
const ResolveDomainOperationRoute = "POST /workspaces/{workspaceId}/agent-runs/{runId}/domain-operations/{operationId}/resolution"

// CommandReceiptRequest identifies one idempotent command. ADR-021 §4 fixes
// the isolation: workspace, project, the authenticated subject, the HTTP
// method, the normalized route, and the key together scope a receipt, so one
// actor's recorded response can never be replayed to another actor, another
// method, or another route.
//
// Subject is the verified credential subject — the identity the token was
// issued to — never the actor the request acts as. Under delegation those
// differ, and several subjects may be permitted to act as the same actor;
// keying on the actor would put their receipts in one namespace and let one
// subject's recorded privileged outcome be replayed to another. The audited
// resolving operator is a separate concern and stays the verified actor.
//
// Digest, Version, and RunID are deliberately not part of that identity. They
// are what a claimed key is checked against, which is what makes reuse
// distinguishable from replay: the same key with different command bytes,
// against a different observed resource revision, or aimed at a different run
// is a conflict, never a replay of an outcome the caller did not ask for.
type CommandReceiptRequest struct {
	WorkspaceID, ProjectID, Subject, Method, Route, Key, RunID, Digest string
	Version                                                            uint64
}

// Valid reports whether the request carries every element the receipt identity
// and its conflict checks are made of.
func (r CommandReceiptRequest) Valid() bool {
	return r.WorkspaceID != "" && r.ProjectID != "" && r.Subject != "" && r.Method != "" &&
		r.Route != "" && r.Key != "" && len(r.Key) <= 256 && r.RunID != "" && r.Digest != "" && r.Version != 0
}

// CommandReceipt is the recorded outcome of one idempotent command: the
// response body a replay must reproduce and the concurrency token that was
// current when it was produced.
type CommandReceipt struct {
	Body []byte
	ETag string
}

// ReceiptClaim fences one holder of one idempotency key. Begin issues it,
// Record and Abandon require it, and every transfer of the claim — the
// takeover of a lapsed lease, and the release Abandon performs — advances it.
// It is opaque to callers: its only meaning is that the holder still owns the
// claim it was issued for.
//
// The fence is what a lease alone cannot provide. A claimant whose command
// stalls past the lease is not stopped from finishing: it simply no longer
// knows that its claim was taken over. Without a fence its late Record would
// overwrite the successor's outcome, or its late Abandon would release a claim
// another command is actively executing under. With one, a stale holder is
// told its claim was lost and changes nothing.
type ReceiptClaim struct{ Epoch uint64 }

// Held reports whether the claim names a live holder. The zero claim is what
// a replay answer carries: there is nothing to record or abandon.
func (c ReceiptClaim) Held() bool { return c.Epoch != 0 }

// CommandReceipts records and replays the outcome of one idempotent command.
//
// The protocol is two-phase because the work a command performs is not a
// single database transaction — operator recovery spans the submission
// journal, the evidence store, and the run aggregate. Begin claims the key or
// answers with the recorded outcome, Record stores the outcome that claim
// authorized, and Abandon releases a claim whose command produced no outcome
// worth recording. Exactly one concurrent caller may hold a claim, so
// concurrent duplicates resolve deterministically: one executes, the rest are
// told the key is in flight rather than executing the command a second time.
//
// Begin returns the claim token that fences the other two calls. Record and
// Abandon act only for the holder the token names, so a claimant whose lease
// lapsed and was taken over can neither record over its successor's outcome
// nor abandon its successor's claim.
type CommandReceipts interface {
	Begin(ctx context.Context, request CommandReceiptRequest) (CommandReceipt, ReceiptClaim, bool, error)
	Record(ctx context.Context, request CommandReceiptRequest, claim ReceiptClaim, receipt CommandReceipt) error
	Abandon(ctx context.Context, request CommandReceiptRequest, claim ReceiptClaim) error
}

// ReceiptConflict renders the problem one form of key misuse raises. Reuse of
// a live key with different canonical bytes is the governed
// IDEMPOTENCY_KEY_REUSED case ADR-021 §4 names, and it is reported under its
// own code because it says something no other conflict says: the caller
// changed the command, not the circumstances. Every other form — a different
// observed revision, a different addressed resource, a duplicate still in
// flight, and a claim lost to a takeover — is a distinct semantic conflict and
// keeps the general idempotency-conflict code.
func ReceiptConflict(detail string) error {
	value := problem.New(receiptConflictCode(detail), "")
	value.Detail = detail
	return value
}

// receiptConflictCode maps one conflict detail onto its governed code.
func receiptConflictCode(detail string) problem.Code {
	if detail == ReceiptBytesReused {
		return problem.CodeIdempotencyKeyReused
	}
	return problem.CodeIdempotencyConflict
}

// Receipt conflict details. They are stable strings rather than free text
// because clients branch on them and operators read them in problem output.
const (
	ReceiptBytesReused    = "the idempotency key was already used with different command bytes"
	ReceiptRevisionReused = "the idempotency key was already used against a different resource revision"
	ReceiptResourceReused = "the idempotency key was already used against a different run"
	ReceiptInFlight       = "a command with this idempotency key is still in flight"
	ReceiptClaimLost      = "the idempotency claim was taken over before its outcome was recorded"
)

// MemoryCommandReceipts is the deterministic in-memory receipt store. It keeps
// the same contract the durable one does — identical key isolation, the same
// conflict vocabulary, single-claim concurrency, fenced claim ownership, and
// lease takeover of a claim whose command died — so what tests prove here is
// what production enforces.
type MemoryCommandReceipts struct {
	lock    sync.Mutex
	lease   time.Duration
	now     func() time.Time
	records map[string]*memoryReceipt
}

type memoryReceipt struct {
	digest     string
	runID      string
	version    uint64
	epoch      uint64
	reservedAt time.Time
	recorded   bool
	receipt    CommandReceipt
}

// NewMemoryCommandReceipts builds the in-memory receipt store over an explicit
// clock and claim lease.
func NewMemoryCommandReceipts(now func() time.Time, lease time.Duration) *MemoryCommandReceipts {
	if now == nil {
		now = time.Now
	}
	if lease <= 0 {
		lease = time.Minute
	}
	return &MemoryCommandReceipts{lease: lease, now: now, records: map[string]*memoryReceipt{}}
}

func receiptKey(request CommandReceiptRequest) string {
	return request.WorkspaceID + "\x00" + request.ProjectID + "\x00" + request.Subject + "\x00" +
		request.Method + "\x00" + request.Route + "\x00" + request.Key
}

func (m *MemoryCommandReceipts) Begin(_ context.Context, request CommandReceiptRequest) (CommandReceipt, ReceiptClaim, bool, error) {
	if !request.Valid() {
		return CommandReceipt{}, ReceiptClaim{}, false, fmt.Errorf("command receipt: scope, subject, method, route, key, run, digest, and revision are required")
	}
	m.lock.Lock()
	defer m.lock.Unlock()
	now := m.now().UTC()
	key := receiptKey(request)
	existing, held := m.records[key]
	if !held {
		m.records[key] = &memoryReceipt{digest: request.Digest, runID: request.RunID, version: request.Version, epoch: 1, reservedAt: now}
		return CommandReceipt{}, ReceiptClaim{Epoch: 1}, false, nil
	}
	if err := existing.conflict(request); err != nil {
		return CommandReceipt{}, ReceiptClaim{}, false, err
	}
	if existing.recorded {
		return CommandReceipt{Body: append([]byte(nil), existing.receipt.Body...), ETag: existing.receipt.ETag}, ReceiptClaim{}, true, nil
	}
	if now.Before(existing.reservedAt.Add(m.lease)) {
		return CommandReceipt{}, ReceiptClaim{}, false, ReceiptConflict(ReceiptInFlight)
	}
	// The claiming command died before it recorded anything. Its lease has
	// elapsed, so this request takes the claim over and executes: the command
	// behind it converges on its own durable state, which is what makes
	// re-execution safe rather than a second effect. Advancing the epoch is
	// what retires the previous holder's token, so a claimant that was only
	// slow rather than dead cannot come back and write over this one.
	existing.epoch++
	existing.reservedAt = now
	return CommandReceipt{}, ReceiptClaim{Epoch: existing.epoch}, false, nil
}

// conflict reports why a held receipt cannot answer this request, or nil when
// it can.
func (r *memoryReceipt) conflict(request CommandReceiptRequest) error {
	switch {
	case r.digest != request.Digest:
		return ReceiptConflict(ReceiptBytesReused)
	case r.runID != request.RunID:
		return ReceiptConflict(ReceiptResourceReused)
	case r.version != request.Version:
		return ReceiptConflict(ReceiptRevisionReused)
	}
	return nil
}

func (m *MemoryCommandReceipts) Record(_ context.Context, request CommandReceiptRequest, claim ReceiptClaim, receipt CommandReceipt) error {
	if !request.Valid() {
		return fmt.Errorf("command receipt: scope, subject, method, route, key, run, digest, and revision are required")
	}
	if !claim.Held() {
		return fmt.Errorf("command receipt: recording an outcome requires the claim Begin issued")
	}
	m.lock.Lock()
	defer m.lock.Unlock()
	existing, held := m.records[receiptKey(request)]
	if !held {
		return ReceiptConflict(ReceiptClaimLost)
	}
	if err := existing.conflict(request); err != nil {
		return err
	}
	if existing.epoch != claim.Epoch {
		// The claim moved on: a takeover — or this claimant's own abandon —
		// retired the token this call carries. The outcome is discarded rather
		// than written over whatever the current holder is doing.
		return ReceiptConflict(ReceiptClaimLost)
	}
	if existing.recorded {
		// This holder already recorded. The command converges, so the recorded
		// outcome stands and this one is discarded rather than overwriting it.
		return nil
	}
	existing.recorded = true
	existing.receipt = CommandReceipt{Body: append([]byte(nil), receipt.Body...), ETag: receipt.ETag}
	return nil
}

// Abandon releases the claim without forgetting it. The claim becomes
// immediately reclaimable, so the same command can be retried under the same
// key as soon as its cause is corrected — but the bytes the key was used with
// are still remembered, so reusing it for a different command stays the
// conflict ADR-021 §4 requires rather than becoming a fresh key.
//
// Only the current holder may release: a claimant whose lease lapsed and was
// taken over would otherwise hand its successor's live claim to anyone. The
// release advances the epoch for the same reason a takeover does — the
// releasing holder's token stops being valid the moment it lets go.
func (m *MemoryCommandReceipts) Abandon(_ context.Context, request CommandReceiptRequest, claim ReceiptClaim) error {
	if !claim.Held() {
		return nil
	}
	m.lock.Lock()
	defer m.lock.Unlock()
	existing, held := m.records[receiptKey(request)]
	if !held || existing.recorded || existing.digest != request.Digest || existing.epoch != claim.Epoch {
		return nil
	}
	existing.epoch++
	existing.reservedAt = time.Time{}
	return nil
}

var _ CommandReceipts = (*MemoryCommandReceipts)(nil)

// ReceiptMethod is the HTTP method every receipt-bearing command on this
// boundary uses.
const ReceiptMethod = http.MethodPost
