package securityaudit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/canonical"
	"github.com/ancyloce/anvilkit-agent-service/internal/journal"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
)

type Scope struct{ WorkspaceID, ProjectID, ResourceID string }

type Record struct {
	ID, Action, Actor, Workload, Reason, Ticket string
	OldDigest, NewDigest, Traceparent, Outcome  string
	// Result is the governed problem code a refused decision reached. It is
	// written with the refusal itself, so the decision a retry is answered
	// with is the one the mutation actually made rather than a generic
	// account of a refusal whose reason was not kept. It is empty on every
	// other outcome, and omitted from the authenticated bytes when it is, so
	// records written before a result was recorded chain exactly as they did.
	Result                 string `json:",omitempty"`
	Scope                  Scope
	UTC                    time.Time
	PreviousDigest, Digest string
}

// ProtectedSink is the append-only tamper-evident record store. Lookup answers
// what is already recorded under one identity: a privileged mutation can be
// interrupted between any two of its steps, and the only way a retry can tell
// which steps already happened is to ask the record itself.
type ProtectedSink interface {
	Append(context.Context, Record) (Record, bool, error)
	Lookup(ctx context.Context, id string) (Record, bool, error)
	Read(context.Context) ([]Record, error)
	Verify(context.Context) error
}
type AlertSink interface {
	Alert(context.Context, string, string) error
}
type Mutation func(context.Context) error

type Service struct {
	sink     ProtectedSink
	clock    *AuthoritativeClock
	alerts   AlertSink
	receipts journal.Store
}

func NewService(sink ProtectedSink, clock *AuthoritativeClock, alerts AlertSink, receipts journal.Store) (*Service, error) {
	if sink == nil || clock == nil || alerts == nil || receipts == nil {
		return nil, fmt.Errorf("protected sink, authoritative clock, alerts, and receipt journal are required")
	}
	return &Service{sink: sink, clock: clock, alerts: alerts, receipts: receipts}, nil
}

// PrivilegedMutation carries one authorization-changing decision: the
// authorization is recorded before the change is applied, the outcome after,
// and a receipt closes it. A crash can land between any two of those, so every
// step reads what is already recorded and resumes from there rather than
// starting again.
//
// The three interruption points and what a retry does at each:
//
//   - after the authorization is recorded, before the mutation. The retry
//     adopts the recorded authorization — it is this same decision, not a
//     second one — and applies the mutation. Treating the recorded
//     authorization as a conflict, which is what this used to do, lost the
//     mutation permanently: the decision was on the record and the change it
//     authorized could never be made.
//   - after the mutation, before the outcome is recorded. No outcome is on the
//     record, so the retry runs the mutation again. Nothing is duplicated
//     because every mutation carried here is idempotent under this decision's
//     own identity: re-applying a change that is already there is recognised
//     and reported as applied.
//   - after the outcome is recorded, before the receipt. The retry finds the
//     outcome, does not touch the mutation at all, and completes the receipt.
//
// A mutation that fails for an indeterminate reason records no outcome. Its
// failure says nothing about whether the change landed, and an outcome written
// on that guess would be the answer every later retry received; leaving the
// decision open lets the next attempt find out for itself.
func (s *Service) PrivilegedMutation(ctx context.Context, record Record, mutation Mutation) error {
	if mutation == nil || !complete(record) {
		return problem.New(problem.CodeRequestInvalid, "")
	}
	authorized, err := s.authorize(ctx, record)
	if err != nil {
		return err
	}
	outcomeID := record.ID + ":outcome"
	retained, found, err := s.sink.Lookup(ctx, outcomeID)
	if err != nil {
		return fmt.Errorf("privileged mutation outcome is unknown: %w", err)
	}
	var mutationErr error
	if !found {
		mutationErr = mutation(ctx)
		if mutationErr != nil && !determinate(mutationErr) {
			return mutationErr
		}
		outcome := authorized
		outcome.ID = outcomeID
		outcome.PreviousDigest, outcome.Digest = "", ""
		outcome.Outcome = "applied"
		if mutationErr != nil {
			outcome.Outcome, outcome.Result = "failed", governedResult(mutationErr)
		}
		stamped, err := s.clock.Now(ctx)
		if err != nil {
			return err
		}
		outcome.UTC = stamped
		retained, err = s.record(ctx, outcome)
		if err != nil {
			// A conflict here is a fact, not an unknown: another attempt at
			// this same decision already closed it with a different outcome,
			// and this one is told so rather than overwriting it or reporting
			// the recorded outcome as if it were its own.
			var details problem.Details
			if errors.As(err, &details) && details.Code == string(problem.CodeIdempotencyConflict) {
				return err
			}
			return fmt.Errorf("privileged mutation outcome is unknown: %w", err)
		}
	}
	if err := s.appendReceipt(ctx, retained); err != nil {
		return err
	}
	if retained.Outcome == "failed" {
		if mutationErr != nil {
			return mutationErr
		}
		// This attempt did not run the mutation: the refusal was already on
		// the record when it arrived. The answer is the decision that refusal
		// recorded, reconstructed from its governed code, so a retry that
		// follows a failed receipt append converges on the result the first
		// attempt produced instead of learning only that something was
		// refused.
		return refusal(record.ID, retained)
	}
	return nil
}

// governedResult is the registry code one determinate refusal carries. Only a
// determinate failure is ever recorded, and a determinate failure is by
// definition one that carries governed problem details, so the code is always
// there to record.
func governedResult(err error) string {
	var details problem.Details
	if errors.As(err, &details) {
		return details.Code
	}
	return ""
}

// refusal reconstructs the governed decision a recorded refusal holds. A
// record written before refusals carried their result, or one naming a code
// this build does not know, still closes the decision — it is simply reported
// as a refusal whose governed result is not recoverable, which is what
// RefusedDecision says.
func refusal(decisionID string, retained Record) error {
	if code := problem.Code(retained.Result); retained.Result != "" {
		if _, known := problem.Lookup(code); known {
			return problem.New(code, "")
		}
	}
	return RefusedDecision{RecordID: decisionID}
}

// authorize records this decision's authorization, or adopts the one already
// recorded under the same identity. The identity is derived from the exact
// resource version being changed, so a record already standing under it is
// either this decision resuming or a different decision claiming an identity
// that is taken — and those are told apart by comparing the decision itself,
// not the chain fields or the moment it was stamped.
func (s *Service) authorize(ctx context.Context, record Record) (Record, error) {
	stamped, err := s.clock.Now(ctx)
	if err != nil {
		return Record{}, err
	}
	record.UTC = stamped
	record.Outcome = "authorized-to-apply"
	authorized, inserted, appendErr := s.sink.Append(ctx, record)
	if appendErr == nil && inserted {
		return authorized, nil
	}
	retained, found, err := s.sink.Lookup(ctx, record.ID)
	if err != nil {
		return Record{}, fmt.Errorf("protected audit unavailable: %w", err)
	}
	if !found {
		if appendErr != nil {
			return Record{}, fmt.Errorf("protected audit unavailable: %w", appendErr)
		}
		return Record{}, fmt.Errorf("protected audit record %q was neither recorded nor retained", record.ID)
	}
	if retained.Outcome != "authorized-to-apply" || !sameDecision(record, retained) {
		return Record{}, problem.New(problem.CodeIdempotencyConflict, "")
	}
	return retained, nil
}

// record appends one record and adopts whatever is already standing under its
// identity. Two attempts at the same decision stamp different moments, so the
// one that landed first is the record — a second attempt adopts it rather than
// treating the difference in its own timestamp as a conflicting decision.
func (s *Service) record(ctx context.Context, value Record) (Record, error) {
	appended, inserted, appendErr := s.sink.Append(ctx, value)
	if appendErr == nil && inserted {
		return appended, nil
	}
	retained, found, err := s.sink.Lookup(ctx, value.ID)
	if err != nil {
		return Record{}, err
	}
	if !found {
		if appendErr != nil {
			return Record{}, appendErr
		}
		return Record{}, fmt.Errorf("protected audit record %q was neither recorded nor retained", value.ID)
	}
	if !sameDecision(value, retained) {
		return Record{}, problem.New(problem.CodeIdempotencyConflict, "")
	}
	return retained, nil
}

// RefusedDecision reports a privileged mutation whose recorded outcome is a
// refusal. The decision is closed on the record: it was refused for a reason
// that will not change on re-application, and a retry is told that rather than
// being allowed to believe the change went through.
type RefusedDecision struct{ RecordID string }

func (e RefusedDecision) Error() string {
	return "privileged mutation " + e.RecordID + " is recorded as refused"
}

// sameDecision reports whether two records describe the same decision. The
// chain fields are the sink's own and the stamped moment belongs to the
// attempt rather than the decision, so neither takes part: the question is
// whether the same decision is being recorded again.
func sameDecision(left, right Record) bool {
	left.PreviousDigest, left.Digest, left.UTC = "", "", time.Time{}
	right.PreviousDigest, right.Digest, right.UTC = "", "", time.Time{}
	return left == right
}

// determinate reports whether a mutation failure decided anything. A governed
// refusal — a version precondition that failed, an access denial — is a
// decision: it will be the same decision on every re-application, so it is
// safe to close the record on it. Anything else, an unreachable database
// above all, says only that the attempt did not finish, which is not a fact
// about whether the change landed.
func determinate(err error) bool {
	var details problem.Details
	return errors.As(err, &details) && details.Retryability == "never"
}

func (s *Service) appendReceipt(ctx context.Context, retained Record) error {
	raw, err := json.Marshal(retained)
	if err != nil {
		return fmt.Errorf("marshal privileged audit receipt: %w", err)
	}
	canonicalBytes, err := canonical.Bytes(raw)
	if err != nil {
		return fmt.Errorf("canonicalize privileged audit receipt: %w", err)
	}
	fact, err := journal.NewFact(retained.Scope.WorkspaceID+":privileged-audit:"+retained.ID, retained.Scope.WorkspaceID, retained.Scope.ProjectID, journal.FactPrivilegedAudit, canonicalBytes, raw)
	if err != nil {
		return err
	}
	if _, err := s.receipts.Append(ctx, fact); err != nil {
		return fmt.Errorf("privileged audit fact remains unacknowledged: %w", err)
	}
	return nil
}

// Read records audit access in the protected sink before returning records.
func (s *Service) Read(ctx context.Context, access Record) ([]Record, error) {
	access.Action = "audit-access"
	if err := s.PrivilegedMutation(ctx, access, func(context.Context) error { return nil }); err != nil {
		return nil, err
	}
	return s.sink.Read(ctx)
}

func (s *Service) Verify(ctx context.Context) error {
	if err := s.sink.Verify(ctx); err != nil {
		_ = s.alerts.Alert(ctx, "PROTECTED_AUDIT_TAMPERED", err.Error())
		return err
	}
	return nil
}

func complete(record Record) bool {
	if record.UTC != (time.Time{}) || record.Outcome != "" || record.Result != "" || record.PreviousDigest != "" || record.Digest != "" || !opaque(record.ID, 120) || !opaque(record.Action, 128) || !opaque(record.Actor, 128) || !opaque(record.Workload, 128) || !opaque(record.Ticket, 128) || !opaque(record.Scope.WorkspaceID, 128) || !opaque(record.Scope.ProjectID, 128) || !opaque(record.Scope.ResourceID, 128) || len(record.Reason) < 1 || len(record.Reason) > 1024 || !printable(record.Reason) || !trace(record.Traceparent) {
		return false
	}
	if record.OldDigest == "" && record.NewDigest == "" {
		return false
	}
	return (record.OldDigest == "" || digest(record.OldDigest)) && (record.NewDigest == "" || digest(record.NewDigest))
}

type MemorySink struct {
	lock        sync.Mutex
	records     []Record
	unavailable bool
}

func (s *MemorySink) Append(_ context.Context, record Record) (Record, bool, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.unavailable {
		return Record{}, false, problem.New(problem.CodeInfrastructureUnavailable, "")
	}
	for _, prior := range s.records {
		if prior.ID == record.ID {
			if sameRecordContent(prior, record) {
				return prior, false, nil
			}
			return Record{}, false, problem.New(problem.CodeIdempotencyConflict, "")
		}
	}
	if len(s.records) > 0 {
		record.PreviousDigest = s.records[len(s.records)-1].Digest
	}
	record.Digest = digestRecord(record)
	s.records = append(s.records, record)
	return record, true, nil
}

func sameRecordContent(left, right Record) bool {
	left.PreviousDigest, left.Digest = "", ""
	right.PreviousDigest, right.Digest = "", ""
	return left == right
}

// Lookup answers what is recorded under one identity.
func (s *MemorySink) Lookup(_ context.Context, id string) (Record, bool, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.unavailable {
		return Record{}, false, problem.New(problem.CodeInfrastructureUnavailable, "")
	}
	for _, prior := range s.records {
		if prior.ID == id {
			return prior, true, nil
		}
	}
	return Record{}, false, nil
}

func (s *MemorySink) Read(context.Context) ([]Record, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.unavailable {
		return nil, problem.New(problem.CodeInfrastructureUnavailable, "")
	}
	return append([]Record(nil), s.records...), nil
}

func (s *MemorySink) Verify(context.Context) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	previous := ""
	for index, record := range s.records {
		if record.PreviousDigest != previous || record.Digest != digestRecord(record) {
			return fmt.Errorf("protected audit chain mismatch at record %d", index)
		}
		previous = record.Digest
	}
	return nil
}

func (s *MemorySink) SetUnavailable(value bool) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.unavailable = value
}

// Corrupt is test-only behavior of the in-memory conformance stand-in.
func (s *MemorySink) Corrupt(index int) {
	s.lock.Lock()
	defer s.lock.Unlock()
	if index >= 0 && index < len(s.records) {
		s.records[index].Outcome = "rewritten"
	}
}

func digestRecord(record Record) string {
	payload, err := ChainPayload(record)
	if err != nil {
		return ""
	}
	return ChainDigest(payload)
}

// ChainPayload renders the exact bytes one protected audit record contributes
// to the chain: the record with its own digest cleared, so the digest covers
// everything about the record except itself. Every sink must chain over these
// bytes — a chain each sink computed its own way would be verifiable only by
// the sink that wrote it, which is the opposite of tamper evidence.
func ChainPayload(record Record) ([]byte, error) {
	copyRecord := record
	copyRecord.Digest = ""
	encoded, err := json.Marshal(copyRecord)
	if err != nil {
		return nil, fmt.Errorf("render protected audit record: %w", err)
	}
	return encoded, nil
}

// ChainDigest is the digest of one record's chain payload.
func ChainDigest(payload []byte) string {
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func opaque(value string, maximum int) bool {
	if len(value) < 1 || len(value) > maximum {
		return false
	}
	for index, character := range value {
		if (character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || (index > 0 && (character == '.' || character == '_' || character == ':' || character == '-')) {
			continue
		}
		return false
	}
	return true
}
func printable(value string) bool {
	for _, character := range value {
		if character < 0x20 || character > 0x7e {
			return false
		}
	}
	return true
}
func digest(value string) bool {
	if len(value) != 71 || value[:7] != "sha256:" {
		return false
	}
	for _, character := range value[7:] {
		if !lowerHexDigit(character) {
			return false
		}
	}
	return true
}

// lowerHexDigit reports whether the character is a lower-case hexadecimal
// digit. Digest and trace formats are lower-case only, so an upper-case
// digit is rejected rather than normalized.
func lowerHexDigit(character rune) bool {
	return character >= '0' && character <= '9' || character >= 'a' && character <= 'f'
}
func trace(value string) bool {
	if len(value) != 55 || value[:3] != "00-" || value[35] != '-' || value[52] != '-' || value[3:35] == "00000000000000000000000000000000" || value[36:52] == "0000000000000000" {
		return false
	}
	for index, character := range value {
		if index == 2 || index == 35 || index == 52 {
			continue
		}
		if !lowerHexDigit(character) {
			return false
		}
	}
	return true
}

type MemoryAlerts struct {
	lock   sync.Mutex
	Values []string
}

func (a *MemoryAlerts) Alert(_ context.Context, code, detail string) error {
	a.lock.Lock()
	defer a.lock.Unlock()
	a.Values = append(a.Values, code+":"+detail)
	return nil
}
