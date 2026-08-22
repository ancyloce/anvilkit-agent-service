// Package postgres implements the protected audit sink on an independently
// held database.
//
// The sink is protected in two senses. It is separate: the connection comes
// from its own configured endpoint, so the records of a security decision do
// not live at the mercy of the same instance the decision was made about. And
// it is tamper evident: every record carries the digest of the one before it,
// the digest is taken over the exact bytes the row stores, and Verify walks
// the whole chain — so a record that is altered, removed, or inserted after
// the fact breaks the chain at that point and cannot be made to chain again
// without rewriting everything after it.
package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/securityaudit"
)

// chainLock serializes appends so two concurrent writers cannot both chain
// onto the same predecessor and leave a fork behind.
const chainLock = 0x5ec0a0d17

// RuntimeRole is the database role the service appends and reads under. It
// holds exactly those two privileges and nothing else, so the connection the
// running service uses cannot alter the schema, rewrite a record, or remove
// one — not because a trigger stops it, but because it was never granted the
// right to try. The append-only trigger and this role are deliberately two
// separate barriers: a trigger can be disabled by whoever owns the table, and
// the point of the separation is that the running service is not that.
const RuntimeRole = "agent_protected_audit_rw"

// Sink is the durable protected audit sink.
type Sink struct{ database *pgxpool.Pool }

func New(database *pgxpool.Pool) (*Sink, error) {
	if database == nil {
		return nil, fmt.Errorf("protected audit sink: an independently held database is required")
	}
	return &Sink{database: database}, nil
}

var _ securityaudit.ProtectedSink = (*Sink)(nil)

// EnsureSchema prepares the protected audit table. It is schema management,
// not runtime work: it is run once at startup on an administrative connection
// and never on the connection the service then appends through.
//
// Three barriers are established here, and they are independent on purpose.
// The table is append-only: a trigger raises on every update, delete, and
// truncate. Every column duplicated from the authenticated payload is checked
// against that payload on the way in, so a row cannot be filed under one
// identity while carrying another, or claim a predecessor or a digest that its
// own bytes do not. And the role the service runs as is granted append and
// read alone, so the running service holds no privilege to rewrite anything
// even if a barrier above it were removed. None of these is the evidence —
// the chain digests are what make a rewrite that got past all three
// detectable afterwards.
func (s *Sink) EnsureSchema(ctx context.Context) error {
	_, err := s.database.Exec(ctx, `CREATE SCHEMA IF NOT EXISTS agent_protected_audit;
CREATE SEQUENCE IF NOT EXISTS agent_protected_audit.record_order_seq;
CREATE TABLE IF NOT EXISTS agent_protected_audit.records (
 record_id text PRIMARY KEY,
 record_order bigint NOT NULL UNIQUE DEFAULT nextval('agent_protected_audit.record_order_seq') CHECK(record_order>0),
 previous_digest text NOT NULL,
 record_digest text NOT NULL,
 chain_payload bytea NOT NULL,
 recorded_at timestamptz NOT NULL DEFAULT transaction_timestamp());
ALTER TABLE agent_protected_audit.records ALTER COLUMN record_order SET DEFAULT nextval('agent_protected_audit.record_order_seq');
SELECT setval('agent_protected_audit.record_order_seq', GREATEST(COALESCE((SELECT max(record_order) FROM agent_protected_audit.records), 0), 1), COALESCE((SELECT max(record_order) FROM agent_protected_audit.records), 0) > 0);
CREATE OR REPLACE FUNCTION agent_protected_audit.refuse_rewrite() RETURNS trigger AS $$
BEGIN
 RAISE EXCEPTION 'the protected audit chain is append-only';
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS protected_audit_is_append_only ON agent_protected_audit.records;
CREATE TRIGGER protected_audit_is_append_only BEFORE UPDATE OR DELETE OR TRUNCATE ON agent_protected_audit.records
 FOR EACH STATEMENT EXECUTE FUNCTION agent_protected_audit.refuse_rewrite();
CREATE OR REPLACE FUNCTION agent_protected_audit.guard_authenticated_columns() RETURNS trigger AS $$
DECLARE authenticated jsonb;
BEGIN
 authenticated := convert_from(NEW.chain_payload,'UTF8')::jsonb;
 IF NEW.record_id IS DISTINCT FROM (authenticated->>'ID') THEN
  RAISE EXCEPTION 'the protected audit record identity does not match its authenticated payload';
 END IF;
 IF NEW.previous_digest IS DISTINCT FROM coalesce(authenticated->>'PreviousDigest','') THEN
  RAISE EXCEPTION 'the protected audit predecessor does not match its authenticated payload';
 END IF;
 IF NEW.record_digest IS DISTINCT FROM 'sha256:'||encode(sha256(NEW.chain_payload),'hex') THEN
  RAISE EXCEPTION 'the protected audit digest does not match its authenticated payload';
 END IF;
 RETURN NEW;
END;
$$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS protected_audit_columns_match_payload ON agent_protected_audit.records;
CREATE TRIGGER protected_audit_columns_match_payload BEFORE INSERT ON agent_protected_audit.records
 FOR EACH ROW EXECUTE FUNCTION agent_protected_audit.guard_authenticated_columns();
DO $$ BEGIN CREATE ROLE agent_protected_audit_rw NOLOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END $$;
REVOKE ALL ON SCHEMA agent_protected_audit FROM PUBLIC;
REVOKE ALL ON agent_protected_audit.records FROM PUBLIC;
REVOKE ALL ON agent_protected_audit.records FROM agent_protected_audit_rw;
REVOKE ALL ON SEQUENCE agent_protected_audit.record_order_seq FROM PUBLIC;
REVOKE ALL ON SEQUENCE agent_protected_audit.record_order_seq FROM agent_protected_audit_rw;
GRANT USAGE ON SCHEMA agent_protected_audit TO agent_protected_audit_rw;
GRANT SELECT, INSERT ON agent_protected_audit.records TO agent_protected_audit_rw;
GRANT USAGE, SELECT ON SEQUENCE agent_protected_audit.record_order_seq TO agent_protected_audit_rw;
GRANT agent_protected_audit_rw TO CURRENT_USER;`)
	if err != nil {
		return fmt.Errorf("ensure protected audit schema: %w", err)
	}
	return nil
}

// VerifyRuntimePrivileges proves the separation the schema establishes is
// really in force. It is checked rather than assumed because a grant made once
// and widened later is exactly the change nobody notices: the service keeps
// working, and the only thing that changed is that it could now rewrite its
// own audit. Startup refuses rather than running on a privilege set nobody
// intended.
func (s *Sink) VerifyRuntimePrivileges(ctx context.Context) error {
	var appends, reads, rewrites, removes, truncates bool
	err := s.database.QueryRow(ctx, `SELECT
	 has_table_privilege($1,'agent_protected_audit.records','INSERT'),
	 has_table_privilege($1,'agent_protected_audit.records','SELECT'),
	 has_table_privilege($1,'agent_protected_audit.records','UPDATE'),
	 has_table_privilege($1,'agent_protected_audit.records','DELETE'),
	 has_table_privilege($1,'agent_protected_audit.records','TRUNCATE')`, RuntimeRole).
		Scan(&appends, &reads, &rewrites, &removes, &truncates)
	if err != nil {
		return fmt.Errorf("read protected audit runtime privileges: %w", err)
	}
	if !appends || !reads {
		return fmt.Errorf("protected audit runtime role %q cannot append and read its own records", RuntimeRole)
	}
	if rewrites || removes || truncates {
		return fmt.Errorf("protected audit runtime role %q holds rewrite privileges it must never have", RuntimeRole)
	}
	return nil
}

// Check proves the protected audit endpoint is reachable. A security decision
// that cannot be recorded is not one the service is allowed to make, so this
// is a startup condition rather than a diagnostic.
func (s *Sink) Check(ctx context.Context) error {
	if err := s.database.Ping(ctx); err != nil {
		return fmt.Errorf("check protected audit sink: %w", err)
	}
	return nil
}

// Append records one audit record at the end of the chain and returns it with
// the chain fields it was given. A record identity that already exists is not
// written again: the same content returns the retained record and reports that
// nothing was inserted, and different content under the same identity is a
// conflict rather than a second record.
func (s *Sink) Append(ctx context.Context, record securityaudit.Record) (securityaudit.Record, bool, error) {
	if record.ID == "" {
		return securityaudit.Record{}, false, problem.New(problem.CodeRequestInvalid, "")
	}
	if retained, found, err := s.read(ctx, record.ID); err != nil {
		return securityaudit.Record{}, false, err
	} else if found {
		return conflictOrRetained(record, retained)
	}
	tx, err := s.database.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return securityaudit.Record{}, false, fmt.Errorf("open protected audit transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, int64(chainLock)); err != nil {
		return securityaudit.Record{}, false, fmt.Errorf("serialize protected audit append: %w", err)
	}
	// The predecessor is read inside the lock, so the digest this record
	// chains onto is the one that is still last when the row lands.
	previous := ""
	err = tx.QueryRow(ctx, `SELECT record_digest FROM agent_protected_audit.records ORDER BY record_order DESC LIMIT 1`).Scan(&previous)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return securityaudit.Record{}, false, fmt.Errorf("read protected audit chain head: %w", err)
	}
	record.PreviousDigest = previous
	record.Digest = ""
	payload, err := securityaudit.ChainPayload(record)
	if err != nil {
		return securityaudit.Record{}, false, err
	}
	record.Digest = securityaudit.ChainDigest(payload)
	tag, err := tx.Exec(ctx, `INSERT INTO agent_protected_audit.records(record_id,previous_digest,record_digest,chain_payload) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`,
		record.ID, record.PreviousDigest, record.Digest, payload)
	if err != nil {
		return securityaudit.Record{}, false, fmt.Errorf("append protected audit record: %w", err)
	}
	if tag.RowsAffected() == 0 {
		// The identity was taken between the read above and this insert.
		if err := tx.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			return securityaudit.Record{}, false, fmt.Errorf("close protected audit transaction: %w", err)
		}
		retained, found, err := s.read(ctx, record.ID)
		if err != nil {
			return securityaudit.Record{}, false, err
		}
		if !found {
			return securityaudit.Record{}, false, fmt.Errorf("protected audit record %q was neither inserted nor retained", record.ID)
		}
		return conflictOrRetained(record, retained)
	}
	if err := tx.Commit(ctx); err != nil {
		return securityaudit.Record{}, false, fmt.Errorf("commit protected audit record: %w", err)
	}
	return record, true, nil
}

// Lookup answers what is recorded under one identity, with the same integrity
// checks every other read makes.
func (s *Sink) Lookup(ctx context.Context, id string) (securityaudit.Record, bool, error) {
	if id == "" {
		return securityaudit.Record{}, false, problem.New(problem.CodeRequestInvalid, "")
	}
	return s.read(ctx, id)
}

// Read returns the whole chain in the order it was written.
func (s *Sink) Read(ctx context.Context) ([]securityaudit.Record, error) {
	rows, err := s.database.Query(ctx, `SELECT record_id,previous_digest,record_digest,chain_payload FROM agent_protected_audit.records ORDER BY record_order`)
	if err != nil {
		return nil, fmt.Errorf("read protected audit records: %w", err)
	}
	defer rows.Close()
	records := make([]securityaudit.Record, 0)
	for rows.Next() {
		var id, storedPrevious, digest string
		var payload []byte
		if err := rows.Scan(&id, &storedPrevious, &digest, &payload); err != nil {
			return nil, fmt.Errorf("scan protected audit record: %w", err)
		}
		record, err := authenticated(id, storedPrevious, digest, payload)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate protected audit records: %w", err)
	}
	return records, nil
}

// Verify walks the chain and reports the first place it breaks. Every fact the
// row states outside its authenticated bytes is checked against those bytes —
// its identity, its predecessor, and its digest — and then the predecessor is
// checked against the record actually before it. Altering a record breaks its
// digest, re-chaining it breaks its position, removing one breaks the position
// of its successor, and filing one under an identity its own payload does not
// claim breaks the identity check that used to be missing entirely: the
// dedupe key and the authenticated identity could disagree, so a lookup could
// answer with a record that was not the record asked for.
func (s *Sink) Verify(ctx context.Context) error {
	rows, err := s.database.Query(ctx, `SELECT record_id,previous_digest,record_digest,chain_payload FROM agent_protected_audit.records ORDER BY record_order`)
	if err != nil {
		return fmt.Errorf("read protected audit chain: %w", err)
	}
	defer rows.Close()
	previous := ""
	for rows.Next() {
		var id, storedPrevious, digest string
		var payload []byte
		if err := rows.Scan(&id, &storedPrevious, &digest, &payload); err != nil {
			return fmt.Errorf("scan protected audit chain: %w", err)
		}
		record, err := authenticated(id, storedPrevious, digest, payload)
		if err != nil {
			return err
		}
		if record.PreviousDigest != previous {
			return fmt.Errorf("protected audit chain mismatch: record %q does not follow the record before it", id)
		}
		previous = digest
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate protected audit chain: %w", err)
	}
	return nil
}

func (s *Sink) read(ctx context.Context, id string) (securityaudit.Record, bool, error) {
	var payload []byte
	var storedPrevious, digest string
	err := s.database.QueryRow(ctx, `SELECT previous_digest,record_digest,chain_payload FROM agent_protected_audit.records WHERE record_id=$1`, id).Scan(&storedPrevious, &digest, &payload)
	if errors.Is(err, pgx.ErrNoRows) {
		return securityaudit.Record{}, false, nil
	}
	if err != nil {
		return securityaudit.Record{}, false, fmt.Errorf("read protected audit record: %w", err)
	}
	record, err := authenticated(id, storedPrevious, digest, payload)
	if err != nil {
		return securityaudit.Record{}, false, err
	}
	return record, true, nil
}

// authenticated turns one stored row into a record only if every column the
// row duplicates from the authenticated payload agrees with that payload. The
// payload is what the chain digest covers, so it is the authority: a column
// that disagrees with it is not a detail to reconcile, it is a row that has
// been written or altered outside the path that authenticates them, and the
// read fails rather than answering from it.
func authenticated(id, storedPrevious, digest string, payload []byte) (securityaudit.Record, error) {
	if securityaudit.ChainDigest(payload) != digest {
		return securityaudit.Record{}, fmt.Errorf("protected audit chain mismatch: record %q does not match its recorded digest", id)
	}
	record, err := decode(payload)
	if err != nil {
		return securityaudit.Record{}, err
	}
	if record.ID != id {
		return securityaudit.Record{}, fmt.Errorf("protected audit chain mismatch: record %q is filed under an identity its authenticated payload does not claim", id)
	}
	if record.PreviousDigest != storedPrevious {
		return securityaudit.Record{}, fmt.Errorf("protected audit chain mismatch: record %q does not claim the predecessor its row records", id)
	}
	record.Digest = digest
	return record, nil
}

// conflictOrRetained decides what a repeated record identity means. The chain
// fields are the sink's own, so they are excluded from the comparison: the
// question is whether the same decision is being recorded again, not whether
// it would land in the same place.
func conflictOrRetained(offered, retained securityaudit.Record) (securityaudit.Record, bool, error) {
	left, right := offered, retained
	left.PreviousDigest, left.Digest = "", ""
	right.PreviousDigest, right.Digest = "", ""
	leftBytes, err := securityaudit.ChainPayload(left)
	if err != nil {
		return securityaudit.Record{}, false, err
	}
	rightBytes, err := securityaudit.ChainPayload(right)
	if err != nil {
		return securityaudit.Record{}, false, err
	}
	if !bytes.Equal(leftBytes, rightBytes) {
		return securityaudit.Record{}, false, problem.New(problem.CodeIdempotencyConflict, "")
	}
	return retained, false, nil
}

func decode(payload []byte) (securityaudit.Record, error) {
	var record securityaudit.Record
	if err := json.Unmarshal(payload, &record); err != nil {
		return securityaudit.Record{}, fmt.Errorf("decode protected audit record: %w", err)
	}
	return record, nil
}
