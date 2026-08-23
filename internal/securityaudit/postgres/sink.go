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
	"strings"

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

// Provision establishes the protected audit on an administrative connection
// and proves the runtime role ended up confined to append and read.
//
// It is deliberately not reachable from the running service. Schema
// management needs a credential that owns the table, and a long-running
// process that holds such a credential owns the account of its own security
// decisions for as long as it runs — whether it uses the credential or not.
// So the administrative credential belongs to a one-shot provisioning run that
// exits, and the service is left with a login that can only add to the chain.
//
// requireSeparation asks for the further proof that the administering login
// and the runtime login are two different identities. A controlled stack
// administers the audit with the credential it also runs as, so the
// separation cannot hold there and is not claimed; a deployment that means it
// asks for it.
func Provision(ctx context.Context, admin *pgxpool.Pool, runtimeLogin string, requireSeparation bool) error {
	sink, err := New(admin)
	if err != nil {
		return err
	}
	if err := sink.EnsureSchema(ctx, runtimeLogin); err != nil {
		return err
	}
	if err := sink.VerifyRuntimePrivileges(ctx); err != nil {
		return err
	}
	if !requireSeparation {
		return nil
	}
	return sink.VerifyRuntimeSeparation(ctx, runtimeLogin)
}

// barrier is one database-side guard the protected audit depends on, named
// completely enough that startup can tell the guard it established from a
// guard that merely carries its name.
//
// A trigger is identified by four things that can each be changed
// independently, and changing any one of them turns the barrier off while
// leaving the name in place: whether it is enabled at all, when and on what
// it fires, which function it executes, and what that function does. Only the
// name used to be checked, so a barrier that had been disabled, re-pointed at
// a permissive function, or whose function body had been replaced all
// reported themselves as present.
type barrier struct {
	// trigger and function are the names the barrier is established under.
	trigger, function string
	// firing is the trigger's tgtype: the timing, the level, and the events
	// it fires on, packed exactly as PostgreSQL packs them. A trigger
	// re-created under the same name for a different event is a different
	// barrier and this is what says so.
	firing int16
	// body is the exact source of the function the trigger executes. It is
	// the same text EnsureSchema installs, so a function replaced in place —
	// which needs no privilege beyond owning it, and leaves every catalog
	// name unchanged — is caught by comparison rather than trusted.
	body string
}

// Trigger type bits, as PostgreSQL packs them in pg_trigger.tgtype. They are
// spelled out here because the barriers are verified against these exact
// values and a bare number in a comparison says nothing about what fires.
const (
	firesPerRow       int16 = 1 << 0
	firesBefore       int16 = 1 << 1
	firesOnInsert     int16 = 1 << 2
	firesOnDelete     int16 = 1 << 3
	firesOnUpdate     int16 = 1 << 4
	firesOnTruncate   int16 = 1 << 5
	auditSchemaName         = "agent_protected_audit"
	auditRecordsTable       = "agent_protected_audit.records"
)

// refuseRewriteBody raises on every statement that would change or remove a
// record. It is the append-only barrier's whole behaviour.
const refuseRewriteBody = `
BEGIN
 RAISE EXCEPTION 'the protected audit chain is append-only';
END;
`

// guardAuthenticatedColumnsBody checks every column duplicated from the
// authenticated payload against that payload on the way in.
const guardAuthenticatedColumnsBody = `
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
`

// barriers is the complete set of database-side guards, and it is the single
// source both EnsureSchema and RequireProvisioned read. Establishing and
// verifying from one description is what keeps the two from drifting into a
// state where the audit is provisioned correctly and checked for something
// else.
func barriers() []barrier {
	return []barrier{
		{
			trigger:  "protected_audit_is_append_only",
			function: "refuse_rewrite",
			firing:   firesBefore | firesOnUpdate | firesOnDelete | firesOnTruncate,
			body:     refuseRewriteBody,
		},
		{
			trigger:  "protected_audit_columns_match_payload",
			function: "guard_authenticated_columns",
			firing:   firesPerRow | firesBefore | firesOnInsert,
			body:     guardAuthenticatedColumnsBody,
		},
	}
}

// RequireProvisioned proves the protected audit was established before the
// service starts appending to it, on the connection the service will use.
//
// The service cannot create the chain it is audited in — that is the whole
// point of provisioning it separately — so it has to be able to tell an audit
// that is not there from one that is. Every barrier is asked for completely:
// a table whose append-only trigger was dropped is not a protected audit, and
// neither is one whose trigger was disabled, re-pointed at a function that
// permits what it was meant to refuse, or whose function body was replaced in
// place. Starting on any of those would produce records that look exactly
// like records that mean something.
func (s *Sink) RequireProvisioned(ctx context.Context) error {
	var table bool
	if err := s.database.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, auditRecordsTable).Scan(&table); err != nil {
		return fmt.Errorf("read protected audit provisioning state: %w", err)
	}
	if !table {
		return fmt.Errorf("the protected audit is not provisioned: establish it with the protected-audit provisioner before starting the service")
	}
	for _, expected := range barriers() {
		if err := s.requireBarrier(ctx, expected); err != nil {
			return err
		}
	}
	var appends, reads bool
	if err := s.database.QueryRow(ctx, `SELECT
	 has_table_privilege(session_user,'agent_protected_audit.records','INSERT'),
	 has_table_privilege(session_user,'agent_protected_audit.records','SELECT')`).Scan(&appends, &reads); err != nil {
		return fmt.Errorf("read protected audit runtime standing: %w", err)
	}
	if !appends || !reads {
		return fmt.Errorf("the protected audit runtime login cannot append and read the chain it is granted")
	}
	return nil
}

// requireBarrier proves one guard is present, enabled, firing on what it was
// established to fire on, and executing exactly the function that was
// installed under it.
func (s *Sink) requireBarrier(ctx context.Context, expected barrier) error {
	var enabled string
	var firing int16
	var arguments int16
	var unconditional bool
	var schema, function, body string
	err := s.database.QueryRow(ctx, `SELECT trigger.tgenabled, trigger.tgtype, trigger.tgnargs, trigger.tgqual IS NULL,
	 namespace.nspname, routine.proname, routine.prosrc
	FROM pg_trigger AS trigger
	JOIN pg_proc AS routine ON routine.oid = trigger.tgfoid
	JOIN pg_namespace AS namespace ON namespace.oid = routine.pronamespace
	WHERE trigger.tgrelid = to_regclass($1) AND trigger.tgname = $2 AND NOT trigger.tgisinternal`,
		auditRecordsTable, expected.trigger).
		Scan(&enabled, &firing, &arguments, &unconditional, &schema, &function, &body)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("the protected audit is provisioned without its %s barrier", expected.trigger)
	}
	if err != nil {
		return fmt.Errorf("read protected audit %s barrier: %w", expected.trigger, err)
	}
	// 'O' fires for ordinary sessions and 'A' fires always. 'D' is disabled
	// and 'R' fires only on a replica, and both leave a row in the catalog
	// that a check for the trigger's mere existence reads as present.
	if enabled != "O" && enabled != "A" {
		return fmt.Errorf("the protected audit %s barrier is disabled", expected.trigger)
	}
	if firing != expected.firing {
		return fmt.Errorf("the protected audit %s barrier fires on something other than what it guards", expected.trigger)
	}
	// A WHEN clause or bound arguments make the barrier conditional, and a
	// condition that is never true is a barrier that never runs.
	if !unconditional || arguments != 0 {
		return fmt.Errorf("the protected audit %s barrier is conditional", expected.trigger)
	}
	if schema != auditSchemaName || function != expected.function {
		return fmt.Errorf("the protected audit %s barrier executes %s.%s rather than the function it was established with", expected.trigger, schema, function)
	}
	if body != expected.body {
		return fmt.Errorf("the protected audit %s barrier executes a function whose body is not the one it was established with", expected.trigger)
	}
	return nil
}

// EnsureSchema prepares the protected audit table. It is schema management,
// not runtime work: it is run once by the provisioner on an administrative
// connection and never on the connection the service then appends through.
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
//
// The trigger functions are installed from the same descriptions
// RequireProvisioned verifies against, so what startup asks for is what
// provisioning put there rather than a second copy of it written down twice.
func (s *Sink) EnsureSchema(ctx context.Context, runtimeLogin string) error {
	if !identifier(runtimeLogin) {
		return fmt.Errorf("protected audit schema: the runtime login role must be named so the grant can be made to it and to nothing else")
	}
	// The administering identity and the runtime identity are two identities
	// or there is no separation to speak of, and this is asked before
	// anything is established rather than as a later proof a deployment can
	// be configured out of. An audit whose runtime login owns the table is an
	// audit the running service can rewrite: the barriers below are on
	// objects it would own, and an owner drops its own triggers.
	var administrator, session string
	if err := s.database.QueryRow(ctx, `SELECT current_user, session_user`).Scan(&administrator, &session); err != nil {
		return fmt.Errorf("read protected audit administrative identity: %w", err)
	}
	if runtimeLogin == administrator || runtimeLogin == session {
		return fmt.Errorf("protected audit schema: the runtime login %q is the login administering the audit, so no barrier established here confines the running service", runtimeLogin)
	}
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
`+establishBarriers()+`DO $x$ BEGIN CREATE ROLE agent_protected_audit_rw NOLOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END $x$;
REVOKE ALL ON SCHEMA agent_protected_audit FROM PUBLIC;
REVOKE ALL ON agent_protected_audit.records FROM PUBLIC;
REVOKE ALL ON agent_protected_audit.records FROM agent_protected_audit_rw;
REVOKE ALL ON SEQUENCE agent_protected_audit.record_order_seq FROM PUBLIC;
REVOKE ALL ON SEQUENCE agent_protected_audit.record_order_seq FROM agent_protected_audit_rw;
GRANT USAGE ON SCHEMA agent_protected_audit TO agent_protected_audit_rw;
GRANT SELECT, INSERT ON agent_protected_audit.records TO agent_protected_audit_rw;
GRANT USAGE, SELECT ON SEQUENCE agent_protected_audit.record_order_seq TO agent_protected_audit_rw;`)
	if err != nil {
		return fmt.Errorf("ensure protected audit schema: %w", err)
	}
	// The runtime role is granted to the login the service connects as, and to
	// nobody else. It used to be granted to CURRENT_USER — the administrative
	// login — which meant the account that owns the table, can drop its
	// triggers, and can rewrite any row was also the account the service ran
	// as. Everything below it was then decoration: the append-only trigger,
	// the column guard, and the narrow role were all things the running
	// process could have removed.
	//
	// The identifier is validated above rather than escaped here because a
	// role name is not a parameter position in GRANT, and a check that admits
	// only ordinary identifiers is a smaller thing to be sure of than an
	// escaping routine.
	if _, err := s.database.Exec(ctx, `GRANT `+RuntimeRole+` TO "`+runtimeLogin+`"`); err != nil {
		return fmt.Errorf("grant the protected audit runtime role to %q: %w", runtimeLogin, err)
	}
	return nil
}

// establishBarriers renders the statements that install every guard, from the
// same descriptions RequireProvisioned checks. Each one is dropped and
// re-created rather than left alone, so re-provisioning an audit whose
// barriers were disabled, re-pointed, or rewritten restores exactly what was
// meant to be there.
func establishBarriers() string {
	var statements strings.Builder
	for _, guard := range barriers() {
		statements.WriteString("CREATE OR REPLACE FUNCTION " + auditSchemaName + "." + guard.function + "() RETURNS trigger AS $x$" + guard.body + "$x$ LANGUAGE plpgsql;\n")
		statements.WriteString("DROP TRIGGER IF EXISTS " + guard.trigger + " ON " + auditRecordsTable + ";\n")
		statements.WriteString("CREATE TRIGGER " + guard.trigger + " " + guard.timing() + " ON " + auditRecordsTable + "\n FOR EACH " + guard.level() + " EXECUTE FUNCTION " + auditSchemaName + "." + guard.function + "();\n")
	}
	return statements.String()
}

// timing renders the trigger's timing and events from the firing bits, so the
// statement that creates a barrier and the check that verifies it are derived
// from one description rather than kept in step by hand.
func (b barrier) timing() string {
	events := make([]string, 0, 4)
	for _, event := range []struct {
		bit  int16
		name string
	}{
		{firesOnInsert, "INSERT"},
		{firesOnUpdate, "UPDATE"},
		{firesOnDelete, "DELETE"},
		{firesOnTruncate, "TRUNCATE"},
	} {
		if b.firing&event.bit != 0 {
			events = append(events, event.name)
		}
	}
	when := "AFTER"
	if b.firing&firesBefore != 0 {
		when = "BEFORE"
	}
	return when + " " + strings.Join(events, " OR ")
}

// level renders whether the barrier fires once per row or once per statement.
func (b barrier) level() string {
	if b.firing&firesPerRow != 0 {
		return "ROW"
	}
	return "STATEMENT"
}

// identifier admits an ordinary lower-case SQL identifier: a letter or
// underscore, then letters, digits, underscores, or dollars, bounded to what
// PostgreSQL will accept.
func identifier(value string) bool {
	if len(value) < 1 || len(value) > 63 {
		return false
	}
	for index, character := range value {
		switch {
		case character >= 'a' && character <= 'z', character == '_':
		case index > 0 && (character >= '0' && character <= '9' || character == '$'):
		default:
			return false
		}
	}
	return true
}

// VerifyRuntimePrivileges proves the separation the schema establishes is
// really in force. It is checked rather than assumed because a grant made once
// and widened later is exactly the change nobody notices: the service keeps
// working, and the only thing that changed is that it could now rewrite its
// own audit. Startup refuses rather than running on a privilege set nobody
// intended.
func (s *Sink) VerifyRuntimePrivileges(ctx context.Context) error {
	return s.verifyNoRewrite(ctx, RuntimeRole, "runtime role")
}

// VerifyRuntimeSeparation proves the login the service connects as is not the
// login that administers the audit, and holds nothing beyond append and read.
//
// The separation is checked from the administrative side because that is where
// both identities are visible at once. Three things are asked, and each is a
// way the separation quietly stops being one: the two logins must differ, so
// the process that appends is not the process that owns the table; the runtime
// login must not be a superuser, because a superuser's privileges are not
// governed by grants at all; and it must not own the audit schema or its
// table, because an owner can drop the triggers and rewrite the rows whatever
// the grants say.
func (s *Sink) VerifyRuntimeSeparation(ctx context.Context, runtimeLogin string) error {
	if !identifier(runtimeLogin) {
		return fmt.Errorf("protected audit separation: the runtime login role must be named")
	}
	var administrator string
	if err := s.database.QueryRow(ctx, `SELECT current_user`).Scan(&administrator); err != nil {
		return fmt.Errorf("read protected audit administrative identity: %w", err)
	}
	if administrator == runtimeLogin {
		return fmt.Errorf("the protected audit is administered by the same login %q the service runs as", runtimeLogin)
	}
	var superuser, ownsSchema, ownsTable bool
	err := s.database.QueryRow(ctx, `SELECT
	 coalesce((SELECT rolsuper FROM pg_roles WHERE rolname=$1), false),
	 pg_has_role($1, (SELECT nspowner FROM pg_namespace WHERE nspname='agent_protected_audit'), 'USAGE'),
	 pg_has_role($1, (SELECT relowner FROM pg_class WHERE oid='agent_protected_audit.records'::regclass), 'USAGE')`, runtimeLogin).
		Scan(&superuser, &ownsSchema, &ownsTable)
	if err != nil {
		return fmt.Errorf("read protected audit runtime login standing: %w", err)
	}
	if superuser {
		return fmt.Errorf("the protected audit runtime login %q is a superuser, so no grant confines it", runtimeLogin)
	}
	if ownsSchema || ownsTable {
		return fmt.Errorf("the protected audit runtime login %q owns the audit schema or table it must only append to", runtimeLogin)
	}
	return s.verifyNoRewrite(ctx, runtimeLogin, "runtime login")
}

// VerifyRuntimeIsolation is the same proof taken from inside the running
// service, on the connection it will actually append through.
//
// It asks about session_user rather than current_user deliberately. The pool
// sets the narrow role on every connection, so current_user answers for the
// role the service is wearing — but wearing a role is not the same as being
// confined to it, and RESET ROLE is one statement away. session_user is the
// login underneath, and what it may do is what the process may do.
func (s *Sink) VerifyRuntimeIsolation(ctx context.Context) error {
	var login string
	if err := s.database.QueryRow(ctx, `SELECT session_user`).Scan(&login); err != nil {
		return fmt.Errorf("read protected audit session identity: %w", err)
	}
	return s.verifyNoRewrite(ctx, login, "running process")
}

// verifyNoRewrite proves one identity may append and read the audit and may do
// nothing else to it. Privileges held through role membership count, which is
// the point: a login that reaches UPDATE through some other role it belongs to
// can rewrite the audit exactly as if it had been granted UPDATE directly.
func (s *Sink) verifyNoRewrite(ctx context.Context, identity, description string) error {
	var appends, reads, rewrites, removes, truncates bool
	err := s.database.QueryRow(ctx, `SELECT
	 has_table_privilege($1,'agent_protected_audit.records','INSERT'),
	 has_table_privilege($1,'agent_protected_audit.records','SELECT'),
	 has_table_privilege($1,'agent_protected_audit.records','UPDATE'),
	 has_table_privilege($1,'agent_protected_audit.records','DELETE'),
	 has_table_privilege($1,'agent_protected_audit.records','TRUNCATE')`, identity).
		Scan(&appends, &reads, &rewrites, &removes, &truncates)
	if err != nil {
		return fmt.Errorf("read protected audit %s privileges: %w", description, err)
	}
	if !appends || !reads {
		return fmt.Errorf("protected audit %s %q cannot append and read its own records", description, identity)
	}
	if rewrites || removes || truncates {
		return fmt.Errorf("protected audit %s %q holds rewrite privileges it must never have", description, identity)
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
