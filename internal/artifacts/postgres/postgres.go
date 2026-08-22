// Package postgres holds the durable artifact metadata store, the write-once
// object store, and the grant-auditing signed reader.
package postgres

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ancyloce/anvilkit-agent-service/internal/artifacts"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
)

// Store is the durable artifact metadata record over agent_artifacts.metadata.
// The lifecycle trigger in the database enforces the same transition, CAS, and
// tombstone rules the service validates, so a defective caller cannot corrupt
// history even by writing SQL directly.
type Store struct {
	database *pgxpool.Pool
}

func NewStore(database *pgxpool.Pool) (*Store, error) {
	if database == nil {
		return nil, fmt.Errorf("artifact store: a database is required")
	}
	return &Store{database: database}, nil
}

var _ artifacts.Store = (*Store)(nil)

func (s *Store) Create(ctx context.Context, record artifacts.Record) (artifacts.Record, bool, error) {
	reference, schema, lineageValue, err := encode(record)
	if err != nil {
		return artifacts.Record{}, false, err
	}
	tag, err := s.database.Exec(ctx, `INSERT INTO agent_artifacts.metadata(workspace_id,project_id,artifact_id,run_id,digest,actual_digest,state,version,security_generation,object_reference,schema_identity,lineage,legal_hold,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) ON CONFLICT (workspace_id,project_id,artifact_id) DO NOTHING`,
		record.WorkspaceID, record.ProjectID, record.ID, record.RunID, record.Digest, record.ActualDigest, record.State, record.Version, record.SecurityGeneration, reference, schema, lineageValue, record.LegalHold, record.CreatedAt, record.UpdatedAt)
	if err != nil {
		return artifacts.Record{}, false, fmt.Errorf("record artifact metadata: %w", err)
	}
	winner, ok, err := s.Get(ctx, record.WorkspaceID, record.ProjectID, record.ID)
	if err != nil {
		return artifacts.Record{}, false, err
	}
	if !ok {
		return artifacts.Record{}, false, fmt.Errorf("record artifact metadata: the recorded row is unreadable")
	}
	return winner, tag.RowsAffected() == 1, nil
}

func (s *Store) Get(ctx context.Context, workspace, project string, id artifacts.ID) (artifacts.Record, bool, error) {
	record := artifacts.Record{WorkspaceID: workspace, ProjectID: project, ID: id}
	var reference, schema, lineageValue []byte
	var actualDigest, deletionReason, deletionClaim *string
	var deletedAt, deletionClaimedAt *time.Time
	err := s.database.QueryRow(ctx, `SELECT run_id,digest,actual_digest,state,version,security_generation,object_reference,schema_identity,lineage,legal_hold,created_at,updated_at,deleted_at,deletion_reason,deletion_claim,deletion_claimed_at FROM agent_artifacts.metadata WHERE workspace_id=$1 AND project_id=$2 AND artifact_id=$3`, workspace, project, id).
		Scan(&record.RunID, &record.Digest, &actualDigest, &record.State, &record.Version, &record.SecurityGeneration, &reference, &schema, &lineageValue, &record.LegalHold, &record.CreatedAt, &record.UpdatedAt, &deletedAt, &deletionReason, &deletionClaim, &deletionClaimedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return artifacts.Record{}, false, nil
	}
	if err != nil {
		return artifacts.Record{}, false, fmt.Errorf("read artifact metadata: %w", err)
	}
	if actualDigest != nil {
		record.ActualDigest = *actualDigest
	}
	if deletionReason != nil {
		record.DeletionReason = *deletionReason
	}
	if deletionClaim != nil {
		record.DeletionClaim = *deletionClaim
	}
	record.DeletedAt = deletedAt
	record.DeletionClaimedAt = deletionClaimedAt
	if err := json.Unmarshal(reference, &record.Reference); err != nil {
		return artifacts.Record{}, false, fmt.Errorf("decode artifact object reference: %w", err)
	}
	if err := json.Unmarshal(schema, &record.Schema); err != nil {
		return artifacts.Record{}, false, fmt.Errorf("decode artifact schema identity: %w", err)
	}
	if err := json.Unmarshal(lineageValue, &record.Lineage); err != nil {
		return artifacts.Record{}, false, fmt.Errorf("decode artifact lineage: %w", err)
	}
	return record, true, nil
}

func (s *Store) Update(ctx context.Context, next artifacts.Record, expectedVersion uint64) (artifacts.Record, error) {
	reference, schema, lineageValue, err := encode(next)
	if err != nil {
		return artifacts.Record{}, err
	}
	tag, err := s.database.Exec(ctx, `UPDATE agent_artifacts.metadata SET state=$4,version=$5,security_generation=$6,legal_hold=$7,updated_at=$8,deleted_at=$9,deletion_reason=$10,object_reference=$11,schema_identity=$12,lineage=$13 WHERE workspace_id=$1 AND project_id=$2 AND artifact_id=$3 AND version=$14`,
		next.WorkspaceID, next.ProjectID, next.ID, next.State, next.Version, next.SecurityGeneration, next.LegalHold, next.UpdatedAt, next.DeletedAt, nullable(next.DeletionReason), reference, schema, lineageValue, expectedVersion)
	if err != nil {
		return artifacts.Record{}, fmt.Errorf("update artifact metadata: %w", err)
	}
	if tag.RowsAffected() == 0 {
		if _, ok, getErr := s.Get(ctx, next.WorkspaceID, next.ProjectID, next.ID); getErr != nil {
			return artifacts.Record{}, getErr
		} else if !ok {
			return artifacts.Record{}, problem.New(problem.CodeResourceNotFound, "")
		}
		return artifacts.Record{}, problem.New(problem.CodeVersionConflict, "")
	}
	return next, nil
}

// ClaimDeletion takes durable ownership of one artifact's destruction. The
// whole decision is one statement: the version precondition, the absence of a
// legal hold, the absence of another owner, the move out of every live state,
// and the ownership marker land together or not at all. Nothing is revoked and
// no content is removed until this row is committed, so a hold that races the
// deletion either wins the version — and the deletion stops with the artifact
// intact — or arrives at a record that has already left the live states, where
// the database itself refuses it.
func (s *Store) ClaimDeletion(ctx context.Context, workspace, project string, id artifacts.ID, expectedVersion uint64, claim artifacts.DeletionClaim) (artifacts.Record, error) {
	if !claim.Valid() {
		return artifacts.Record{}, problem.New(problem.CodeRequestInvalid, "")
	}
	tag, err := s.database.Exec(ctx, `UPDATE agent_artifacts.metadata
		SET state=$4,version=version+1,security_generation=security_generation+1,
		    updated_at=$5,deletion_claim=$6,deletion_claimed_at=$5
		WHERE workspace_id=$1 AND project_id=$2 AND artifact_id=$3
		  AND version=$7 AND legal_hold=false AND deletion_claim IS NULL`,
		workspace, project, id, claim.Terminal, claim.At, claim.Decision, expectedVersion)
	if err != nil {
		return artifacts.Record{}, fmt.Errorf("claim artifact deletion: %w", err)
	}
	current, ok, readErr := s.Get(ctx, workspace, project, id)
	if readErr != nil {
		return artifacts.Record{}, readErr
	}
	if !ok {
		return artifacts.Record{}, problem.New(problem.CodeResourceNotFound, "")
	}
	if tag.RowsAffected() == 1 {
		return current, nil
	}
	// The claim did not land. Whether that is this decision meeting its own
	// earlier claim, a standing hold, or another owner decides what the caller
	// is told, and only the record can say which.
	if current.DeletionClaim == claim.Decision {
		return current, nil
	}
	if current.DeletionClaim == "" && current.LegalHold {
		return artifacts.Record{}, problem.New(problem.CodeArtifactAccessDenied, "")
	}
	return artifacts.Record{}, problem.New(problem.CodeVersionConflict, "")
}

func (s *Store) Snapshot(ctx context.Context) ([]artifacts.Record, error) {
	rows, err := s.database.Query(ctx, `SELECT workspace_id,project_id,artifact_id FROM agent_artifacts.metadata`)
	if err != nil {
		return nil, fmt.Errorf("list artifact metadata: %w", err)
	}
	type identity struct{ workspace, project, id string }
	var identities []identity
	for rows.Next() {
		var value identity
		if err := rows.Scan(&value.workspace, &value.project, &value.id); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan artifact identity: %w", err)
		}
		identities = append(identities, value)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list artifact metadata: %w", err)
	}
	records := make([]artifacts.Record, 0, len(identities))
	for _, value := range identities {
		record, ok, err := s.Get(ctx, value.workspace, value.project, artifacts.ID(value.id))
		if err != nil {
			return nil, err
		}
		if ok {
			records = append(records, record)
		}
	}
	return records, nil
}

func encode(record artifacts.Record) ([]byte, []byte, []byte, error) {
	reference, err := json.Marshal(record.Reference)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("encode artifact object reference: %w", err)
	}
	schema, err := json.Marshal(record.Schema)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("encode artifact schema identity: %w", err)
	}
	lineageValue, err := json.Marshal(record.Lineage)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("encode artifact lineage: %w", err)
	}
	return reference, schema, lineageValue, nil
}

func nullable(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

// Objects is the write-once artifact object store over agent_artifacts.objects.
type Objects struct {
	database *pgxpool.Pool
}

func NewObjects(database *pgxpool.Pool) (*Objects, error) {
	if database == nil {
		return nil, fmt.Errorf("artifact objects: a database is required")
	}
	return &Objects{database: database}, nil
}

var _ artifacts.ObjectStore = (*Objects)(nil)

func (o *Objects) PutOnce(ctx context.Context, reference artifacts.Reference, value []byte) error {
	if _, err := o.database.Exec(ctx, `INSERT INTO agent_artifacts.objects(bucket,object_key,bytes,size_bytes,media_type) VALUES($1,$2,$3,$4,$5) ON CONFLICT (bucket,object_key) DO NOTHING`, reference.Bucket, reference.ObjectKey, value, len(value), reference.MediaType); err != nil {
		return fmt.Errorf("write artifact object: %w", err)
	}
	var digestStored, digestGiven string
	err := o.database.QueryRow(ctx, `SELECT encode(sha256(bytes),'hex'), encode(sha256($3::bytea),'hex') FROM agent_artifacts.objects WHERE bucket=$1 AND object_key=$2`, reference.Bucket, reference.ObjectKey, value).Scan(&digestStored, &digestGiven)
	if err != nil {
		return fmt.Errorf("verify artifact object: %w", err)
	}
	if digestStored != digestGiven {
		return fmt.Errorf("write-once conflict")
	}
	return nil
}

func (o *Objects) Delete(ctx context.Context, reference artifacts.Reference) error {
	if _, err := o.database.Exec(ctx, `DELETE FROM agent_artifacts.objects WHERE bucket=$1 AND object_key=$2`, reference.Bucket, reference.ObjectKey); err != nil {
		return fmt.Errorf("delete artifact object: %w", err)
	}
	return nil
}

func (o *Objects) Exists(ctx context.Context, reference artifacts.Reference) (bool, error) {
	var one int
	err := o.database.QueryRow(ctx, `SELECT 1 FROM agent_artifacts.objects WHERE bucket=$1 AND object_key=$2`, reference.Bucket, reference.ObjectKey).Scan(&one)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read artifact object: %w", err)
	}
	return true, nil
}

// Read returns the immutable bytes one reference stores.
func (o *Objects) Read(ctx context.Context, reference artifacts.Reference) ([]byte, error) {
	var value []byte
	err := o.database.QueryRow(ctx, `SELECT bytes FROM agent_artifacts.objects WHERE bucket=$1 AND object_key=$2`, reference.Bucket, reference.ObjectKey).Scan(&value)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, problem.New(problem.CodeResourceNotFound, "")
	}
	if err != nil {
		return nil, fmt.Errorf("read artifact object: %w", err)
	}
	return value, nil
}

// HMACReader signs short-lived read capabilities and audits every grant in
// agent_artifacts.access_grants before the capability leaves the service.
// Verify proves a presented capability against both the signature and the
// durable grant row, including its revocation state. Revoke records the
// withdrawal immutably on the audited rows — the audit history shows what was
// issued and what was withdrawn, and nothing is ever deleted.
type HMACReader struct {
	database *pgxpool.Pool
	secret   []byte
}

func NewHMACReader(database *pgxpool.Pool, secret []byte) (*HMACReader, error) {
	if database == nil {
		return nil, fmt.Errorf("artifact reader: a database is required")
	}
	if len(secret) < 16 {
		return nil, fmt.Errorf("artifact reader: signing material must be at least 16 bytes")
	}
	return &HMACReader{database: database, secret: append([]byte(nil), secret...)}, nil
}

var _ artifacts.Reader = (*HMACReader)(nil)

func (r *HMACReader) SignRead(ctx context.Context, record artifacts.Record, grant artifacts.Grant, ttl time.Duration) (string, error) {
	if ttl <= 0 || grant.ExpiresAt.IsZero() {
		return "", fmt.Errorf("artifact reader: a bounded grant expiry is required")
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("allocate grant identity: %w", err)
	}
	grantID := "grant." + hex.EncodeToString(raw)
	issuedAt := grant.ExpiresAt.Add(-ttl)
	if _, err := r.database.Exec(ctx, `INSERT INTO agent_artifacts.access_grants(workspace_id,project_id,artifact_id,grant_id,security_generation,purpose,actor_id,issued_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		record.WorkspaceID, record.ProjectID, record.ID, grantID, grant.SecurityGeneration, grant.Purpose, grant.ActorID, issuedAt, grant.ExpiresAt); err != nil {
		return "", fmt.Errorf("durably audit artifact grant: %w", err)
	}
	expiry := strconv.FormatInt(grant.ExpiresAt.UTC().Unix(), 10)
	signature := r.sign(record, grant, grantID, expiry)
	return "anvilkit-artifact://" + record.Reference.Bucket + "/" + record.Reference.ObjectKey + "?grant=" + grantID + "&generation=" + strconv.FormatUint(grant.SecurityGeneration, 10) + "&expires=" + expiry + "&signature=" + signature, nil
}

// sign binds the capability to the object, the content digest, the security
// generation, the grant identity and expiry, and the actor and purpose the
// durable grant row audits.
func (r *HMACReader) sign(record artifacts.Record, grant artifacts.Grant, grantID, expiry string) string {
	message := record.Reference.Bucket + "\x00" + record.Reference.ObjectKey + "\x00" + record.Digest + "\x00" + strconv.FormatUint(grant.SecurityGeneration, 10) + "\x00" + grantID + "\x00" + expiry + "\x00" + grant.ActorID + "\x00" + string(grant.Purpose)
	mac := hmac.New(sha256.New, r.secret)
	mac.Write([]byte(message))
	return hex.EncodeToString(mac.Sum(nil))
}

// Verify proves one presented capability. The signature must recompute over
// the presented parameters, and the durable audited grant row must exist,
// bind the same artifact, actor, purpose, generation, and expiry, and carry
// no revocation. Every failure is a denial; nothing is ever partially
// accepted.
func (r *HMACReader) Verify(ctx context.Context, record artifacts.Record, grant artifacts.Grant) error {
	parsed, err := url.Parse(grant.URL)
	if err != nil || parsed.Scheme != "anvilkit-artifact" {
		return fmt.Errorf("artifact grant capability is not parseable")
	}
	if parsed.Host != record.Reference.Bucket || strings.TrimPrefix(parsed.Path, "/") != record.Reference.ObjectKey {
		return fmt.Errorf("artifact grant capability names a different object")
	}
	query := parsed.Query()
	grantID := query.Get("grant")
	generation := query.Get("generation")
	expiry := query.Get("expires")
	presented := query.Get("signature")
	if grantID == "" || generation != strconv.FormatUint(grant.SecurityGeneration, 10) || expiry == "" || presented == "" {
		return fmt.Errorf("artifact grant capability is incomplete")
	}
	expected := r.sign(record, grant, grantID, expiry)
	presentedBytes, err := hex.DecodeString(presented)
	if err != nil || !hmac.Equal(presentedBytes, mustDecodeHex(expected)) {
		return fmt.Errorf("artifact grant signature is invalid")
	}
	expiryUnix, err := strconv.ParseInt(expiry, 10, 64)
	if err != nil || !time.Unix(expiryUnix, 0).UTC().Equal(grant.ExpiresAt.UTC().Truncate(time.Second)) {
		return fmt.Errorf("artifact grant expiry does not match the signed capability")
	}
	var actor, purpose string
	var securityGeneration uint64
	var expiresAt time.Time
	var revokedAt *time.Time
	err = r.database.QueryRow(ctx, `SELECT actor_id,purpose,security_generation,expires_at,revoked_at FROM agent_artifacts.access_grants WHERE workspace_id=$1 AND project_id=$2 AND grant_id=$3`, record.WorkspaceID, record.ProjectID, grantID).
		Scan(&actor, &purpose, &securityGeneration, &expiresAt, &revokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("artifact grant has no durable record")
	}
	if err != nil {
		return fmt.Errorf("read audited artifact grant: %w", err)
	}
	if revokedAt != nil {
		return fmt.Errorf("artifact grant is revoked")
	}
	// Postgres stores microsecond precision; compare at that precision.
	if actor != grant.ActorID || purpose != string(grant.Purpose) || securityGeneration != grant.SecurityGeneration || !expiresAt.Truncate(time.Microsecond).Equal(grant.ExpiresAt.Truncate(time.Microsecond)) {
		return fmt.Errorf("artifact grant record does not match the presented capability")
	}
	return nil
}

func mustDecodeHex(value string) []byte {
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return nil
	}
	return decoded
}

// Revoke withdraws every outstanding grant on the record by marking it
// revoked. The audited rows are never deleted: the immutability trigger
// enforces that a recorded revocation, like the grant identity itself, is
// history.
func (r *HMACReader) Revoke(ctx context.Context, record artifacts.Record) error {
	if _, err := r.database.Exec(ctx, `UPDATE agent_artifacts.access_grants SET revoked_at=transaction_timestamp(),revocation_reason=$4 WHERE workspace_id=$1 AND project_id=$2 AND artifact_id=$3 AND revoked_at IS NULL`, record.WorkspaceID, record.ProjectID, record.ID, "lifecycle:"+string(record.State)); err != nil {
		return fmt.Errorf("record artifact grant revocation: %w", err)
	}
	return nil
}
