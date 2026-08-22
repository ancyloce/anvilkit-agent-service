package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ancyloce/anvilkit-agent-service/internal/api"
	"github.com/ancyloce/anvilkit-agent-service/internal/artifacts"
	"github.com/ancyloce/anvilkit-agent-service/internal/authority"
	authoritypg "github.com/ancyloce/anvilkit-agent-service/internal/authority/postgres"
	"github.com/ancyloce/anvilkit-agent-service/internal/canonical"
	"github.com/ancyloce/anvilkit-agent-service/internal/config"
	contractguard "github.com/ancyloce/anvilkit-agent-service/internal/contracts"
	"github.com/ancyloce/anvilkit-agent-service/internal/execution"
	"github.com/ancyloce/anvilkit-agent-service/internal/journal"
	"github.com/ancyloce/anvilkit-agent-service/internal/persistence"
	"github.com/ancyloce/anvilkit-agent-service/internal/telemetry"
	workflowdbos "github.com/ancyloce/anvilkit-agent-service/internal/workflow/dbos"
)

const custodyTrace = "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"
const custodyBasis = "anvilkit://evidence/records-retention-review/LEGAL-114-hold-instruction"

// custodyStack is the composed service a custody request actually reaches: the
// same builders main() calls, over a real database, behind the real HTTP
// handler. Nothing about custody is stubbed — the artifact lifecycle, the
// current-authority register, the protected audit, and the receipt store are
// all the production implementations.
type custodyStack struct {
	server    *httptest.Server
	core      *runtimeCore
	authority *authoritypg.Store
	database  *pgxpool.Pool
	bearers   bearers
}

func newCustodyStack(t *testing.T, ctx context.Context) *custodyStack {
	t.Helper()
	base := os.Getenv("POSTGRES_TEST_URL")
	if base == "" {
		t.Skip("POSTGRES_TEST_URL is not set")
	}
	databaseURL := isolatedSliceDatabase(t, ctx, base)
	migration, err := pgx.Connect(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	if err := persistence.NewMigrator(migration).Apply(ctx); err != nil {
		t.Fatal(err)
	}
	if err := migration.Close(ctx); err != nil {
		t.Fatal(err)
	}
	managerID, managerDigest := managerReference(t)
	authorityPath := writeRunAuthority(t, managerID, managerDigest)
	minted := mintBearers(t)
	for name, value := range map[string]string{
		"ANVILKIT_ENVIRONMENT":                     "development",
		"ANVILKIT_CONTRACT_ROOT":                   "../..",
		"ANVILKIT_CONTROL_DATABASE_URL":            databaseURL,
		"ANVILKIT_WORKFLOW_DATABASE_URL":           databaseURL,
		"ANVILKIT_EVENTS_DATABASE_URL":             databaseURL,
		"ANVILKIT_ARTIFACTS_DATABASE_URL":          databaseURL,
		"ANVILKIT_EVALUATION_DATABASE_URL":         databaseURL,
		"ANVILKIT_PROTECTED_AUDIT_URL":             databaseURL,
		"ANVILKIT_MODEL_IMPLEMENTATION":            "controlled-fake",
		"ANVILKIT_TOOL_IMPLEMENTATION":             "controlled-fake",
		"ANVILKIT_DOMAIN_IMPLEMENTATION":           "controlled-fake",
		"ANVILKIT_CONTRACT_RUNTIME_IMPLEMENTATION": "controlled-fake",
		"ANVILKIT_WORKER_IMPLEMENTATION":           "controlled-fake",
		"ANVILKIT_CONTROLLED_MODEL_SCRIPT":         "final",
		"ANVILKIT_SIGNING_KEY":                     "custody-signing-material-0123456789",
		"ANVILKIT_ENCRYPTION_KEY":                  "custody-encryption-material-012345",
		"ANVILKIT_RUN_AUTHORITY_FILE":              authorityPath,
		"ANVILKIT_AUTH_TRUST_SNAPSHOT":             minted.trustPath,
		"ANVILKIT_STREAM_CURSOR_SPOOL":             filepath.Join(t.TempDir(), "stream-cursors"),
		"ANVILKIT_AUTH_ISSUERS":                    "issuer",
		"ANVILKIT_EXECUTOR_ID":                     "custody-executor-1",
	} {
		t.Setenv(name, value)
	}
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	pools, err := openPersistencePools(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pools.Close)
	guard, err := contractguard.NewGuard(cfg.ContractRoot)
	if err != nil {
		t.Fatal(err)
	}
	clock, auditClock, err := applicationClock(cfg)
	if err != nil {
		t.Fatal(err)
	}
	receipts := journal.NewMemoryStore()
	protectedAudit, closeAudit, err := buildProtectedAudit(ctx, cfg, auditClock, receipts, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(closeAudit)
	handle := &runtimeHandle{}
	core, err := buildRuntimeCore(ctx, cfg, pools, guard, receipts, clock, protectedAudit, handle)
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := workflowdbos.New(ctx, workflowdbos.Config{DatabaseURL: cfg.WorkflowDatabase, Schema: "agent_dbos", ExecutorID: cfg.ExecutorID, ApplicationVersion: "custody-test", Logger: slog.Default()}, core.executor)
	if err != nil {
		t.Fatal(err)
	}
	handle.set(runtime)
	if err := runtime.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := runtime.Stop(context.Background()); err != nil {
			t.Errorf("stop workflow runtime: %v", err)
		}
	})
	redactor := telemetry.NewRedactor([]string{cfg.SigningKey.RedactionValue(), cfg.EncryptionKey.RedactionValue()})
	observability, err := telemetry.New(cfg.ServiceName, nil, redactor)
	if err != nil {
		t.Fatal(err)
	}
	options, err := agentAPIOptions(ctx, cfg, pools, runtime, core, observability)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(api.New(readyAlways{}, options...))
	t.Cleanup(server.Close)
	register, err := authoritypg.New(pools.Authority, func() time.Time { return time.Now().UTC() })
	if err != nil {
		t.Fatal(err)
	}
	observe, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(observe.Close)
	return &custodyStack{server: server, core: core, authority: register, database: observe, bearers: minted}
}

// createArtifact puts one immutable artifact into the composed artifact
// service. It is not a custody operation: it is how an artifact comes to exist
// so that its custody can be decided.
func (s *custodyStack) createArtifact(t *testing.T, ctx context.Context, id string) artifacts.Record {
	t.Helper()
	payload := []byte(`{"artifact":"` + id + `"}`)
	sum := sha256.Sum256(payload)
	record, err := s.core.artifacts.Create(ctx, artifacts.Create{
		WorkspaceID:   "workspace",
		ProjectID:     "project",
		RunID:         "run.custody",
		ID:            artifacts.ID(id),
		Bytes:         payload,
		ClaimedDigest: "sha256:" + hex.EncodeToString(sum[:]),
		Reference:     artifacts.Reference{Bucket: execution.ArtifactBucket, ObjectKey: id, SizeBytes: int64(len(payload)), MediaType: "application/json"},
		Schema:        artifacts.SchemaIdentity{Component: "anvilkit.contract.schema.agent-artifact", Version: "1.0.0", Digest: "sha256:" + strings.Repeat("e", 64)},
		Lineage: artifacts.Lineage{
			RunID: "run.custody", TaskID: "task.custody", PhysicalAttemptID: "attempt.custody",
			Producer:      artifacts.Producer{TaskID: "task.custody", PhysicalAttemptID: "attempt.custody", RecoveryEpoch: 1, ExecutionGeneration: 1, LeaseEpoch: 1, BuildIdentity: "build.custody", Provider: "controlled-fake"},
			BOMDigest:     "sha256:" + strings.Repeat("a", 64),
			SchemaDigest:  "sha256:" + strings.Repeat("b", 64),
			CatalogDigest: "sha256:" + strings.Repeat("c", 64),
		},
		CreatedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func custodyCommand(id, decision string) []byte {
	return []byte(`{"kind":"DecideArtifactCustodyRequest","artifactId":"` + id + `","decision":"` + decision + `","basis":"` + custodyBasis + `","ticket":"CHG-2291"}`)
}

// decide issues one custody request over HTTP exactly as a client would.
func (s *custodyStack) decide(t *testing.T, ctx context.Context, token, workspace, id, key, etag string, body []byte) (*http.Response, []byte) {
	t.Helper()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, s.server.URL+"/v1/workspaces/"+workspace+"/artifacts/"+id+"/custody", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("traceparent", custodyTrace)
	request.Header.Set("Idempotency-Key", key)
	if etag != "" {
		request.Header.Set("If-Match", etag)
	}
	digest, err := canonical.Digest(body)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-AnvilKit-Request-Digest", digest)
	response, err := (&http.Client{Timeout: 30 * time.Second}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	return response, payload
}

func (s *custodyStack) held(t *testing.T, ctx context.Context, id string) (bool, string, uint64) {
	t.Helper()
	var hold bool
	var state string
	var version int64
	if err := s.database.QueryRow(ctx, `SELECT legal_hold,state,version FROM agent_artifacts.metadata WHERE workspace_id=$1 AND project_id=$2 AND artifact_id=$3`, "workspace", "project", id).Scan(&hold, &state, &version); err != nil {
		t.Fatal(err)
	}
	return hold, state, uint64(version)
}

// An authorized custodian's request reaches the artifact lifecycle through the
// production composition and changes durable state. Everything below the HTTP
// handler is the code path main() composes: no test-only wiring, no permissive
// stand-in for authority, and no stand-in for the protected audit.
func TestArtifactCustodyIsReachableThroughTheProductionComposition(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	stack := newCustodyStack(t, ctx)
	record := stack.createArtifact(t, ctx, "artifact.custody.reachable")

	body := custodyCommand(string(record.ID), "legal-hold-placed")
	response, payload := stack.decide(t, ctx, stack.bearers.custodian, "workspace", string(record.ID), "custody-1", record.ETag(), body)
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("custody status=%d body=%s", response.StatusCode, payload)
	}
	if response.Header.Get("ETag") != `"`+string(record.ID)+`:v`+"2"+`"` {
		t.Fatalf("etag=%q, want the revision the decision produced", response.Header.Get("ETag"))
	}
	hold, state, version := stack.held(t, ctx, string(record.ID))
	if !hold || state != string(artifacts.Pending) || version != 2 {
		t.Fatalf("durable record: hold=%v state=%q version=%d, want the hold applied", hold, state, version)
	}

	// The decision is on the protected audit's own chain, and the chain still
	// verifies afterwards.
	var recorded int
	if err := stack.database.QueryRow(ctx, `SELECT count(*) FROM agent_protected_audit.records WHERE convert_from(chain_payload,'UTF8')::jsonb->>'Action' = 'artifact-legal-hold-placed'`).Scan(&recorded); err != nil {
		t.Fatal(err)
	}
	if recorded < 2 {
		t.Fatalf("protected audit holds %d records for the decision, want its authorization and its outcome", recorded)
	}
	var actor, workload string
	if err := stack.database.QueryRow(ctx, `SELECT convert_from(chain_payload,'UTF8')::jsonb->>'Actor', convert_from(chain_payload,'UTF8')::jsonb->>'Workload' FROM agent_protected_audit.records WHERE convert_from(chain_payload,'UTF8')::jsonb->>'Action' = 'artifact-legal-hold-placed' ORDER BY record_order LIMIT 1`).Scan(&actor, &workload); err != nil {
		t.Fatal(err)
	}
	if actor != "custodian" {
		t.Fatalf("audited actor=%q, want the verified custodian", actor)
	}

	// An exact replay answers with the recorded revision and decides nothing a
	// second time.
	replay, _ := stack.decide(t, ctx, stack.bearers.custodian, "workspace", string(record.ID), "custody-1", record.ETag(), body)
	if replay.StatusCode != http.StatusNoContent || replay.Header.Get("Idempotency-Replayed") != "true" {
		t.Fatalf("replay status=%d replayed=%q", replay.StatusCode, replay.Header.Get("Idempotency-Replayed"))
	}
	if hold, _, version := stack.held(t, ctx, string(record.ID)); !hold || version != 2 {
		t.Fatalf("a replay decided again: hold=%v version=%d", hold, version)
	}

	// A held artifact cannot be destroyed: the lifecycle's own refusal reaches
	// the caller through the production path.
	deletion := custodyCommand(string(record.ID), "deleted")
	refused, _ := stack.decide(t, ctx, stack.bearers.custodian, "workspace", string(record.ID), "custody-2", `"`+string(record.ID)+`:v2"`, deletion)
	if refused.StatusCode != http.StatusForbidden {
		t.Fatalf("destroying a held artifact status=%d, want a refusal", refused.StatusCode)
	}

	// Lifting the hold and then destroying it both land, which proves the
	// whole custody surface is reachable rather than only its first operation.
	lift := custodyCommand(string(record.ID), "legal-hold-lifted")
	lifted, payload := stack.decide(t, ctx, stack.bearers.custodian, "workspace", string(record.ID), "custody-3", `"`+string(record.ID)+`:v2"`, lift)
	if lifted.StatusCode != http.StatusNoContent {
		t.Fatalf("lift status=%d body=%s", lifted.StatusCode, payload)
	}
	destroyed, payload := stack.decide(t, ctx, stack.bearers.custodian, "workspace", string(record.ID), "custody-4", `"`+string(record.ID)+`:v3"`, deletion)
	if destroyed.StatusCode != http.StatusNoContent {
		t.Fatalf("delete status=%d body=%s", destroyed.StatusCode, payload)
	}
	if _, state, _ := stack.held(t, ctx, string(record.ID)); state != string(artifacts.Deleted) {
		t.Fatalf("state=%q, want the tombstone", state)
	}
}

// Every denial axis, exercised through the production composition rather than
// against the module in isolation. Each request below is well-formed and
// authenticated; what it lacks is authority.
func TestArtifactCustodyDeniesUnauthorizedProductionRequests(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	stack := newCustodyStack(t, ctx)
	record := stack.createArtifact(t, ctx, "artifact.custody.denied")
	id := string(record.ID)
	body := custodyCommand(id, "deleted")

	for _, testCase := range []struct {
		name      string
		token     string
		workspace string
		body      []byte
		status    int
	}{
		// The custody scope is not one an ordinary run actor holds.
		{name: "missing scope", token: stack.bearers.actor, workspace: "workspace", body: body, status: http.StatusForbidden},
		// The operator scope decides escalated effects, not artifact custody.
		{name: "another privileged scope", token: stack.bearers.operator, workspace: "workspace", body: body, status: http.StatusForbidden},
		// The scope is held, but the register admits this subject under an
		// ordinary role: scope never substitutes for role.
		{name: "missing role", token: stack.bearers.pretender, workspace: "workspace", body: body, status: http.StatusForbidden},
		// A workspace the caller proved no authority for is absent, not denied.
		{name: "cross tenant", token: stack.bearers.custodian, workspace: "workspace.other", body: body, status: http.StatusNotFound},
		// Forged identity in the command is structurally rejected.
		{name: "forged custodian", token: stack.bearers.custodian, workspace: "workspace", body: []byte(`{"kind":"DecideArtifactCustodyRequest","artifactId":"` + id + `","decision":"deleted","basis":"` + custodyBasis + `","ticket":"CHG-2291","custodianId":"custodian"}`), status: http.StatusUnprocessableEntity},
		{name: "forged tenant", token: stack.bearers.custodian, workspace: "workspace", body: []byte(`{"kind":"DecideArtifactCustodyRequest","artifactId":"` + id + `","decision":"deleted","basis":"` + custodyBasis + `","ticket":"CHG-2291","workspaceId":"workspace.attacker"}`), status: http.StatusUnprocessableEntity},
		// A decision addressed at one artifact and naming another is refused.
		{name: "addressed elsewhere", token: stack.bearers.custodian, workspace: "workspace", body: custodyCommand("artifact.custody.elsewhere", "deleted"), status: http.StatusUnprocessableEntity},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			response, payload := stack.decide(t, ctx, testCase.token, testCase.workspace, id, "custody-"+testCase.name, record.ETag(), testCase.body)
			if response.StatusCode != testCase.status {
				t.Fatalf("status=%d want=%d body=%s", response.StatusCode, testCase.status, payload)
			}
			if _, state, version := stack.held(t, ctx, id); state == string(artifacts.Deleted) || version != 1 {
				t.Fatalf("a refused request changed the artifact: state=%q version=%d", state, version)
			}
		})
	}

	// The precondition axes: an unpinned decision and a stale one are
	// different answers, and neither changes anything.
	unpinned, _ := stack.decide(t, ctx, stack.bearers.custodian, "workspace", id, "custody-unpinned", "", body)
	if unpinned.StatusCode != http.StatusPreconditionRequired {
		t.Fatalf("unpinned status=%d, want 428", unpinned.StatusCode)
	}
	stale, _ := stack.decide(t, ctx, stack.bearers.custodian, "workspace", id, "custody-stale", `"`+id+`:v9"`, body)
	if stale.StatusCode != http.StatusPreconditionFailed {
		t.Fatalf("stale status=%d, want 412", stale.StatusCode)
	}

	// Revocation takes effect on the next request. The custodian keeps its
	// token, its scope, and its role, and is refused because the register no
	// longer admits it.
	if err := stack.authority.Revoke(ctx, authority.Revocation{WorkspaceID: "workspace", ProjectID: "project", RevocationID: "revocation.custodian", Kind: authority.RevokeActor, Subject: "custodian", Reason: "offboarded"}); err != nil {
		t.Fatal(err)
	}
	revoked, payload := stack.decide(t, ctx, stack.bearers.custodian, "workspace", id, "custody-revoked", record.ETag(), body)
	if revoked.StatusCode != http.StatusForbidden {
		t.Fatalf("revoked status=%d body=%s, want a refusal", revoked.StatusCode, payload)
	}
	if _, state, version := stack.held(t, ctx, id); state == string(artifacts.Deleted) || version != 1 {
		t.Fatalf("a revoked custodian destroyed the artifact: state=%q version=%d", state, version)
	}
	var problemBody struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(payload, &problemBody); err != nil || problemBody.Code == "" {
		t.Fatalf("refusal body is not governed problem details: %v %s", err, payload)
	}
}
