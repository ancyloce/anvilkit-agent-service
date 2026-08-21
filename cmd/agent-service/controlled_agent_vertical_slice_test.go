package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ancyloce/anvilkit-agent-service/internal/api"
	"github.com/ancyloce/anvilkit-agent-service/internal/canonical"
	"github.com/ancyloce/anvilkit-agent-service/internal/config"
	contractguard "github.com/ancyloce/anvilkit-agent-service/internal/contracts"
	"github.com/ancyloce/anvilkit-agent-service/internal/journal"
	"github.com/ancyloce/anvilkit-agent-service/internal/persistence"
	"github.com/ancyloce/anvilkit-agent-service/internal/telemetry"
	workflowdbos "github.com/ancyloce/anvilkit-agent-service/internal/workflow/dbos"
)

// TestControlledAgentVerticalSlice drives the complete governed flow through the
// production composition: HTTP create → durable preparation → planning → a
// durable input wait answered over HTTP → a fenced tool execution → contract
// validation → an immutable artifact → review → a durable approval answered
// over HTTP → real signed apply-authorization issuance → the simulated domain
// outcome → completion. Everything below the HTTP handler is the same code
// path main() composes; nothing is faked beyond the explicitly selected
// controlled implementations, and no state is fixed up by hand.
func TestControlledAgentVerticalSlice(t *testing.T) {
	base := os.Getenv("POSTGRES_TEST_URL")
	if base == "" {
		t.Skip("POSTGRES_TEST_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

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

	// The declared definition is the approved catalog manager; the run
	// authority file pins the same reference, so creation, execution, and
	// issuance all govern one identity.
	managerID, managerDigest := managerReference(t)
	authorityPath := writeRunAuthority(t, managerID, managerDigest)
	trustPath, bearer, reviewerBearer := mintVerifiedBearer(t)

	environment := map[string]string{
		"ANVILKIT_ENVIRONMENT":                     "development",
		"ANVILKIT_CONTRACT_ROOT":                   "../..",
		"ANVILKIT_CONTROL_DATABASE_URL":            databaseURL,
		"ANVILKIT_WORKFLOW_DATABASE_URL":           databaseURL,
		"ANVILKIT_EVENTS_DATABASE_URL":             databaseURL,
		"ANVILKIT_ARTIFACTS_DATABASE_URL":          databaseURL,
		"ANVILKIT_EVALUATION_DATABASE_URL":         databaseURL,
		"ANVILKIT_MODEL_IMPLEMENTATION":            "controlled-fake",
		"ANVILKIT_TOOL_IMPLEMENTATION":             "controlled-fake",
		"ANVILKIT_DOMAIN_IMPLEMENTATION":           "controlled-fake",
		"ANVILKIT_CONTRACT_RUNTIME_IMPLEMENTATION": "controlled-fake",
		"ANVILKIT_WORKER_IMPLEMENTATION":           "controlled-fake",
		"ANVILKIT_CONTROLLED_MODEL_SCRIPT":         "need-input,tool-echo,final",
		"ANVILKIT_SIGNING_KEY":                     "slice-signing-material-0123456789",
		"ANVILKIT_ENCRYPTION_KEY":                  "slice-encryption-material-0123456789",
		"ANVILKIT_RUN_AUTHORITY_FILE":              authorityPath,
		"ANVILKIT_AUTH_TRUST_SNAPSHOT":             trustPath,
		"ANVILKIT_AUTH_ISSUERS":                    "issuer",
		"ANVILKIT_EXECUTOR_ID":                     "slice-executor-1",
	}
	for name, value := range environment {
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
	defer pools.Close()
	guard, err := contractguard.NewGuard(cfg.ContractRoot)
	if err != nil {
		t.Fatal(err)
	}
	clock, err := applicationClock(cfg)
	if err != nil {
		t.Fatal(err)
	}
	handle := &runtimeHandle{}
	core, err := buildRuntimeCore(ctx, cfg, pools, guard, journal.NewMemoryStore(), clock, handle)
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := workflowdbos.New(ctx, workflowdbos.Config{DatabaseURL: cfg.WorkflowDatabase, Schema: "agent_dbos", ExecutorID: cfg.ExecutorID, ApplicationVersion: "slice-test", Logger: slog.Default()}, core.executor)
	if err != nil {
		t.Fatal(err)
	}
	handle.set(runtime)
	if err := runtime.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := runtime.Stop(context.Background()); err != nil {
			t.Errorf("stop workflow runtime: %v", err)
		}
	}()
	redactor := telemetry.NewRedactor([]string{cfg.SigningKey.RedactionValue(), cfg.EncryptionKey.RedactionValue()})
	observability, err := telemetry.New(cfg.ServiceName, nil, redactor)
	if err != nil {
		t.Fatal(err)
	}
	options, err := agentAPIOptions(ctx, cfg, pools, runtime, core, observability)
	if err != nil {
		t.Fatal(err)
	}
	handler := api.New(readyAlways{}, options...)
	server := httptest.NewServer(handler)
	defer server.Close()

	observe, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer observe.Close()

	trace := "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"
	client := &http.Client{Timeout: 30 * time.Second}
	callAs := func(token, method, path, key, etag string, body []byte) (*http.Response, []byte) {
		t.Helper()
		request, err := http.NewRequestWithContext(ctx, method, server.URL+path, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer "+token)
		request.Header.Set("traceparent", trace)
		if key != "" {
			request.Header.Set("Idempotency-Key", key)
		}
		if etag != "" {
			request.Header.Set("If-Match", etag)
		}
		if body != nil {
			digest, err := canonical.Digest(body)
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("X-AnvilKit-Request-Digest", digest)
		}
		response, err := client.Do(request)
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
	call := func(method, path, key, etag string, body []byte) (*http.Response, []byte) {
		t.Helper()
		return callAs(bearer, method, path, key, etag, body)
	}

	createBody := []byte(`{"kind":"CreateAgentRunRequest","definition":{"definitionId":"` + managerID + `","definitionDigest":"` + managerDigest + `"},"operation":"page-change","target":{"targetType":"page","targetId":"page-slice-001","workspaceId":"workspace","projectId":"project"},"input":{"userInput":"Make the hero section bolder."}}`)
	created, createdPayload := call(http.MethodPost, "/v1/workspaces/workspace/agent-runs", "slice-create-1", "", createBody)
	if created.StatusCode != http.StatusCreated || created.Header.Get("Location") == "" || created.Header.Get("ETag") == "" {
		t.Fatalf("create status=%d location=%q etag=%q body=%s", created.StatusCode, created.Header.Get("Location"), created.Header.Get("ETag"), createdPayload)
	}
	var createdRun struct {
		RunID  string `json:"runId"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal(createdPayload, &createdRun); err != nil || createdRun.RunID == "" {
		t.Fatalf("created run body undecodable: %v %s", err, createdPayload)
	}
	runID := createdRun.RunID
	runPath := "/v1/workspaces/workspace/agent-runs/" + runID

	replayed, _ := call(http.MethodPost, "/v1/workspaces/workspace/agent-runs", "slice-create-1", "", createBody)
	if replayed.StatusCode != http.StatusOK || replayed.Header.Get("Idempotency-Replayed") != "true" {
		t.Fatalf("idempotent replay status=%d replayed=%q", replayed.StatusCode, replayed.Header.Get("Idempotency-Replayed"))
	}

	// latestEventPayload reads the governed public stream over HTTP/SSE and
	// returns the payload of the newest event of the given type. Interrupt
	// discovery uses only this public surface: the request identity and the
	// required version come from the run.input-requested and
	// run.approval-requested payloads, never from internal tables.
	latestEventPayload := func(runPath, eventType string) (map[string]string, bool) {
		t.Helper()
		streamCtx, cancelStream := context.WithTimeout(ctx, 3*time.Second)
		defer cancelStream()
		request, err := http.NewRequestWithContext(streamCtx, http.MethodGet, server.URL+runPath+"/events", nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer "+bearer)
		request.Header.Set("traceparent", trace)
		request.Header.Set("Accept", "text/event-stream")
		response, err := http.DefaultTransport.RoundTrip(request)
		if err != nil {
			return nil, false
		}
		defer func() { _ = response.Body.Close() }()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("stream status=%d", response.StatusCode)
		}
		scanner := bufio.NewScanner(response.Body)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		var payload map[string]string
		var found bool
		var data []byte
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "data: ") {
				data = []byte(strings.TrimPrefix(line, "data: "))
				continue
			}
			if line != "" {
				continue
			}
			if len(data) == 0 {
				continue
			}
			var event struct {
				EventType string            `json:"eventType"`
				Payload   map[string]string `json:"payload"`
			}
			if err := json.Unmarshal(data, &event); err == nil && event.EventType == eventType {
				payload, found = event.Payload, true
			}
			data = nil
		}
		return payload, found
	}
	waitForEventPayload := func(runPath, eventType string) map[string]string {
		t.Helper()
		deadline := time.Now().Add(90 * time.Second)
		for time.Now().Before(deadline) {
			if payload, found := latestEventPayload(runPath, eventType); found {
				return payload
			}
			time.Sleep(250 * time.Millisecond)
		}
		t.Fatalf("the public stream never carried %s", eventType)
		return nil
	}

	currentRun := func() (string, string, []byte) {
		t.Helper()
		response, payload := call(http.MethodGet, runPath, "", "", nil)
		if response.StatusCode != http.StatusOK {
			t.Fatalf("get run status=%d body=%s", response.StatusCode, payload)
		}
		var run struct {
			Status string `json:"status"`
		}
		if err := json.Unmarshal(payload, &run); err != nil {
			t.Fatal(err)
		}
		return run.Status, response.Header.Get("ETag"), payload
	}
	waitForStatus := func(want string) string {
		t.Helper()
		deadline := time.Now().Add(90 * time.Second)
		for {
			status, etag, payload := currentRun()
			if status == want {
				return etag
			}
			switch status {
			case "failed", "refused", "cancelled", "discarded", "conflict":
				t.Fatalf("run settled in %q while waiting for %q: %s", status, want, payload)
			}
			if time.Now().After(deadline) {
				t.Fatalf("run is %q; %q was not reached in time: %s", status, want, payload)
			}
			time.Sleep(500 * time.Millisecond)
		}
	}

	// Input leg: the controlled script requests input; the durable wait is
	// answered over HTTP with the canonical control command. The request
	// identity and the required request version are discovered from the
	// public run.input-requested event alone. A missing If-Match precondition
	// answers 428 without any effect.
	etag := waitForStatus("awaiting_input")
	inputEvent := waitForEventPayload(runPath, "run.input-requested")
	inputRequestID := inputEvent["requestId"]
	inputVersion, err := strconv.ParseUint(inputEvent["requestVersion"], 10, 64)
	if err != nil || inputRequestID == "" {
		t.Fatalf("run.input-requested payload does not disclose identity and version: %#v", inputEvent)
	}
	inputBody := []byte(fmt.Sprintf(`{"kind":"SubmitInputResponseRequest","requestVersion":%d,"responsePayload":{"answer":"the hero section"}}`, inputVersion))
	missingPrecondition, _ := call(http.MethodPost, runPath+"/inputs/"+inputRequestID+"/responses", "slice-input-1", "", inputBody)
	if missingPrecondition.StatusCode != http.StatusPreconditionRequired {
		t.Fatalf("missing If-Match answered %d, want 428", missingPrecondition.StatusCode)
	}
	// The canonical SubmitInputResponseRequest contract is enforced at the
	// boundary, so the shape the contract describes is the only shape the
	// deployed API accepts: the pre-canonical body is refused, and so is one
	// missing the discriminator.
	for name, rejected := range map[string][]byte{
		"pre-canonical-value-field": []byte(fmt.Sprintf(`{"requestVersion":%d,"value":{"answer":"the hero section"}}`, inputVersion)),
		"missing-kind":              []byte(fmt.Sprintf(`{"requestVersion":%d,"responsePayload":{"answer":"the hero section"}}`, inputVersion)),
		"non-string-payload":        []byte(fmt.Sprintf(`{"kind":"SubmitInputResponseRequest","requestVersion":%d,"responsePayload":{"answer":{"nested":true}}}`, inputVersion)),
	} {
		response, payload := call(http.MethodPost, runPath+"/inputs/"+inputRequestID+"/responses", "slice-input-reject-"+name, etag, rejected)
		if response.StatusCode != http.StatusUnprocessableEntity {
			t.Fatalf("%s input body status=%d body=%s, want the canonical contract to reject it", name, response.StatusCode, payload)
		}
	}
	answered, answeredPayload := call(http.MethodPost, runPath+"/inputs/"+inputRequestID+"/responses", "slice-input-1", etag, inputBody)
	if answered.StatusCode != http.StatusOK {
		t.Fatalf("input response status=%d body=%s", answered.StatusCode, answeredPayload)
	}

	// Approval leg: the tool executes through the fenced dispatch, the
	// candidate validates through the Contract Runtime, becomes an immutable
	// artifact, and review opens a durable approval. The request identity and
	// the required decision version are discovered from the public
	// run.approval-requested event alone.
	etag = waitForStatus("awaiting_approval")
	approvalEvent := waitForEventPayload(runPath, "run.approval-requested")
	approvalRequestID := approvalEvent["requestId"]
	approvalVersion, err := strconv.ParseUint(approvalEvent["decisionVersion"], 10, 64)
	if err != nil || approvalRequestID == "" || approvalEvent["actionDigest"] == "" {
		t.Fatalf("run.approval-requested payload does not disclose identity, version, and action binding: %#v", approvalEvent)
	}
	// The reviewer binds the exact action they decided; the digest comes from
	// the same public event that disclosed the request identity.
	decisionBody := []byte(fmt.Sprintf(`{"kind":"SubmitApprovalDecisionRequest","decision":"approve","decisionVersion":%d,"actionDigest":%q}`, approvalVersion, approvalEvent["actionDigest"]))
	// The canonical SubmitApprovalDecisionRequest contract is enforced the same
	// way: the pre-canonical body, a decision without its action binding, and
	// a decision spelling the third outcome with the retired vocabulary are all
	// refused. A well-formed decision naming a different action is refused by
	// the service instead, because the binding is a state check, not a shape.
	for name, rejected := range map[string][]byte{
		"pre-canonical-no-kind":  []byte(fmt.Sprintf(`{"decisionVersion":%d,"decision":"approve"}`, approvalVersion)),
		"missing-action-digest":  []byte(fmt.Sprintf(`{"kind":"SubmitApprovalDecisionRequest","decision":"approve","decisionVersion":%d}`, approvalVersion)),
		"retired-decision-value": []byte(fmt.Sprintf(`{"kind":"SubmitApprovalDecisionRequest","decision":"change","decisionVersion":%d,"actionDigest":%q}`, approvalVersion, approvalEvent["actionDigest"])),
		"pre-canonical-reason":   []byte(fmt.Sprintf(`{"kind":"SubmitApprovalDecisionRequest","decision":"approve","decisionVersion":%d,"actionDigest":%q,"reason":"looks good"}`, approvalVersion, approvalEvent["actionDigest"])),
	} {
		response, payload := callAs(reviewerBearer, http.MethodPost, runPath+"/approvals/"+approvalRequestID+"/decisions", "slice-approve-reject-"+name, etag, rejected)
		if response.StatusCode != http.StatusUnprocessableEntity {
			t.Fatalf("%s decision body status=%d body=%s, want the canonical contract to reject it", name, response.StatusCode, payload)
		}
	}
	otherAction := []byte(fmt.Sprintf(`{"kind":"SubmitApprovalDecisionRequest","decision":"approve","decisionVersion":%d,"actionDigest":"sha256:%s"}`, approvalVersion, strings.Repeat("b", 64)))
	if response, payload := callAs(reviewerBearer, http.MethodPost, runPath+"/approvals/"+approvalRequestID+"/decisions", "slice-approve-other-action", etag, otherAction); response.StatusCode != http.StatusConflict {
		t.Fatalf("decision on another action status=%d body=%s, want the action binding to refuse it", response.StatusCode, payload)
	}
	decided, decidedPayload := callAs(reviewerBearer, http.MethodPost, runPath+"/approvals/"+approvalRequestID+"/decisions", "slice-approve-1", etag, decisionBody)
	if decided.StatusCode != http.StatusOK {
		t.Fatalf("approval decision status=%d body=%s", decided.StatusCode, decidedPayload)
	}

	waitForStatus("completed")

	// The governed effect left the full durable trail: exactly one signed
	// audited authorization pinned to its durable operation, a committed
	// immutable artifact, a decided domain submission with its redemption,
	// recorded validation evidence, a durably accepted worker result with its
	// replayable output, and an all-attempt usage observation from the fenced
	// tool execution. Every database read below is post-hoc evidence
	// verification only — the public workflow above was driven exclusively
	// through HTTP and SSE.
	counts := map[string]string{
		"evidence records":    `SELECT count(*) FROM agent_evidence.records WHERE workspace_id='workspace' AND project_id='project' AND run_id=$1`,
		"authorizations":      `SELECT count(*) FROM agent_control.apply_authorizations WHERE workspace_id='workspace' AND project_id='project' AND run_id=$1`,
		"issuances":           `SELECT count(*) FROM agent_control.commit_issuances WHERE workspace_id='workspace' AND project_id='project' AND run_id=$1 AND authorization_jws<>''`,
		"domain submissions":  `SELECT count(*) FROM agent_control.domain_operations WHERE workspace_id='workspace' AND project_id='project' AND run_id=$1 AND status='applied' AND authorization_consumed`,
		"domain redemptions":  `SELECT count(*) FROM agent_control.domain_redemptions WHERE workspace_id='workspace' AND project_id='project' AND run_id=$1 AND outcome='confirmed'`,
		"committed artifacts": `SELECT count(*) FROM agent_artifacts.metadata WHERE workspace_id='workspace' AND project_id='project' AND run_id=$1 AND state='committed'`,
		"validation evidence": `SELECT count(*) FROM agent_evaluation.validation_evidence WHERE workspace_id='workspace' AND project_id='project' AND run_id=$1`,
		"worker outputs":      `SELECT count(*) FROM agent_workflow.worker_outputs o JOIN agent_workflow.agent_tasks t ON t.workspace_id=o.workspace_id AND t.project_id=o.project_id AND t.task_id=o.task_id WHERE o.workspace_id='workspace' AND o.project_id='project' AND t.run_id=$1`,
		"usage observations":  `SELECT count(*) FROM agent_control.usage_observations WHERE workspace_id='workspace' AND project_id='project' AND run_id=$1`,
	}
	// The public stream carries the complete lifecycle through exactly the
	// six-event registry: five types appear on the happy path, and nothing
	// outside the registry is ever observable.
	eventRows, err := observe.Query(ctx, `SELECT event_bytes FROM agent_events.agent_events WHERE workspace_id='workspace' AND project_id='project' AND run_id=$1 ORDER BY sequence`, runID)
	if err != nil {
		t.Fatal(err)
	}
	observedTypes := map[string]bool{}
	for eventRows.Next() {
		var raw []byte
		if err := eventRows.Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var event struct {
			EventType string `json:"eventType"`
		}
		if err := json.Unmarshal(raw, &event); err != nil {
			t.Fatal(err)
		}
		observedTypes[event.EventType] = true
	}
	eventRows.Close()
	registry := map[string]bool{"run.created": true, "run.state-changed": true, "run.input-requested": true, "run.approval-requested": true, "run.artifact-available": true, "run.problem-recorded": true}
	for observed := range observedTypes {
		if !registry[observed] {
			t.Fatalf("event type %q escaped the six-event public registry", observed)
		}
	}
	for _, want := range []string{"run.created", "run.state-changed", "run.input-requested", "run.approval-requested", "run.artifact-available"} {
		if !observedTypes[want] {
			t.Fatalf("the public stream never carried %q", want)
		}
	}

	for name, query := range counts {
		var count int
		if err := observe.QueryRow(ctx, query, runID).Scan(&count); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if count < 1 {
			t.Fatalf("%s: count=%d, want at least 1", name, count)
		}
		if (name == "authorizations" || name == "issuances" || name == "committed artifacts" || name == "domain submissions" || name == "domain redemptions") && count != 1 {
			t.Fatalf("%s: count=%d, want exactly 1", name, count)
		}
	}
}

type readyAlways struct{}

func (readyAlways) ServeHTTP(response http.ResponseWriter, _ *http.Request) {
	response.WriteHeader(http.StatusOK)
}

// clusterRoleLockKey mirrors the persistence suite's advisory lock: while an
// isolated database exists, its migrations reference the cluster-global
// service roles, so the shared lock keeps the role-dropping rollback in the
// persistence package from racing it.
const clusterRoleLockKey = 0x5750334b

func isolatedSliceDatabase(t *testing.T, ctx context.Context, base string) string {
	t.Helper()
	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `SELECT pg_advisory_lock_shared($1)`, clusterRoleLockKey); err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("agent_slice_%d", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, _ = admin.Exec(cleanupCtx, "DROP DATABASE "+name+" WITH (FORCE)")
		_ = admin.Close(cleanupCtx)
	})
	parsed, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	parsed.Path = "/" + name
	return parsed.String()
}

func managerReference(t *testing.T) (string, string) {
	t.Helper()
	raw, err := os.ReadFile("../../internal/agent/definitions/definition.platform.manager.json")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		DefinitionID     string `json:"definitionId"`
		DefinitionDigest string `json:"definitionDigest"`
	}
	if err := json.Unmarshal(raw, &document); err != nil || document.DefinitionID == "" || document.DefinitionDigest == "" {
		t.Fatalf("manager definition undecodable: %v", err)
	}
	return document.DefinitionID, document.DefinitionDigest
}

func writeRunAuthority(t *testing.T, definitionID, definitionDigest string) string {
	t.Helper()
	// The run policy is the manager definition's own pinned guardrail
	// policy: the reviewer authorization proves request, run, and current
	// policy are one identity.
	policy := `{"policyId":"policy.guardrail.baseline","version":"v1","digest":"sha256:80ca0c4751b2df4cbe5b68642ea75b183c212b8fa002823df174c5ddb7e32a80"}`
	// The operator subject is admitted with the operator role: operator
	// recovery of an escalated governed effect is role-gated against this
	// register, not against anything the request presents.
	raw := `{"scope":{"workspaceId":"workspace","projectId":"project"},"subjects":[{"actorId":"actor","role":"agent-actor"},{"actorId":"reviewer","role":"agent-reviewer"},{"actorId":"operator","role":"agent-operator"},{"actorId":"impostor","role":"agent-actor"}],"definition":{"definitionId":"` + definitionID + `","definitionDigest":"` + definitionDigest + `"},"contractBomReference":{"repository":"anvilkit/contracts","bomDigest":"sha256:` + strings.Repeat("a", 64) + `","ociManifestDigest":"sha256:` + strings.Repeat("b", 64) + `","evidenceManifestDigest":"sha256:` + strings.Repeat("c", 64) + `"},"policy":` + policy + `,"budget":{"kind":"AgentBudget","modelLimits":{"maximumCalls":10,"maximumConcurrentCalls":2},"tokenLimits":{"inputTokens":4096,"outputTokens":2048,"totalTokens":6144},"workerLimits":{"maximumAttempts":4,"maximumDurationMilliseconds":60000},"gpuLimits":{"maximumGpuMilliseconds":0},"currencyLimits":{"maximumCost":{"amount":"1000","currency":"USD"},"reservedCost":{"amount":"500","currency":"USD"}},"reservationId":"reservation.synthetic.001","exceedBehavior":"refuse","policy":` + policy + `}}`
	path := filepath.Join(t.TempDir(), "authority.json")
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// bearers are the verified request authorities the integration tests call
// with. Each identity holds only the scopes its role needs.
type bearers struct {
	trustPath string
	actor     string
	reviewer  string
	operator  string
	// impostor is admitted to the workspace and holds the operator scope, but
	// is not admitted under the operator role: it proves scope alone never
	// authorizes operator recovery.
	impostor string
}

func mintVerifiedBearer(t *testing.T) (string, string, string) {
	minted := mintBearers(t)
	return minted.trustPath, minted.actor, minted.reviewer
}

func mintBearers(t *testing.T) bearers {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trust := fmt.Sprintf(`{"keys":{"slice-key":{"publicKey":%q,"status":"active"}},"subjects":{"actor":"active","reviewer":"active","operator":"active","impostor":"active"},"delegations":{}}`, base64.RawURLEncoding.EncodeToString(public))
	path := filepath.Join(t.TempDir(), "trust.json")
	if err := os.WriteFile(path, []byte(trust), 0o600); err != nil {
		t.Fatal(err)
	}
	mint := func(subject string, scopes []string) string {
		t.Helper()
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","kid":"slice-key","typ":"JWT"}`))
		now := time.Now()
		claims := struct {
			Issuer      string   `json:"iss"`
			Audience    string   `json:"aud"`
			Subject     string   `json:"sub"`
			ActorID     string   `json:"actorId"`
			WorkspaceID string   `json:"workspaceId"`
			ProjectID   string   `json:"projectId"`
			Purpose     string   `json:"purpose"`
			Source      string   `json:"source"`
			Scopes      []string `json:"scopes"`
			ExpiresAt   int64    `json:"exp"`
			NotBefore   int64    `json:"nbf"`
		}{"issuer", "urn:anvilkit:audience:agent-service", subject, subject, "workspace", "project", "agent", "workload", scopes, now.Add(time.Hour).Unix(), now.Add(-time.Minute).Unix()}
		payloadRaw, err := json.Marshal(claims)
		if err != nil {
			t.Fatal(err)
		}
		payload := base64.RawURLEncoding.EncodeToString(payloadRaw)
		signature := ed25519.Sign(private, []byte(header+"."+payload))
		return header + "." + payload + "." + base64.RawURLEncoding.EncodeToString(signature)
	}
	// The reviewer is a distinct identity: the run actor cannot review its
	// own approval request. The operator is distinct again, and holds only
	// the read and operate scopes.
	return bearers{
		trustPath: path,
		actor:     mint("actor", []string{"agent:read", "agent:write"}),
		reviewer:  mint("reviewer", []string{"agent:read", "agent:review"}),
		operator:  mint("operator", []string{"agent:read", "agent:operate"}),
		impostor:  mint("impostor", []string{"agent:read", "agent:operate"}),
	}
}
