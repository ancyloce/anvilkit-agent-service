package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/config"
	contractguard "github.com/ancyloce/anvilkit-agent-service/internal/contracts"
	"github.com/ancyloce/anvilkit-agent-service/internal/events"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/queue"
	"github.com/ancyloce/anvilkit-agent-service/internal/securityaudit"
	"github.com/ancyloce/anvilkit-agent-service/internal/trust"
)

type queuePublisherCapture struct{ message queue.Message }

func (p *queuePublisherCapture) Publish(_ context.Context, message queue.Message) error {
	p.message = message
	return nil
}

func TestEventQueuePublisherPreservesOutboxIdentityAndPayload(t *testing.T) {
	capture := &queuePublisherCapture{}
	publisher := eventQueuePublisher{broker: capture}
	want := events.OutboxMessage{ID: "event-7", WorkspaceID: "workspace", ProjectID: "project", RunID: "run", Sequence: 7, Topic: "agent.public-events", Payload: []byte(`{"eventId":"event-7"}`)}
	if err := publisher.Publish(context.Background(), want); err != nil {
		t.Fatal(err)
	}
	got := capture.message
	if got.ID != want.ID || got.WorkspaceID != want.WorkspaceID || got.ProjectID != want.ProjectID || got.RunID != want.RunID || got.Topic != want.Topic || got.TaskID != "run-event" || string(got.Payload) != string(want.Payload) {
		t.Fatalf("queue message = %#v", got)
	}
}

// The composed clock reads an authenticated time authority, and an outage
// takes the service's time away rather than quietly handing it the host clock.
// The outage also has to be reported as an outage: a caller told its authority
// is stale goes looking for a revocation that never happened.
func TestApplicationClockFailsClosedAfterAuthoritativeTimeOutage(t *testing.T) {
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	const issuer = "urn:anvilkit:issuer:time-authority"
	const keyID = "urn:anvilkit:key:time-authority:verification"
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		payload, marshalErr := json.Marshal(securityaudit.TimeStatement{
			Kind:      securityaudit.TimeStatementKind,
			Algorithm: "dsse-ed25519-v1",
			Issuer:    issuer,
			Audience:  securityaudit.TimeAudience,
			KeyID:     keyID,
			Nonce:     request.Header.Get(securityaudit.NonceHeader),
			UTC:       time.Now().UTC().Format(trust.Timestamp),
		})
		if marshalErr != nil {
			response.WriteHeader(http.StatusInternalServerError)
			return
		}
		envelope, sealErr := trust.Seal(private, keyID, securityaudit.TimeStatementType, payload)
		if sealErr != nil {
			response.WriteHeader(http.StatusInternalServerError)
			return
		}
		raw, marshalErr := json.Marshal(envelope)
		if marshalErr != nil {
			response.WriteHeader(http.StatusInternalServerError)
			return
		}
		response.Header().Set("Content-Type", securityaudit.TimeStatementType)
		_, _ = response.Write(raw)
	}))
	key := trust.Key{KeyID: keyID, Issuer: issuer, Audiences: []string{securityaudit.TimeAudience}, Algorithms: []string{"dsse-ed25519-v1"}, Status: "active", NotBefore: "2020-01-01T00:00:00.000Z", NotAfter: "2099-01-01T00:00:00.000Z"}
	key.PublicKeyJwk.KeyType, key.PublicKeyJwk.Curve = "OKP", "Ed25519"
	key.PublicKeyJwk.X = base64.RawURLEncoding.EncodeToString(public)
	rootBytes, err := json.Marshal(trust.Root{Kind: trust.RootKind, SnapshotID: "snapshot.time.0001", IssuedAt: "2026-01-01T00:00:00.000Z", NextUpdate: "2099-01-01T00:00:00.000Z", MaximumClockSkewSeconds: 60, Keys: []trust.Key{key}})
	if err != nil {
		t.Fatal(err)
	}
	rootPath := filepath.Join(t.TempDir(), "time-trust-root.json")
	if err := os.WriteFile(rootPath, rootBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{
		Environment:                config.EnvironmentProduction,
		AuthoritativeTime:          config.Endpoint{URL: server.URL, TrustRef: issuer},
		AuthoritativeTimeTrustRoot: rootPath,
		MaximumClockSkew:           time.Minute,
	}
	clock, _, err := applicationClock(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if now := clock.Now(); now.IsZero() {
		t.Fatalf("live authoritative endpoint returned zero time: %v", clock.Refusal())
	}
	if clock.Refusal() != nil {
		t.Fatalf("a working clock reports %v", clock.Refusal())
	}
	server.Close()
	if now := clock.Now(); !now.IsZero() {
		t.Fatalf("authority outage fell back to local time: %s", now)
	}
	var details problem.Details
	if !errors.As(clock.Refusal(), &details) || details.Code != string(problem.CodeInfrastructureUnavailable) {
		t.Fatalf("an outage was reported as %v, want a retryable dependency failure", clock.Refusal())
	}
	// A configuration that names a time endpoint with no trust material is
	// refused outright: it would believe whatever answered on that address.
	unauthenticated := cfg
	unauthenticated.AuthoritativeTimeTrustRoot = ""
	if _, _, err := applicationClock(unauthenticated); err == nil {
		t.Fatal("a time authority with no trust material was composed")
	}
}

func TestRunAuthoritySeedIsStrictAndContractValid(t *testing.T) {
	guard, err := contractguard.NewGuard("../..")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "authority.json")
	policy := `{"policyId":"policy.synthetic","version":"v1","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`
	material := `"definition":{"definitionId":"definition.synthetic.001","definitionDigest":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"},"contractBomReference":{"repository":"anvilkit/contracts","bomDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","ociManifestDigest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","evidenceManifestDigest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},"policy":` + policy + `,"budget":{"kind":"AgentBudget","modelLimits":{"maximumCalls":10,"maximumConcurrentCalls":2},"tokenLimits":{"inputTokens":4096,"outputTokens":2048,"totalTokens":6144},"workerLimits":{"maximumAttempts":4,"maximumDurationMilliseconds":60000},"gpuLimits":{"maximumGpuMilliseconds":0},"currencyLimits":{"maximumCost":{"amount":"1000","currency":"USD"},"reservedCost":{"amount":"500","currency":"USD"}},"reservationId":"reservation.synthetic.001","exceedBehavior":"refuse","policy":` + policy + `}`
	change := `"change":{"generation":3,"authorizedBy":"operator.jane","reason":"admit the incident custodian","ticket":"CHG-4711"}`
	raw := `{"scope":{"workspaceId":"workspace","projectId":"project"},` + change + `,"subjects":[{"actorId":"actor","role":"agent-actor"}],` + material + `}`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	seed, err := loadAuthoritySeed(path, guard)
	if err != nil {
		t.Fatal(err)
	}
	if seed.Scope.WorkspaceID != "workspace" || seed.Scope.ProjectID != "project" || len(seed.Subjects) != 1 || seed.Subjects[0].ActorID != "actor" {
		t.Fatalf("seed scope and subjects were not carried: %#v", seed)
	}
	if seed.Change.Generation != 3 || seed.Change.AuthorizedBy != "operator.jane" || seed.Change.Ticket != "CHG-4711" {
		t.Fatalf("the change the document declares was not carried: %#v", seed.Change)
	}
	// A document with no ordinal cannot be told apart from an older one, so
	// it is refused rather than trusted to be the newest thing anyone holds.
	for name, change := range map[string]string{
		"no generation":                  `"change":{"generation":0,"authorizedBy":"operator.jane","reason":"why","ticket":"CHG-1"}`,
		"no authorizing identity":        `"change":{"generation":2,"authorizedBy":"","reason":"why","ticket":"CHG-1"}`,
		"unbounded authorizing identity": `"change":{"generation":2,"authorizedBy":"operator jane","reason":"why","ticket":"CHG-1"}`,
		"no reason":                      `"change":{"generation":2,"authorizedBy":"operator.jane","reason":"","ticket":"CHG-1"}`,
		"no ticket":                      `"change":{"generation":2,"authorizedBy":"operator.jane","reason":"why","ticket":""}`,
	} {
		document := `{"scope":{"workspaceId":"workspace","projectId":"project"},` + change + `,"subjects":[{"actorId":"actor","role":"agent-actor"}],` + material + `}`
		if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadAuthoritySeed(path, guard); err == nil {
			t.Fatalf("an authority document with %s was accepted", name)
		}
	}
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	// A document without its scope binds no authority at all.
	unscoped := `{` + material + `}`
	if err := os.WriteFile(path, []byte(unscoped), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAuthoritySeed(path, guard); err == nil {
		t.Fatal("an unscoped authority document was accepted")
	}
	// An unknown server-authority field is structurally rejected.
	if err := os.WriteFile(path, []byte(raw[:len(raw)-1]+`,"actorId":"attacker"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAuthoritySeed(path, guard); err == nil {
		t.Fatal("unknown server-authority field was accepted")
	}
	// A subject may be granted only the custody capabilities and the
	// registered classifications the service defines. Configuration that could
	// name anything else would be a way to write new authority into the
	// register rather than to grant the authority that exists.
	subject := func(grants string) string {
		return `{"scope":{"workspaceId":"workspace","projectId":"project"},` + change + `,"subjects":[{"actorId":"actor","role":"agent-artifact-custodian"` + grants + `}],` + material + `}`
	}
	for name, grants := range map[string]string{
		"unknown capability":   `,"custodyCapabilities":["artifact-custody.rename"]`,
		"tool capability":      `,"custodyCapabilities":["fake.execute"]`,
		"unregistered class":   `,"dataClasses":["unbounded"]`,
		"empty classification": `,"dataClasses":[""]`,
	} {
		if err := os.WriteFile(path, []byte(subject(grants)), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadAuthoritySeed(path, guard); err == nil {
			t.Fatalf("a subject granted an %s was accepted", name)
		}
	}
	granted := subject(`,"custodyCapabilities":["artifact-custody.delete"],"dataClasses":["internal"]`)
	if err := os.WriteFile(path, []byte(granted), 0o600); err != nil {
		t.Fatal(err)
	}
	seed, err = loadAuthoritySeed(path, guard)
	if err != nil {
		t.Fatalf("a governed custody grant was refused: %v", err)
	}
	if len(seed.Subjects) != 1 || len(seed.Subjects[0].CustodyCapabilities) != 1 || len(seed.Subjects[0].DataClasses) != 1 {
		t.Fatalf("the subject's own grants were not carried: %#v", seed.Subjects)
	}
}

func TestOpenPersistencePoolsRoutesAuthorityThroughControlConfiguration(t *testing.T) {
	cfg := config.Config{
		ControlDatabase:    "postgres://control_owner@platform-db.example.invalid:5432/anvilkit",
		ControlPoolSize:    7,
		EventsDatabase:     "postgres://events_owner@platform-db.example.invalid:5432/anvilkit",
		EventsPoolSize:     3,
		WorkflowPoolSize:   1,
		ArtifactsPoolSize:  1,
		EvaluationPoolSize: 1,
	}
	pools, err := openPersistencePools(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pools.Close()
	if pools.Authority == nil || pools.Control == nil || pools.Events == nil {
		t.Fatalf("expected control, authority, and events pools: %#v", pools)
	}
	if actual := pools.Authority.Config().ConnConfig.User; actual != "control_owner" {
		t.Fatalf("authority pool uses %q credentials, want control configuration", actual)
	}
	if actual := pools.Authority.Config().ConnConfig.RuntimeParams["role"]; actual != "agent_authority_rw" {
		t.Fatalf("authority pool role = %q", actual)
	}
	if actual := pools.Authority.Stat().MaxConns(); actual != 7 {
		t.Fatalf("authority pool maximum = %d, want control maximum", actual)
	}
}

func TestOpenPersistencePoolsRejectsSplitPlatformDatabases(t *testing.T) {
	cfg := config.Config{
		ControlDatabase:    "postgres://owner@platform-db.example.invalid:5432/anvilkit_control",
		ControlPoolSize:    1,
		EventsDatabase:     "postgres://owner@platform-db.example.invalid:5432/anvilkit_events",
		EventsPoolSize:     1,
		WorkflowPoolSize:   1,
		ArtifactsPoolSize:  1,
		EvaluationPoolSize: 1,
	}
	_, err := openPersistencePools(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "same Platform Postgres database") {
		t.Fatalf("split database topology was accepted: %v", err)
	}
}
