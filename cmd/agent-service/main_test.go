package main

import (
	"context"
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
	"github.com/ancyloce/anvilkit-agent-service/internal/queue"
	"github.com/ancyloce/anvilkit-agent-service/internal/runs"
)

type queuePublisherCapture struct{ message queue.Message }

func (p *queuePublisherCapture) Publish(_ context.Context, message queue.Message) error {
	p.message = message
	return nil
}

func TestEventQueuePublisherPreservesOutboxIdentityAndPayload(t *testing.T) {
	capture := &queuePublisherCapture{}
	publisher := eventQueuePublisher{broker: capture}
	want := events.OutboxMessage{ID: "event-7", WorkspaceID: "workspace", ProjectID: "project", RunID: "run", Sequence: 7, Topic: "agent.events.v1", Payload: []byte(`{"eventId":"event-7"}`)}
	if err := publisher.Publish(context.Background(), want); err != nil {
		t.Fatal(err)
	}
	got := capture.message
	if got.ID != want.ID || got.WorkspaceID != want.WorkspaceID || got.ProjectID != want.ProjectID || got.RunID != want.RunID || got.Topic != want.Topic || got.TaskID != "run-event" || string(got.Payload) != string(want.Payload) {
		t.Fatalf("queue message = %#v", got)
	}
}

func TestApplicationClockFailsClosedAfterAuthoritativeTimeOutage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Date", time.Now().UTC().Format(http.TimeFormat))
		response.WriteHeader(http.StatusNoContent)
	}))
	cfg := config.Config{Environment: config.EnvironmentProduction, AuthoritativeTime: config.Endpoint{URL: server.URL}, MaximumClockSkew: time.Minute}
	clock, err := applicationClock(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if now := clock.Now(); now.IsZero() {
		t.Fatal("live authoritative endpoint returned zero time")
	}
	server.Close()
	if now := clock.Now(); !now.IsZero() {
		t.Fatalf("authority outage fell back to local time: %s", now)
	}
}

func TestRunAuthorityFileIsStrictAndContractValid(t *testing.T) {
	guard, err := contractguard.NewGuard("../..")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "authority.json")
	policy := `{"policyId":"policy.synthetic","version":"v1","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`
	raw := `{"contractBomReference":{"repository":"anvilkit/contracts","bomDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","ociManifestDigest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","evidenceManifestDigest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},"policy":` + policy + `,"budget":{"apiVersion":"anvilkit.io/contracts/v1","kind":"AgentBudget","modelLimits":{"maximumCalls":10,"maximumConcurrentCalls":2},"tokenLimits":{"inputTokens":4096,"outputTokens":2048,"totalTokens":6144},"workerLimits":{"maximumAttempts":4,"maximumDurationMilliseconds":60000},"gpuLimits":{"maximumGpuMilliseconds":0},"currencyLimits":{"maximumCost":{"amount":"1000","currency":"USD"},"reservedCost":{"amount":"500","currency":"USD"}},"reservationId":"reservation.synthetic.001","exceedBehavior":"refuse","policy":` + policy + `}}`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadRunAuthority(path, guard); err != nil {
		t.Fatal(err)
	}
	provider, err := newFileRunAuthority(path, guard)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := provider.Current(context.Background(), runs.Scope{})
	if err != nil {
		t.Fatal(err)
	}
	rotatedRaw := strings.ReplaceAll(raw, "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")
	if err := os.WriteFile(path, []byte(rotatedRaw), 0o600); err != nil {
		t.Fatal(err)
	}
	rotated, err := provider.Current(context.Background(), runs.Scope{})
	if err != nil || string(rotated.Policy) == string(initial.Policy) {
		t.Fatalf("authority provider did not reload rotated policy: %v", err)
	}
	if err := os.WriteFile(path, []byte(raw[:len(raw)-1]+`,"actorId":"attacker"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadRunAuthority(path, guard); err == nil {
		t.Fatal("unknown server-authority field was accepted")
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
