package runs

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/canonical"
	contractguard "github.com/ancyloce/anvilkit-agent-service/internal/contracts"
)

func TestCreateCommandStructurallyOmitsServerAuthority(t *testing.T) {
	forbidden := map[string]bool{"actorId": true, "tenantId": true, "workspaceId": true, "projectId": true, "runId": true, "rootRunId": true, "parentRunId": true, "status": true, "state": true, "version": true, "executionGeneration": true, "policy": true, "budget": true, "createdAt": true, "updatedAt": true, "signingMaterial": true}
	typeOf := reflect.TypeOf(CreateRequest{})
	for index := range typeOf.NumField() {
		field := typeOf.Field(index)
		name := field.Tag.Get("json")
		if forbidden[name] {
			t.Fatalf("server-owned field %s is representable", name)
		}
	}
	valid := []byte(`{"domain":"platform-agent","operation":"artifact-validation","target":{"targetType":"page","targetId":"page-1"}}`)
	for field := range forbidden {
		var object map[string]any
		_ = json.Unmarshal(valid, &object)
		object[field] = "attacker"
		raw, _ := json.Marshal(object)
		if _, err := DecodeCreateRequest(raw); err == nil {
			t.Fatalf("mass-assigned field %s accepted", field)
		}
	}
}

func TestCreateIsDurableBeforeWorkflowAndReplayIsStable(t *testing.T) {
	store := &fakeStore{}
	starter := &checkingStarter{store: store}
	service := NewService(store, starter, fixedID("run-1"), fixedClock{time.Unix(100, 0)})
	raw := []byte(`{"domain":"platform-agent","operation":"artifact-validation","target":{"targetType":"page","targetId":"page-1"}}`)
	digest, _ := canonical.Digest(raw)
	input := CreateInput{Scope: Scope{TenantID: "tenant", WorkspaceID: "workspace", ProjectID: "project", ActorID: "actor"}, Key: "key", ClaimedDigest: digest, Raw: raw, Authority: testAuthority()}
	input.Traceparent = testTraceparent
	first, err := service.Create(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.Create(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if !second.Replayed || string(first.Bytes) != string(second.Bytes) || starter.beforeDurable {
		t.Fatalf("first=%#v second=%#v starter=%#v", first, second, starter)
	}
	guard, err := contractguard.NewGuard("../..")
	if err != nil {
		t.Fatal(err)
	}
	findings := guard.Validate(context.Background(), contractguard.APIIn, "anvilkit://schema/agent-run.v1@1.0.0?digest=sha256:68949242c9b4557a8b5ff965f76de8f2de49c11523a7cc1e64cfd1b4af824233", first.Bytes)
	if len(findings) != 0 {
		t.Fatalf("created representation violates AgentRunV1: %#v raw=%s", findings, first.Bytes)
	}
}

func TestETagIsStrongAndRoundTrips(t *testing.T) {
	snapshot := Snapshot{RunID: "run", Version: 42}
	if snapshot.ETag() != `"run:v42"` {
		t.Fatal(snapshot.ETag())
	}
	version, err := ParseETag(snapshot.ETag(), snapshot.RunID)
	if err != nil || version != 42 {
		t.Fatalf("version=%d err=%v", version, err)
	}
	if _, err := ParseETag(`W/"run:v42"`, snapshot.RunID); err == nil {
		t.Fatal("weak ETag accepted")
	}
}

type fixedID ID

func (id fixedID) NewID() (ID, error) { return ID(id), nil }

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

type fakeStore struct{ created *CreateOutcome }

func (s *fakeStore) Create(_ context.Context, record CreateRecord) (CreateOutcome, error) {
	if s.created != nil {
		replay := *s.created
		replay.Replayed = true
		return replay, nil
	}
	bytes, _ := json.Marshal(record.Snapshot)
	outcome := CreateOutcome{Snapshot: record.Snapshot, Bytes: bytes}
	s.created = &outcome
	return outcome, nil
}
func (*fakeStore) Get(context.Context, Scope, ID) (Snapshot, error)       { return Snapshot{}, nil }
func (*fakeStore) List(context.Context, Scope, ListOptions) (Page, error) { return Page{}, nil }
func (*fakeStore) Transition(context.Context, Scope, ID, uint64, Command) (Snapshot, error) {
	return Snapshot{}, nil
}

type checkingStarter struct {
	store         *fakeStore
	beforeDurable bool
}

func (s *checkingStarter) Ensure(context.Context, Start) error {
	if s.store.created == nil {
		s.beforeDurable = true
	}
	return nil
}
func testAuthority() Authority {
	policy := json.RawMessage(`{"policyId":"policy.synthetic","version":"v1","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`)
	return Authority{
		ContractBOM: json.RawMessage(`{"repository":"anvilkit/contracts","bomDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","ociManifestDigest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","evidenceManifestDigest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}`),
		Policy:      policy,
		Budget:      json.RawMessage(`{"apiVersion":"anvilkit.io/contracts/v1","kind":"AgentBudget","modelLimits":{"maximumCalls":10,"maximumConcurrentCalls":2},"tokenLimits":{"inputTokens":4096,"outputTokens":2048,"totalTokens":6144},"workerLimits":{"maximumAttempts":4,"maximumDurationMilliseconds":60000},"gpuLimits":{"maximumGpuMilliseconds":0},"currencyLimits":{"maximumCost":{"amount":"1000","currency":"USD"},"reservedCost":{"amount":"500","currency":"USD"}},"reservationId":"reservation.synthetic.001","exceedBehavior":"refuse","policy":` + string(policy) + `}`),
	}
}

const testTraceparent = "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"
