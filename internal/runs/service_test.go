package runs

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/canonical"
	contractguard "github.com/ancyloce/anvilkit-agent-service/internal/contracts"
	"github.com/ancyloce/anvilkit-agent-service/internal/journal"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
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
	for _, raw := range [][]byte{
		[]byte(`{"domain":"platform-agent","operation":"artifact-validation","target":{"targetType":"Page","targetId":"page-1"}}`),
		[]byte(`{"domain":"platform-agent","operation":"artifact-validation","target":{"targetType":"page","targetId":"not allowed"}}`),
		[]byte(`{"domain":"platform-agent","operation":"artifact-validation","target":{"targetType":"page","targetId":"` + strings.Repeat("a", 129) + `"}}`),
		[]byte(`{"domain":"platform-agent","domain":"pagix-page","operation":"artifact-validation","target":{"targetType":"page","targetId":"page-1"}}`),
	} {
		if _, err := DecodeCreateRequest(raw); err == nil {
			t.Fatalf("unbounded target accepted: %s", raw)
		}
	}
}

func TestCreateIsDurableBeforeWorkflowAndReplayIsStable(t *testing.T) {
	store := &fakeStore{}
	starter := &checkingStarter{store: store}
	service := NewService(store, starter, fixedID("run-1"), fixedClock{time.Unix(100, 0)}, journal.NewMemoryStore(), admitAll())
	raw := []byte(`{"domain":"platform-agent","operation":"artifact-validation","target":{"targetType":"page","targetId":"page-1"}}`)
	digest, _ := canonical.Digest(raw)
	input := CreateInput{Scope: Scope{WorkspaceID: "workspace", ProjectID: "project", ActorID: "actor"}, Key: "key", ClaimedDigest: digest, Raw: raw, Authority: testAuthority()}
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
	findings := guard.Validate(context.Background(), contractguard.APIIn, "anvilkit://schema/agent-run?digest=sha256:e293860d680a93c9fa5d8c3907201ac3a6a54b7a81cbb81fd5bcb6f332497564", first.Bytes)
	if len(findings) != 0 {
		t.Fatalf("created representation violates AgentRun: %#v raw=%s", findings, first.Bytes)
	}
}

func TestConversationalAndHeadlessCreateHaveInteractionParity(t *testing.T) {
	raw := []byte(`{"domain":"platform-agent","operation":"artifact-validation","target":{"targetType":"page","targetId":"page-1"}}`)
	digest, _ := canonical.Digest(raw)
	create := func(runID, key string) CreateOutcome {
		store := &fakeStore{}
		service := NewService(store, &checkingStarter{store: store}, fixedID(runID), fixedClock{time.Unix(100, 0)}, journal.NewMemoryStore(), admitAll())
		outcome, err := service.Create(context.Background(), CreateInput{Scope: Scope{WorkspaceID: "workspace", ProjectID: "project", ActorID: "actor"}, Key: key, ClaimedDigest: digest, Traceparent: testTraceparent, Raw: raw, Authority: testAuthority()})
		if err != nil {
			t.Fatal(err)
		}
		return outcome
	}
	conversational := create("run-conversational", "conversation-command")
	headless := create("run-headless", "headless-command")
	if conversational.Snapshot.Domain != headless.Snapshot.Domain || conversational.Snapshot.Operation != headless.Snapshot.Operation || conversational.Snapshot.Target != headless.Snapshot.Target || conversational.Snapshot.Status != headless.Snapshot.Status || conversational.Snapshot.ExecutionGeneration != headless.Snapshot.ExecutionGeneration || string(conversational.Snapshot.ContractBOM) != string(headless.Snapshot.ContractBOM) || string(conversational.Snapshot.Policy) != string(headless.Snapshot.Policy) || string(conversational.Snapshot.Budget) != string(headless.Snapshot.Budget) {
		t.Fatalf("interaction style changed governance: conversational=%#v headless=%#v", conversational.Snapshot, headless.Snapshot)
	}
}

func TestCreateCannotAcknowledgeWhenReceiptJournalIsUnavailable(t *testing.T) {
	store := &fakeStore{}
	starter := &checkingStarter{store: store}
	receipts := journal.NewMemoryStore()
	receipts.SetAvailable(false)
	service := NewService(store, starter, fixedID("run-journal"), fixedClock{time.Unix(100, 0)}, receipts, admitAll())
	raw := []byte(`{"domain":"platform-agent","operation":"artifact-validation","target":{"targetType":"page","targetId":"page-1"}}`)
	digest, _ := canonical.Digest(raw)
	input := CreateInput{Scope: Scope{WorkspaceID: "workspace", ProjectID: "project", ActorID: "actor"}, Key: "journal-key", ClaimedDigest: digest, Traceparent: testTraceparent, Raw: raw, Authority: testAuthority()}
	if _, err := service.Create(context.Background(), input); err == nil {
		t.Fatal("create acknowledged without independent journal")
	}
	if starter.beforeDurable || store.created == nil {
		t.Fatal("journal failure did not occur after durable database outcome")
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

func TestTraceparentAndAuthorityIdentitiesUseClosedBounds(t *testing.T) {
	if validTraceparent("00-"+strings.Repeat("0", 32)+"-0123456789abcdef-01") || validTraceparent("00-0123456789abcdef0123456789abcdef-"+strings.Repeat("0", 16)+"-01") || validTraceparent("ff-0123456789abcdef0123456789abcdef-0123456789abcdef-01") {
		t.Fatal("invalid W3C trace identity accepted")
	}
	if err := (Scope{WorkspaceID: "workspace", ProjectID: strings.Repeat("p", 129), ActorID: "actor"}).Validate(); err == nil {
		t.Fatal("unbounded authoritative scope accepted")
	}
}

func TestCreateRejectsGeneratedIdentityThatCannotProduceBoundedEventIDs(t *testing.T) {
	store := &fakeStore{}
	service := NewService(store, &checkingStarter{store: store}, fixedID(strings.Repeat("r", 108)), fixedClock{time.Unix(100, 0)}, journal.NewMemoryStore(), admitAll())
	raw := []byte(`{"domain":"platform-agent","operation":"artifact-validation","target":{"targetType":"page","targetId":"page-1"}}`)
	digest, _ := canonical.Digest(raw)
	_, err := service.Create(context.Background(), CreateInput{Scope: Scope{WorkspaceID: "workspace", ProjectID: "project", ActorID: "actor"}, Key: "key", ClaimedDigest: digest, Traceparent: testTraceparent, Raw: raw, Authority: testAuthority()})
	if err == nil || store.created != nil {
		t.Fatalf("unbounded generated identity reached persistence: err=%v", err)
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
	started       int
}

func (s *checkingStarter) Ensure(context.Context, Start) error {
	if s.store.created == nil {
		s.beforeDurable = true
	}
	s.started++
	return nil
}
func testAuthority() Authority {
	policy := json.RawMessage(`{"policyId":"policy.synthetic","version":"v1","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`)
	return Authority{
		Definition:  json.RawMessage(`{"definitionId":"definition.synthetic.001","definitionDigest":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}`),
		ContractBOM: json.RawMessage(`{"repository":"anvilkit/contracts","bomDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","ociManifestDigest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","evidenceManifestDigest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}`),
		Policy:      policy,
		Budget:      json.RawMessage(`{"kind":"AgentBudget","modelLimits":{"maximumCalls":10,"maximumConcurrentCalls":2},"tokenLimits":{"inputTokens":4096,"outputTokens":2048,"totalTokens":6144},"workerLimits":{"maximumAttempts":4,"maximumDurationMilliseconds":60000},"gpuLimits":{"maximumGpuMilliseconds":0},"currencyLimits":{"maximumCost":{"amount":"1000","currency":"USD"},"reservedCost":{"amount":"500","currency":"USD"}},"reservationId":"reservation.synthetic.001","exceedBehavior":"refuse","policy":` + string(policy) + `}`),
	}
}

const testTraceparent = "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"

// admitAll is the admission gate for tests whose subject is not the trust
// boundary. Production composition supplies the real revalidating gate.
func admitAll() Admission {
	return AdmitFunc(func(context.Context, Scope) error { return nil })
}

// The admission gate is where service-wide trust material is revalidated
// before a new run exists. A refusal must stop creation outright: no run
// identity, no durable record, and no workflow.
func TestRefusedAdmissionCreatesNothing(t *testing.T) {
	store := &fakeStore{}
	starter := &checkingStarter{store: store}
	stale := problem.New(problem.CodeAuthorityStale, "")
	service := NewService(store, starter, fixedID("run-refused"), fixedClock{time.Unix(100, 0)}, journal.NewMemoryStore(), AdmitFunc(func(context.Context, Scope) error { return stale }))
	raw := []byte(`{"domain":"platform-agent","operation":"artifact-validation","target":{"targetType":"page","targetId":"page-1"}}`)
	digest, _ := canonical.Digest(raw)
	input := CreateInput{Scope: Scope{WorkspaceID: "workspace", ProjectID: "project", ActorID: "actor"}, Key: "key", ClaimedDigest: digest, Raw: raw, Authority: testAuthority(), Traceparent: testTraceparent}
	_, err := service.Create(context.Background(), input)
	var details problem.Details
	if !errors.As(err, &details) || details.Code != string(problem.CodeAuthorityStale) {
		t.Fatalf("create error = %v, want %s", err, problem.CodeAuthorityStale)
	}
	if store.created != nil {
		t.Fatal("a durable run record was written behind a refused admission")
	}
	if starter.started != 0 {
		t.Fatalf("workflow starts = %d, want none behind a refused admission", starter.started)
	}
}

// A service composed without an admission gate refuses to create runs rather
// than admitting them unchecked.
func TestMissingAdmissionGateFailsClosed(t *testing.T) {
	store := &fakeStore{}
	service := NewService(store, &checkingStarter{store: store}, fixedID("run-ungated"), fixedClock{time.Unix(100, 0)}, journal.NewMemoryStore(), nil)
	raw := []byte(`{"domain":"platform-agent","operation":"artifact-validation","target":{"targetType":"page","targetId":"page-1"}}`)
	digest, _ := canonical.Digest(raw)
	input := CreateInput{Scope: Scope{WorkspaceID: "workspace", ProjectID: "project", ActorID: "actor"}, Key: "key", ClaimedDigest: digest, Raw: raw, Authority: testAuthority(), Traceparent: testTraceparent}
	if _, err := service.Create(context.Background(), input); err == nil {
		t.Fatal("a run was created with no admission gate configured")
	}
	if store.created != nil {
		t.Fatal("a durable run record was written with no admission gate configured")
	}
}
