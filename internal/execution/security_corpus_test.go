package execution_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/agent"
	"github.com/ancyloce/anvilkit-agent-service/internal/artifacts"
	"github.com/ancyloce/anvilkit-agent-service/internal/authority"
	"github.com/ancyloce/anvilkit-agent-service/internal/budget"
	"github.com/ancyloce/anvilkit-agent-service/internal/interrupts"
	"github.com/ancyloce/anvilkit-agent-service/internal/journal"
	"github.com/ancyloce/anvilkit-agent-service/internal/security"
	"github.com/ancyloce/anvilkit-agent-service/internal/securityaudit"
	"github.com/ancyloce/anvilkit-agent-service/internal/workflow"
)

// The adversarial corpus is only worth what it is evaluated against. It used
// to answer every case from a comparison written beside the case itself —
// "cross-tenant is blocked if the input is not workspace-a" — so a run of the
// corpus proved that the corpus agreed with itself and nothing about the
// production paths the cases named. Every category is now bound to the real
// decision that owns it, and a category bound to nothing fails the run.
//
// Zero tolerance means what it says: every case must be refused, every finding
// must be recorded, and a case that cannot be evaluated is a failure rather
// than a pass.
func TestAdversarialCorpusIsRefusedByProductionDecisions(t *testing.T) {
	ctx := context.Background()
	corpus, err := security.LoadCorpus("../security/testdata/adversarial-corpus.v1.json")
	if err != nil {
		t.Fatal(err)
	}
	guards := productionGuards(t)
	// The bindings must cover the corpus before it is run, so a category added
	// to the corpus without a guard is a failure of coverage rather than a
	// case that quietly never ran.
	for _, category := range corpus.Categories() {
		if _, bound := guards[category]; !bound {
			t.Fatalf("adversarial category %q is bound to no production decision", category)
		}
	}

	recorder := &security.MemoryFindingRecorder{}
	findings, err := security.RunCorpusWithRecorder(ctx, corpus, guards, recorder)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != len(corpus.Cases) {
		t.Fatalf("findings=%d, want one per case (%d)", len(findings), len(corpus.Cases))
	}
	accepted := make([]string, 0)
	for index, finding := range findings {
		if !finding.Recorded {
			t.Fatalf("finding %s was not recorded", finding.ID)
		}
		if finding.ID != corpus.Cases[index].ID || finding.Category != corpus.Cases[index].Category {
			t.Fatalf("finding %+v does not answer case %+v", finding, corpus.Cases[index])
		}
		if finding.Outcome != "blocked" {
			accepted = append(accepted, finding.ID+" ("+finding.Category+")")
		}
	}
	if len(accepted) != 0 {
		t.Fatalf("the zero-tolerance corpus admitted %d case(s): %s", len(accepted), strings.Join(accepted, ", "))
	}
}

// A corpus with no bindings is refused outright, and a category the bindings
// do not cover fails the run rather than passing unevaluated. This is the
// property that makes the corpus meaningful: it cannot report a refusal it did
// not obtain from a real decision.
func TestTheCorpusCannotPassWithoutTheDecisionsItNames(t *testing.T) {
	ctx := context.Background()
	corpus, err := security.LoadCorpus("../security/testdata/adversarial-corpus.v1.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := security.RunCorpus(ctx, corpus, nil); err == nil {
		t.Fatal("the corpus ran with no production decisions bound to it")
	}
	partial := security.Guards{}
	for category, guard := range productionGuards(t) {
		if category == corpus.Cases[0].Category {
			continue
		}
		partial[category] = guard
	}
	if _, err := security.RunCorpus(ctx, corpus, partial); err == nil {
		t.Fatal("a category bound to no production decision did not fail the corpus")
	}
	// A guard that cannot reach a decision is a failure, never a refusal.
	unreachable := productionGuards(t)
	unreachable[corpus.Cases[0].Category] = security.GuardFunc(func(context.Context, security.AttackCase) (bool, error) {
		return false, context.Canceled
	})
	if _, err := security.RunCorpus(ctx, corpus, unreachable); err == nil {
		t.Fatal("a decision that could not be reached was treated as an outcome")
	}
}

// productionGuards binds every adversarial category to the production decision
// that owns it. Each binding calls real code: the executor's scope and
// authority guards, the approved catalog's tool attestation, the pinned
// argument validator, the interrupt service's approval handling, the budget
// controller's generation fence and observation binding, and the memory and
// egress guards.
func productionGuards(t *testing.T) security.Guards {
	t.Helper()
	return security.Guards{
		"cross-tenant": security.GuardFunc(func(ctx context.Context, attack security.AttackCase) (bool, error) {
			return foreignTenantIsRefusedAtPreparation(t, ctx, attack)
		}),
		"unauthorized-disclosure": security.GuardFunc(func(ctx context.Context, attack security.AttackCase) (bool, error) {
			return foreignTenantIsRefusedAtTheTurn(t, ctx, attack)
		}),
		"revoked-authority": security.GuardFunc(func(ctx context.Context, _ security.AttackCase) (bool, error) {
			return revokedAuthorityIsRefused(t, ctx)
		}),
		"duplicate-effect": security.GuardFunc(func(ctx context.Context, _ security.AttackCase) (bool, error) {
			return aReplayedOperationCausesNoSecondEffect(t, ctx)
		}),
		"forbidden-tool": security.GuardFunc(func(ctx context.Context, attack security.AttackCase) (bool, error) {
			return anUnattestedToolIsRefused(t, attack)
		}),
		"recursive-tool": security.GuardFunc(func(ctx context.Context, attack security.AttackCase) (bool, error) {
			return anUnattestedToolIsRefused(t, attack)
		}),
		"schema-violation": security.GuardFunc(func(ctx context.Context, attack security.AttackCase) (bool, error) {
			return anInvalidArgumentPayloadIsRefused(t, ctx, attack)
		}),
		"approval-bypass": security.GuardFunc(func(ctx context.Context, _ security.AttackCase) (bool, error) {
			return anApprovalForNoOpenRequestIsRefused(t, ctx)
		}),
		"forged-observation": security.GuardFunc(func(ctx context.Context, _ security.AttackCase) (bool, error) {
			return anUnboundUsageObservationIsRefused(t, ctx)
		}),
		"stale-result": security.GuardFunc(func(ctx context.Context, _ security.AttackCase) (bool, error) {
			return aSupersededGenerationCannotDispatch(t, ctx)
		}),
		"restored-deletion": security.GuardFunc(func(ctx context.Context, _ security.AttackCase) (bool, error) {
			return aRestoredObjectDoesNotResurrectADeletedArtifact(t, ctx)
		}),
		"direct-injection":      memoryAdmissionGuard(t),
		"indirect-injection":    memoryAdmissionGuard(t),
		"encoded-injection":     memoryAdmissionGuard(t),
		"markup-injection":      memoryAdmissionGuard(t),
		"memory-poisoning":      memoryAdmissionGuard(t),
		"exfiltration-proposal": memoryAdmissionGuard(t),
		"ssrf-egress":           egressGuard(t),
	}
}

// foreignTenantIsRefusedAtPreparation drives the executor's preparation
// boundary under a workspace the run does not belong to.
func foreignTenantIsRefusedAtPreparation(t *testing.T, ctx context.Context, attack security.AttackCase) (bool, error) {
	t.Helper()
	h := newHarness(t, [][]byte{finalPlan()})
	input := h.seedRun("artifact-validation")
	foreign := input
	foreign.Scope.WorkspaceID = attack.Input
	result, err := h.ops.Prepare(ctx, opID(foreign, "prepare"), foreign)
	return err != nil || result.Refused != nil || result.Superseded, nil
}

// foreignTenantIsRefusedAtTheTurn asks an existing run to take a turn under a
// workspace it does not belong to. The run exists; the tenant does not own it.
func foreignTenantIsRefusedAtTheTurn(t *testing.T, ctx context.Context, attack security.AttackCase) (bool, error) {
	t.Helper()
	h := newHarness(t, [][]byte{finalPlan()})
	input := h.seedRun("artifact-validation")
	prepare(t, h, input)
	foreign := input
	foreign.Scope.WorkspaceID = attack.Input
	_, err := h.ops.ExecuteTurn(ctx, opID(foreign, "turn-0000"), workflow.TurnInput{Run: foreign, Turn: 0, Phase: workflow.PhasePlan})
	return err != nil, nil
}

// revokedAuthorityIsRefused withdraws the run actor's authority and asks the
// executor to take a turn under it.
func revokedAuthorityIsRefused(t *testing.T, ctx context.Context) (bool, error) {
	t.Helper()
	h := newHarness(t, [][]byte{finalPlan()})
	input := h.seedRun("artifact-validation")
	prepare(t, h, input)
	h.authoritySource.Revoke()
	result, err := h.ops.ExecuteTurn(ctx, opID(input, "turn-0000"), workflow.TurnInput{Run: input, Turn: 0, Phase: workflow.PhasePlan})
	return err != nil || result.Halt != nil || result.Superseded, nil
}

// aReplayedOperationCausesNoSecondEffect replays one durable operation and
// proves the provider is not billed a second time.
func aReplayedOperationCausesNoSecondEffect(t *testing.T, ctx context.Context) (bool, error) {
	t.Helper()
	h := newHarness(t, [][]byte{finalPlan(), finalPlan()})
	input := h.seedRun("artifact-validation")
	prepare(t, h, input)
	if _, err := h.ops.ExecuteTurn(ctx, opID(input, "turn-0000"), workflow.TurnInput{Run: input, Turn: 0, Phase: workflow.PhasePlan}); err != nil {
		return false, err
	}
	first := billedOperations(t, h)
	if _, err := h.ops.ExecuteTurn(ctx, opID(input, "turn-0000"), workflow.TurnInput{Run: input, Turn: 0, Phase: workflow.PhasePlan}); err != nil {
		return false, err
	}
	return billedOperations(t, h) == first, nil
}

// anUnattestedToolIsRefused asks the running tool material whether the
// approved catalog attests the named tool. The fenced dispatcher refuses
// anything it does not, which is the decision that stops both a tool outside
// the profile and a tool that names itself.
func anUnattestedToolIsRefused(t *testing.T, attack security.AttackCase) (bool, error) {
	t.Helper()
	h := newHarness(t, [][]byte{finalPlan()})
	_, attested := h.toolMaterial().ToolDefinition(attack.Input)
	return !attested, nil
}

// anInvalidArgumentPayloadIsRefused proposes a tool call whose arguments do
// not satisfy the digest-pinned input schema. The refusal is deliberately not
// an error — a denied tool call is a recorded decision the run continues past
// — so what proves the guard held is that the tool never executed and the
// denial was recorded, not that the caller saw a failure.
func anInvalidArgumentPayloadIsRefused(t *testing.T, ctx context.Context, attack security.AttackCase) (bool, error) {
	t.Helper()
	h := newHarness(t, [][]byte{finalPlan()})
	input := h.seedRun("artifact-validation")
	prepare(t, h, input)
	_, err := h.ops.ExecuteAction(ctx, opID(input, "action-0000"), workflow.ActionInput{
		Run:      input,
		Turn:     0,
		Phase:    workflow.PhasePlan,
		Decision: agent.TurnDecision{Kind: agent.DecisionToolCall, ToolCall: &agent.ToolCallDecision{ToolID: "anvilkit.tool.context-echo", Arguments: json.RawMessage(attack.Input)}},
	})
	if err != nil {
		return true, nil
	}
	if h.tool.Executions() != 0 {
		return false, nil
	}
	for _, recorded := range h.recorder.Decisions {
		if !recorded.Decision.Allowed {
			return true, nil
		}
	}
	return false, nil
}

// anApprovalForNoOpenRequestIsRefused presents an approval decision for a
// request that was never opened.
func anApprovalForNoOpenRequestIsRefused(t *testing.T, ctx context.Context) (bool, error) {
	t.Helper()
	h := newHarness(t, [][]byte{finalPlan()})
	input := h.seedRun("artifact-validation")
	prepare(t, h, input)
	snapshot := h.snapshot()
	_, err := h.service.DecideApproval(ctx,
		interrupts.Write{Scope: testScope(), RunID: testRunID, ExpectedVersion: snapshot.Version, IdempotencyKey: "forged-approval", Traceparent: traceparent},
		interrupts.ApprovalDecisionCommand{RequestID: "approval.never-opened", RequestVersion: 1, Decision: interrupts.DecisionApprove, ActionDigest: validDigest, Comment: "approved without a request"})
	return err != nil, nil
}

// anUnboundUsageObservationIsRefused offers the budget ledger an observation
// that names no reservation it holds. Usage that is not bound to a hold is
// usage nobody authorized, whatever it claims to have observed.
func anUnboundUsageObservationIsRefused(t *testing.T, ctx context.Context) (bool, error) {
	t.Helper()
	h := newHarness(t, [][]byte{finalPlan()})
	input := h.seedRun("artifact-validation")
	prepare(t, h, input)
	err := h.budgetController.Observe(ctx, budget.Observation{
		ID:                  "forged-observation",
		Scope:               testBudgetScope,
		ReservationID:       "budget:no-such-reservation:g1",
		RootRunID:           testRunID,
		RunID:               testRunID,
		TaskID:              "model:forged",
		AttemptID:           "attempt.forged",
		ExecutionGeneration: 1,
		MeterSequence:       1,
		CostMicros:          1_000_000,
	})
	return err != nil, nil
}

// aSupersededGenerationCannotDispatch asks the budget controller to dispatch
// expensive work under a generation the run has moved past.
func aSupersededGenerationCannotDispatch(t *testing.T, ctx context.Context) (bool, error) {
	t.Helper()
	h := newHarness(t, [][]byte{finalPlan()})
	input := h.seedRun("artifact-validation")
	prepare(t, h, input)
	dispatched := false
	err := h.budgetController.Dispatch(ctx, testBudgetScope, budget.ReservationID("budget:"+testRunID+":g1"), budget.Generation(99), func(context.Context, budget.Reservation) error {
		dispatched = true
		return nil
	})
	return err != nil && !dispatched, nil
}

// aRestoredObjectDoesNotResurrectADeletedArtifact deletes an artifact, puts
// its bytes back exactly as a restore from backup would, and asks the artifact
// service whether access is available again. The tombstone is the authority,
// not the presence of the object: a restore that reaches around the record
// must not hand back the access the deletion withdrew.
func aRestoredObjectDoesNotResurrectADeletedArtifact(t *testing.T, ctx context.Context) (bool, error) {
	t.Helper()
	store := artifacts.NewMemoryStore()
	objects := artifacts.NewMemoryObjects()
	service, err := artifacts.New(store, objects, corpusArtifactReader{}, corpusArtifactAuthority(), corpusProtectedAudit(t), time.Hour, 5*time.Minute)
	if err != nil {
		return false, err
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	value := []byte("immutable artifact bytes")
	digest := sha256.Sum256(value)
	input := artifacts.Create{
		WorkspaceID: testWorkspace, ProjectID: testProject, RunID: testRunID, ID: "artifact.corpus",
		Bytes: value, ClaimedDigest: "sha256:" + hex.EncodeToString(digest[:]),
		Reference: artifacts.Reference{Bucket: "artifacts", ObjectKey: "artifact.corpus", SizeBytes: int64(len(value)), MediaType: "application/json"},
		Schema:    artifacts.SchemaIdentity{Component: "plan", Version: "1.0.0", Digest: "sha256:" + strings.Repeat("e", 64)},
		Lineage: artifacts.Lineage{
			RunID: testRunID, TaskID: "task.1", PhysicalAttemptID: "attempt.1",
			Producer:      artifacts.Producer{TaskID: "task.1", PhysicalAttemptID: "attempt.1", RecoveryEpoch: 1, ExecutionGeneration: 1, LeaseEpoch: 1, BuildIdentity: "build.1", Provider: "corpus"},
			BOMDigest:     "sha256:" + strings.Repeat("a", 64),
			SchemaDigest:  "sha256:" + strings.Repeat("b", 64),
			CatalogDigest: "sha256:" + strings.Repeat("c", 64),
		},
		CreatedAt: now,
	}
	record, err := service.Create(ctx, input)
	if err != nil {
		return false, err
	}
	custody := artifacts.Custody{ActorID: testActor, Workload: "corpus", Reason: "adversarial-corpus", Ticket: "corpus-0001", Traceparent: traceparent}
	if _, err := service.Delete(ctx, input.WorkspaceID, input.ProjectID, input.ID, record.Version, custody, now.Add(time.Minute)); err != nil {
		return false, err
	}
	// The restore: the bytes are back where they were.
	objects.Restore(input.Reference, value)
	if err := service.Reconcile(ctx, traceparent, now.Add(2*time.Minute)); err != nil {
		return false, err
	}
	restored, err := service.Get(ctx, input.WorkspaceID, input.ProjectID, input.ID)
	if err != nil {
		return false, err
	}
	if restored.State != artifacts.Deleted || restored.DeletedAt == nil {
		return false, nil
	}
	// And no grant can be issued over the resurrected bytes.
	_, grantErr := service.Grant(ctx, input.WorkspaceID, input.ProjectID, input.ID, artifacts.ReviewAccess, testActor, now.Add(3*time.Minute))
	return grantErr != nil, nil
}

// corpusArtifactReader signs and revokes nothing: the decision this binding
// exercises is the artifact record's own tombstone and eligibility guard, and
// the signing port is only what the service needs in order to reach it.
type corpusArtifactReader struct{}

func (corpusArtifactReader) SignRead(context.Context, artifacts.Record, artifacts.Grant, time.Duration) (string, error) {
	return "anvilkit-artifact://artifacts/artifact.corpus", nil
}

func (corpusArtifactReader) Verify(context.Context, artifacts.Record, artifacts.Grant) error {
	return nil
}

func (corpusArtifactReader) Revoke(context.Context, artifacts.Record) error { return nil }

func corpusArtifactAuthority() authority.Source {
	material := json.RawMessage(`{"corpus":true}`)
	return authority.NewStatic(authority.Current{
		Definition: material, ContractBOM: material, Policy: material, Budget: material,
		WorkspaceActive: true, ActorActive: true, PermissionActive: true, PolicyActive: true,
		ActorRole: authority.RoleArtifactCustodian,
		Grants: authority.Grants{
			AllowedCapabilities: []string{string(artifacts.LegalHoldCapability), string(artifacts.DeleteCapability)},
			DataClasses:         []string{artifacts.CustodyDataClass},
		},
	})
}

func corpusProtectedAudit(t *testing.T) *securityaudit.Service {
	t.Helper()
	clock, err := securityaudit.NewAuthoritativeClock(corpusTimeSource{}, corpusTime{}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	service, err := securityaudit.NewService(&securityaudit.MemorySink{}, clock, &securityaudit.MemoryAlerts{}, journal.NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	return service
}

// corpusTime is the fixed authoritative time these bindings run under.
type corpusTime struct{}

func (corpusTime) Now() time.Time { return time.Unix(1_700_000_000, 0).UTC() }

type corpusTimeSource struct{}

func (corpusTimeSource) Now(context.Context) (time.Time, error) {
	return time.Unix(1_700_000_000, 0).UTC(), nil
}

// memoryAdmissionGuard binds the injection and poisoning families to the
// memory admission guard that owns them: untrusted content offered to durable
// memory is refused rather than classified as instruction.
func memoryAdmissionGuard(t *testing.T) security.Guard {
	t.Helper()
	now := time.Unix(700, 0).UTC()
	guard, err := security.NewMemoryGuard(1024, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	return security.GuardFunc(func(_ context.Context, attack security.AttackCase) (bool, error) {
		return guard.Admit(security.MemoryCandidate{
			WorkspaceID:    testWorkspace,
			ProjectID:      testProject,
			SourceID:       attack.ID,
			Classification: "untrusted",
			Content:        []byte(attack.Input),
			ExpiresAt:      now.Add(time.Minute),
		}) != nil, nil
	})
}

// egressGuard binds outbound destinations to the egress guard that owns them.
// The link-local address the case resolves to is the one a cloud instance
// metadata service answers on, so a policy that allows the host by name still
// has to refuse the address it resolves to.
func egressGuard(t *testing.T) security.Guard {
	t.Helper()
	guard, err := security.NewEgressGuard(security.EgressPolicy{
		AllowedHosts:    map[string]struct{}{"api.allowed.test": {}, "metadata.allowed.test": {}},
		MaximumBytes:    1 << 20,
		MaximumDuration: time.Second,
	}, corpusResolver{addresses: map[string][]net.IPAddr{
		"api.allowed.test":      {{IP: net.ParseIP("8.8.8.8")}},
		"metadata.allowed.test": {{IP: net.ParseIP("169.254.169.254")}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return security.GuardFunc(func(ctx context.Context, attack security.AttackCase) (bool, error) {
		_, err := guard.Resolve(ctx, attack.Input)
		return err != nil, nil
	})
}

type corpusResolver struct{ addresses map[string][]net.IPAddr }

func (r corpusResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	values, ok := r.addresses[host]
	if !ok {
		return nil, errNoSuchHost
	}
	return values, nil
}

var errNoSuchHost = &net.DNSError{Err: "no such host", Name: "corpus", IsNotFound: true}
