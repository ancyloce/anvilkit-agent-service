package execution

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/applyauth"
	"github.com/ancyloce/anvilkit-agent-service/internal/authority"
	"github.com/ancyloce/anvilkit-agent-service/internal/canonical"
	contractguard "github.com/ancyloce/anvilkit-agent-service/internal/contracts"
	"github.com/ancyloce/anvilkit-agent-service/internal/interrupts"
	"github.com/ancyloce/anvilkit-agent-service/internal/journal"
	"github.com/ancyloce/anvilkit-agent-service/internal/runs"
)

var applyAuthorityNow = time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)

type applyAuthorityClock struct{ value time.Time }

func (c applyAuthorityClock) Now() time.Time { return c.value }

type applyAuthorityRunStore struct{ snapshot runs.Snapshot }

func (s applyAuthorityRunStore) Get(context.Context, runs.Scope, runs.ID) (runs.Snapshot, error) {
	return s.snapshot, nil
}

func (s applyAuthorityRunStore) Transition(context.Context, runs.Scope, runs.ID, uint64, runs.Command) (runs.Snapshot, error) {
	return runs.Snapshot{}, fmt.Errorf("the authority resolver never transitions runs")
}

type applyAuthorityInterrupts struct{ approval interrupts.ApprovalRequest }

func (r applyAuthorityInterrupts) Input(context.Context, runs.Scope, runs.ID, interrupts.RequestID) (interrupts.InputRequest, error) {
	return interrupts.InputRequest{}, fmt.Errorf("the authority resolver never reads input requests")
}

func (r applyAuthorityInterrupts) Approval(context.Context, runs.Scope, runs.ID, interrupts.RequestID) (interrupts.ApprovalRequest, error) {
	return r.approval, nil
}

func applyAuthorityMaterial() (json.RawMessage, json.RawMessage, json.RawMessage, json.RawMessage) {
	return json.RawMessage(`{"doc":"definition"}`), json.RawMessage(`{"doc":"contract-bom"}`), json.RawMessage(`{"doc":"policy"}`), json.RawMessage(`{"maximumCostMicros":"1000000","currency":"USD"}`)
}

func applyAuthorityFixture(t *testing.T, artifactDigest string) (applyAuthorityRunStore, applyAuthorityInterrupts, authority.Source, applyauth.Command) {
	t.Helper()
	definition, contractBOM, policy, budget := applyAuthorityMaterial()
	snapshot := runs.Snapshot{
		Kind:        "AgentRun",
		RunID:       "run-01",
		WorkspaceID: "workspace-01",
		ActorID:     "actor-01",
		Target:      runs.Target{Type: "page", ID: "page-01", WorkspaceID: "workspace-01", ProjectID: "project-01"},
		Definition:  definition,
		ContractBOM: contractBOM,
		Policy:      policy,
		Budget:      budget,
		Status:      runs.AwaitingApproval,
		Version:     9,
	}
	approval := interrupts.ApprovalRequest{
		ID:           "request.approve01",
		RunID:        "run-01",
		Version:      7,
		ActionDigest: artifactDigest,
		ExpiresAt:    applyAuthorityNow.Add(time.Hour),
		Decision:     &interrupts.Decision{RequestVersion: 7, Kind: interrupts.DecisionApprove, AcceptedAt: applyAuthorityNow},
	}
	source := authority.NewStatic(authority.Current{
		Definition:       definition,
		ContractBOM:      contractBOM,
		Policy:           policy,
		Budget:           budget,
		WorkspaceActive:  true,
		ActorActive:      true,
		PermissionActive: true,
		PolicyActive:     true,
	})
	command := applyauth.Command{WorkspaceID: "workspace-01", ProjectID: "project-01", RunID: "run-01", ApprovalRequestID: "request.approve01", ArtifactID: artifactDigest}
	return applyAuthorityRunStore{snapshot: snapshot}, applyAuthorityInterrupts{approval: approval}, source, command
}

// finalizedArtifacts returns a controlled artifact port already carrying the
// candidate in the finalized state — the state the commit gate reaches after
// the run's own finalize and review operations.
func finalizedArtifacts(t *testing.T, artifactDigest string) *ControlledArtifactPort {
	t.Helper()
	port := NewControlledArtifactPort()
	candidate := ArtifactCandidate{WorkspaceID: "workspace-01", ProjectID: "project-01", RunID: "run-01", Digest: artifactDigest, Bytes: []byte(`{"kind":"candidate"}`), OperationKey: "workflow-1:finalize"}
	if err := port.RecordCandidate(context.Background(), candidate); err != nil {
		t.Fatal(err)
	}
	if err := port.EnsureFinalized(context.Background(), ArtifactQuery{WorkspaceID: "workspace-01", ProjectID: "project-01", RunID: "run-01", ArtifactDigest: artifactDigest}); err != nil {
		t.Fatal(err)
	}
	return port
}

func TestApplyAuthorityResolverProvesTheCurrentBinding(t *testing.T) {
	artifactDigest := "sha256:" + strings.Repeat("b", 64)
	runStore, reader, source, command := applyAuthorityFixture(t, artifactDigest)
	resolver, err := NewApplyAuthorityResolver(runStore, reader, source, finalizedArtifacts(t, artifactDigest))
	if err != nil {
		t.Fatal(err)
	}
	proof, err := resolver.Resolve(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	if !proof.ApprovalCurrent || !proof.ArtifactEligible {
		t.Fatalf("proof = %+v, want a current approval over an eligible artifact", proof)
	}
	if proof.Approved != proof.Current {
		t.Fatalf("approved and current bindings must match without drift:\napproved %+v\ncurrent  %+v", proof.Approved, proof.Current)
	}
	definition, _, _, _ := applyAuthorityMaterial()
	wantDefinition, err := canonical.Digest(definition)
	if err != nil {
		t.Fatal(err)
	}
	if proof.Current.DefinitionDigest != wantDefinition || proof.Current.ArtifactDigest != artifactDigest || proof.Current.ApprovalVersion != 7 || proof.Current.ActorID != "actor-01" || proof.Current.Target.ProjectID != "project-01" {
		t.Fatalf("binding = %+v, want the re-proved run facts", proof.Current)
	}
}

func TestApplyAuthorityResolverSurfacesEveryDrift(t *testing.T) {
	artifactDigest := "sha256:" + strings.Repeat("b", 64)
	t.Run("rotated policy drifts the current binding", func(t *testing.T) {
		runStore, reader, _, command := applyAuthorityFixture(t, artifactDigest)
		definition, contractBOM, _, budget := applyAuthorityMaterial()
		rotated := authority.NewStatic(authority.Current{Definition: definition, ContractBOM: contractBOM, Policy: json.RawMessage(`{"doc":"policy-v2"}`), Budget: budget, WorkspaceActive: true, ActorActive: true, PermissionActive: true, PolicyActive: true})
		resolver, err := NewApplyAuthorityResolver(runStore, reader, rotated, finalizedArtifacts(t, artifactDigest))
		if err != nil {
			t.Fatal(err)
		}
		proof, err := resolver.Resolve(context.Background(), command)
		if err != nil {
			t.Fatal(err)
		}
		if proof.Approved == proof.Current {
			t.Fatal("a rotated policy must drift the current binding away from the approved binding")
		}
	})
	t.Run("re-decided approval drifts the approval version", func(t *testing.T) {
		runStore, reader, source, command := applyAuthorityFixture(t, artifactDigest)
		reader.approval.Version = 8
		resolver, err := NewApplyAuthorityResolver(runStore, reader, source, finalizedArtifacts(t, artifactDigest))
		if err != nil {
			t.Fatal(err)
		}
		proof, err := resolver.Resolve(context.Background(), command)
		if err != nil {
			t.Fatal(err)
		}
		if proof.Approved.ApprovalVersion == proof.Current.ApprovalVersion {
			t.Fatal("a re-decided approval must drift the approval version")
		}
	})
	t.Run("a rejecting decision is not a current approval", func(t *testing.T) {
		runStore, reader, source, command := applyAuthorityFixture(t, artifactDigest)
		reader.approval.Decision = &interrupts.Decision{RequestVersion: 7, Kind: interrupts.DecisionReject, AcceptedAt: applyAuthorityNow}
		resolver, err := NewApplyAuthorityResolver(runStore, reader, source, finalizedArtifacts(t, artifactDigest))
		if err != nil {
			t.Fatal(err)
		}
		proof, err := resolver.Resolve(context.Background(), command)
		if err != nil {
			t.Fatal(err)
		}
		if proof.ApprovalCurrent {
			t.Fatal("a rejecting decision must not count as a current approval")
		}
	})
	t.Run("a withdrawn artifact is ineligible", func(t *testing.T) {
		runStore, reader, source, command := applyAuthorityFixture(t, artifactDigest)
		artifacts := NewControlledArtifactPort()
		artifacts.Withdraw(artifactDigest, "quarantined after approval")
		resolver, err := NewApplyAuthorityResolver(runStore, reader, source, artifacts)
		if err != nil {
			t.Fatal(err)
		}
		proof, err := resolver.Resolve(context.Background(), command)
		if err != nil {
			t.Fatal(err)
		}
		if proof.ArtifactEligible {
			t.Fatal("a withdrawn artifact must be ineligible")
		}
	})
}

// countingIssuer proves how many real issuances the bridge caused.
type countingIssuer struct {
	inner  Issuer
	issued int
}

func (c *countingIssuer) Issue(ctx context.Context, command applyauth.Command) (applyauth.Authorization, error) {
	c.issued++
	return c.inner.Issue(ctx, command)
}

func TestIssuerCommitAuthorityIssuesOneSignedAuditedAuthorizationPerOperation(t *testing.T) {
	artifactDigest := "sha256:" + strings.Repeat("b", 64)
	runStore, reader, source, _ := applyAuthorityFixture(t, artifactDigest)
	resolver, err := NewApplyAuthorityResolver(runStore, reader, source, finalizedArtifacts(t, artifactDigest))
	if err != nil {
		t.Fatal(err)
	}
	guard, err := contractguard.NewGuard("../..")
	if err != nil {
		t.Fatal(err)
	}
	keyring, err := applyauth.NewSeededKeyRing([]byte("test-signing-material-0123456789"))
	if err != nil {
		t.Fatal(err)
	}
	// One durable record plays both sides of the atomic contract: it is the
	// issuer's audit port and the commit authority's issuance reader.
	store := NewMemoryIssuanceStore()
	service, err := applyauth.New(resolver, RandomAuthorizationIDs{}, keyring, store, journal.NewMemoryStore(), guard, applyAuthorityClock{applyAuthorityNow}, 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	issuer := &countingIssuer{inner: service}
	bridge, err := NewIssuerCommitAuthority(issuer, store)
	if err != nil {
		t.Fatal(err)
	}
	request := AuthorizationRequest{
		IdempotencyKey:    "workflow-1:commit",
		WorkspaceID:       "workspace-01",
		ProjectID:         "project-01",
		RunID:             "run-01",
		ArtifactDigest:    artifactDigest,
		ActionDigest:      artifactDigest,
		ApprovalRequestID: "request.approve01",
	}
	first, err := bridge.Issue(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if first.AuthorizationID == "" || first.CompactJWS == "" {
		t.Fatal("issuance must return the durable authorization identity and its complete signed token")
	}
	payload, err := applyauth.Verify(context.Background(), first.CompactJWS, keyring, applyAuthorityNow.Add(time.Minute))
	if err != nil {
		t.Fatalf("the issued token must verify: %v", err)
	}
	if string(payload.AuthorizationID) != first.AuthorizationID || !strings.HasPrefix(payload.KeyID, "urn:anvilkit:key:") || payload.RunID != "run-01" {
		t.Fatalf("signed payload = %+v, want the issued identity, signing key, and run binding", payload)
	}
	second, err := bridge.Issue(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if second.AuthorizationID != first.AuthorizationID || second.CompactJWS != first.CompactJWS {
		t.Fatalf("replaying the durable operation returned %q, want the original persisted authorization %q", second.AuthorizationID, first.AuthorizationID)
	}
	if issuer.issued != 1 {
		t.Fatalf("issued %d times, want exactly one signed audited issuance", issuer.issued)
	}
	recorded, ok, err := store.Recorded(context.Background(), "workspace-01", "project-01", "workflow-1:commit")
	if err != nil || !ok || recorded.AuthorizationID != first.AuthorizationID || recorded.AuthorizationJWS != first.CompactJWS || recorded.RunID != "run-01" {
		t.Fatalf("recorded issuance = %+v ok=%v err=%v, want the complete persisted authorization", recorded, ok, err)
	}
	// A fresh process over the same durable record must replay the recorded
	// original authorization instead of minting a new one.
	replayBridge, err := NewIssuerCommitAuthority(issuer, store)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := replayBridge.Issue(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if replayed.AuthorizationID != first.AuthorizationID || replayed.CompactJWS != first.CompactJWS || issuer.issued != 1 {
		t.Fatal("a fresh process must replay the recorded original authorization")
	}
}

// Concurrent executions of the same durable commit operation — racing
// replicas, or a crash replay racing its predecessor — resolve to exactly one
// signed capability: every caller observes the same identity and the same
// token, and the issuance record holds exactly one mapping.
func TestConcurrentIssuanceResolvesToOneCapability(t *testing.T) {
	artifactDigest := "sha256:" + strings.Repeat("b", 64)
	runStore, reader, source, _ := applyAuthorityFixture(t, artifactDigest)
	resolver, err := NewApplyAuthorityResolver(runStore, reader, source, finalizedArtifacts(t, artifactDigest))
	if err != nil {
		t.Fatal(err)
	}
	guard, err := contractguard.NewGuard("../..")
	if err != nil {
		t.Fatal(err)
	}
	keyring, err := applyauth.NewSeededKeyRing([]byte("test-signing-material-9876543210"))
	if err != nil {
		t.Fatal(err)
	}
	store := NewMemoryIssuanceStore()
	service, err := applyauth.New(resolver, RandomAuthorizationIDs{}, keyring, store, journal.NewMemoryStore(), guard, applyAuthorityClock{applyAuthorityNow}, 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	bridge, err := NewIssuerCommitAuthority(service, store)
	if err != nil {
		t.Fatal(err)
	}
	request := AuthorizationRequest{
		IdempotencyKey:    "workflow-race:commit",
		WorkspaceID:       "workspace-01",
		ProjectID:         "project-01",
		RunID:             "run-01",
		ArtifactDigest:    artifactDigest,
		ActionDigest:      artifactDigest,
		ApprovalRequestID: "request.approve01",
	}
	const racers = 16
	results := make(chan IssuedAuthorization, racers)
	failures := make(chan error, racers)
	start := make(chan struct{})
	var wait sync.WaitGroup
	for index := 0; index < racers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			issued, err := bridge.Issue(context.Background(), request)
			if err != nil {
				failures <- err
				return
			}
			results <- issued
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	close(failures)
	for err := range failures {
		t.Fatalf("concurrent issuance failed: %v", err)
	}
	var winner IssuedAuthorization
	count := 0
	for issued := range results {
		count++
		if winner.AuthorizationID == "" {
			winner = issued
			continue
		}
		if issued.AuthorizationID != winner.AuthorizationID || issued.CompactJWS != winner.CompactJWS {
			t.Fatalf("racing issuance observed a second capability: %q vs %q", issued.AuthorizationID, winner.AuthorizationID)
		}
	}
	if count != racers || winner.CompactJWS == "" {
		t.Fatalf("racers=%d winner=%+v, want every racer to observe the one signed capability", count, winner)
	}
	recorded, ok, err := store.Recorded(context.Background(), "workspace-01", "project-01", "workflow-race:commit")
	if err != nil || !ok || recorded.AuthorizationID != winner.AuthorizationID || recorded.AuthorizationJWS != winner.CompactJWS {
		t.Fatalf("recorded=%+v ok=%v err=%v, want exactly the winning capability", recorded, ok, err)
	}
}

func TestIssuerCommitAuthorityRejectsUnboundRequests(t *testing.T) {
	artifactDigest := "sha256:" + strings.Repeat("b", 64)
	bridge, err := NewIssuerCommitAuthority(&countingIssuer{inner: issuerFunc(func(context.Context, applyauth.Command) (applyauth.Authorization, error) {
		return applyauth.Authorization{ID: "authorization.unreachable"}, nil
	})}, NewMemoryIssuanceStore())
	if err != nil {
		t.Fatal(err)
	}
	base := AuthorizationRequest{IdempotencyKey: "workflow-1:commit", WorkspaceID: "workspace-01", ProjectID: "project-01", RunID: "run-01", ArtifactDigest: artifactDigest, ActionDigest: artifactDigest, ApprovalRequestID: "request.approve01"}
	missingApproval := base
	missingApproval.ApprovalRequestID = ""
	if _, err := bridge.Issue(context.Background(), missingApproval); err == nil {
		t.Fatal("issuance without the approval identity must fail closed")
	}
	mismatched := base
	mismatched.ActionDigest = "sha256:" + strings.Repeat("c", 64)
	if _, err := bridge.Issue(context.Background(), mismatched); err == nil {
		t.Fatal("an action digest that does not bind the artifact must fail closed")
	}
}

type issuerFunc func(context.Context, applyauth.Command) (applyauth.Authorization, error)

func (f issuerFunc) Issue(ctx context.Context, command applyauth.Command) (applyauth.Authorization, error) {
	return f(ctx, command)
}
