package execution

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/applyauth"
	"github.com/ancyloce/anvilkit-agent-service/internal/canonical"
	contractguard "github.com/ancyloce/anvilkit-agent-service/internal/contracts"
	"github.com/ancyloce/anvilkit-agent-service/internal/journal"
)

var domainOwnerNow = time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)

type domainOwnerClock struct{ value time.Time }

func (c domainOwnerClock) Now() time.Time { return c.value }

// issueRealAuthorization mints one really signed apply authorization through
// the full issuer service, so the owner verifies genuine material.
func issueRealAuthorization(t *testing.T, keyring *applyauth.MemoryKeyRing, artifactDigest string) (applyauth.Authorization, DomainCommand) {
	t.Helper()
	runStore, reader, source, _ := applyAuthorityFixture(t, artifactDigest)
	resolver, err := NewApplyAuthorityResolver(runStore, reader, source, finalizedArtifacts(t, artifactDigest))
	if err != nil {
		t.Fatal(err)
	}
	guard, err := contractguard.NewGuard("../..")
	if err != nil {
		t.Fatal(err)
	}
	store := NewMemoryIssuanceStore()
	service, err := applyauth.New(resolver, RandomAuthorizationIDs{}, keyring, store, journal.NewMemoryStore(), guard, domainOwnerClock{domainOwnerNow}, 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := service.Issue(context.Background(), applyauth.Command{WorkspaceID: "workspace-01", ProjectID: "project-01", RunID: "run-01", ApprovalRequestID: "request.approve01", ArtifactID: artifactDigest, OperationKey: "workflow-1:commit"})
	if err != nil {
		t.Fatal(err)
	}
	definition, contractBOM, policy, _ := applyAuthorityMaterial()
	definitionDigest, _ := canonical.Digest(definition)
	bomDigest, _ := canonical.Digest(contractBOM)
	policyDigest, _ := canonical.Digest(policy)
	command := DomainCommand{
		OperationID:       "domain.operation-01",
		WorkspaceID:       "workspace-01",
		ProjectID:         "project-01",
		RunID:             "run-01",
		ArtifactDigest:    artifactDigest,
		AuthorizationID:   string(authorization.ID),
		AuthorizationJWS:  authorization.Compact,
		ActionDigest:      artifactDigest,
		BaseRevision:      "rev:request.approve01",
		Target:            applyauth.Target{Type: "page", ID: "page-01", WorkspaceID: "workspace-01", ProjectID: "project-01"},
		ActorID:           "actor-01",
		DefinitionDigest:  definitionDigest,
		ContractBOMDigest: bomDigest,
		PolicyDigest:      policyDigest,
	}
	return authorization, command
}

func TestVerifyingDomainPortRedeemsOnceAndReplaysTheRecordedOutcome(t *testing.T) {
	artifactDigest := "sha256:" + strings.Repeat("b", 64)
	keyring, err := applyauth.NewSeededKeyRing([]byte("domain-owner-signing-material-01"))
	if err != nil {
		t.Fatal(err)
	}
	_, command := issueRealAuthorization(t, keyring, artifactDigest)
	redemptions := NewMemoryRedemptionStore()
	port, err := NewVerifyingDomainPort(DomainConfirmed, keyring, redemptions, domainOwnerClock{domainOwnerNow.Add(time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := port.Commit(context.Background(), command)
	if err != nil || outcome.Status != DomainConfirmed {
		t.Fatalf("outcome=%+v err=%v", outcome, err)
	}
	// A duplicate submission across a newly constructed owner replays the
	// recorded redemption; nothing is applied twice.
	successor, err := NewVerifyingDomainPort(DomainConfirmed, keyring, redemptions, domainOwnerClock{domainOwnerNow.Add(2 * time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := successor.Commit(context.Background(), command)
	if err != nil || replayed.Status != DomainConfirmed {
		t.Fatalf("replayed=%+v err=%v", replayed, err)
	}
	record, found, err := successor.Reconcile(context.Background(), DomainQuery{OperationID: command.OperationID, WorkspaceID: command.WorkspaceID, ProjectID: command.ProjectID, RunID: command.RunID})
	if err != nil || !found || record.Status != DomainConfirmed {
		t.Fatalf("reconciled=%+v found=%v err=%v", record, found, err)
	}
	// The same valid token cannot be redeemed under a second operation.
	secondOperation := command
	secondOperation.OperationID = "domain.operation-02"
	rejected, err := successor.Commit(context.Background(), secondOperation)
	if err != nil || rejected.Status != DomainRejected {
		t.Fatalf("second-operation redemption=%+v err=%v, want rejection", rejected, err)
	}
}

func TestVerifyingDomainPortRejectsForgedExpiredAndDriftedAuthorizations(t *testing.T) {
	artifactDigest := "sha256:" + strings.Repeat("b", 64)
	keyring, err := applyauth.NewSeededKeyRing([]byte("domain-owner-signing-material-02"))
	if err != nil {
		t.Fatal(err)
	}
	_, command := issueRealAuthorization(t, keyring, artifactDigest)

	t.Run("forged token", func(t *testing.T) {
		redemptions := NewMemoryRedemptionStore()
		port, err := NewVerifyingDomainPort(DomainConfirmed, keyring, redemptions, domainOwnerClock{domainOwnerNow.Add(time.Second)})
		if err != nil {
			t.Fatal(err)
		}
		forged := command
		parts := strings.Split(forged.AuthorizationJWS, ".")
		parts[2] = strings.Repeat("A", len(parts[2]))
		forged.AuthorizationJWS = strings.Join(parts, ".")
		outcome, err := port.Commit(context.Background(), forged)
		if err != nil || outcome.Status != DomainRejected {
			t.Fatalf("forged outcome=%+v err=%v, want rejection", outcome, err)
		}
		if _, found, _ := redemptions.Redeemed(context.Background(), command.WorkspaceID, command.ProjectID, command.OperationID); found {
			t.Fatal("a forged token left a redemption record")
		}
	})

	t.Run("token signed by a different key", func(t *testing.T) {
		otherRing, err := applyauth.NewSeededKeyRing([]byte("domain-owner-other-material-0002"))
		if err != nil {
			t.Fatal(err)
		}
		_, otherCommand := issueRealAuthorization(t, otherRing, artifactDigest)
		port, err := NewVerifyingDomainPort(DomainConfirmed, keyring, NewMemoryRedemptionStore(), domainOwnerClock{domainOwnerNow.Add(time.Second)})
		if err != nil {
			t.Fatal(err)
		}
		outcome, err := port.Commit(context.Background(), otherCommand)
		if err != nil || outcome.Status != DomainRejected {
			t.Fatalf("cross-key outcome=%+v err=%v, want rejection", outcome, err)
		}
	})

	t.Run("expired token", func(t *testing.T) {
		port, err := NewVerifyingDomainPort(DomainConfirmed, keyring, NewMemoryRedemptionStore(), domainOwnerClock{domainOwnerNow.Add(10 * time.Minute)})
		if err != nil {
			t.Fatal(err)
		}
		outcome, err := port.Commit(context.Background(), command)
		if err != nil || outcome.Status != DomainRejected {
			t.Fatalf("expired outcome=%+v err=%v, want rejection", outcome, err)
		}
	})

	t.Run("revoked signing key", func(t *testing.T) {
		revokedRing, err := applyauth.NewSeededKeyRing([]byte("domain-owner-revoked-material-02"))
		if err != nil {
			t.Fatal(err)
		}
		authorization, revokedCommand := issueRealAuthorization(t, revokedRing, artifactDigest)
		revokedRing.Revoke(authorization.KeyID)
		port, err := NewVerifyingDomainPort(DomainConfirmed, revokedRing, NewMemoryRedemptionStore(), domainOwnerClock{domainOwnerNow.Add(time.Second)})
		if err != nil {
			t.Fatal(err)
		}
		outcome, err := port.Commit(context.Background(), revokedCommand)
		if err != nil || outcome.Status != DomainRejected {
			t.Fatalf("revoked-key outcome=%+v err=%v, want rejection", outcome, err)
		}
	})

	t.Run("every drifted binding is rejected", func(t *testing.T) {
		mutations := map[string]func(*DomainCommand){
			"artifact":   func(c *DomainCommand) { c.ArtifactDigest = "sha256:" + strings.Repeat("e", 64) },
			"action":     func(c *DomainCommand) { c.ActionDigest = "sha256:" + strings.Repeat("e", 64) },
			"revision":   func(c *DomainCommand) { c.BaseRevision = "rev:other" },
			"target":     func(c *DomainCommand) { c.Target.ID = "page-99" },
			"actor":      func(c *DomainCommand) { c.ActorID = "actor-99" },
			"workspace":  func(c *DomainCommand) { c.WorkspaceID = "workspace-99" },
			"definition": func(c *DomainCommand) { c.DefinitionDigest = "sha256:" + strings.Repeat("e", 64) },
			"bom":        func(c *DomainCommand) { c.ContractBOMDigest = "sha256:" + strings.Repeat("e", 64) },
			"policy":     func(c *DomainCommand) { c.PolicyDigest = "sha256:" + strings.Repeat("e", 64) },
			"identity":   func(c *DomainCommand) { c.AuthorizationID = "authorization.other" },
		}
		for name, mutate := range mutations {
			t.Run(name, func(t *testing.T) {
				port, err := NewVerifyingDomainPort(DomainConfirmed, keyring, NewMemoryRedemptionStore(), domainOwnerClock{domainOwnerNow.Add(time.Second)})
				if err != nil {
					t.Fatal(err)
				}
				drifted := command
				mutate(&drifted)
				outcome, err := port.Commit(context.Background(), drifted)
				if err != nil || outcome.Status != DomainRejected {
					t.Fatalf("drifted %s outcome=%+v err=%v, want rejection", name, outcome, err)
				}
			})
		}
	})
}
