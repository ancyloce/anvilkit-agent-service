package pagixclient

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ancyloce/anvilkit-agent-service/internal/budget"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
)

type fakePort struct {
	writes   []Metadata
	effect   DomainOutcome
	commands int
}

func (p *fakePort) AuthorizedSnapshot(_ context.Context, request SnapshotRequest) (Snapshot, error) {
	return Snapshot{Target: request.Target, BaseRevision: "revision-1"}, nil
}
func (p *fakePort) CheckEntitlement(context.Context, EntitlementRequest) error { return nil }
func (p *fakePort) Reserve(_ context.Context, m Metadata, e budget.Estimate, g budget.Generation) (budget.Reservation, error) {
	p.writes = append(p.writes, m)
	return budget.Reservation{ID: "reservation-1", Generation: g, UpperBoundMicros: e.MaximumCostMicros}, nil
}
func (p *fakePort) Observe(_ context.Context, m Metadata, _ budget.Observation) error {
	p.writes = append(p.writes, m)
	return nil
}
func (p *fakePort) Settle(_ context.Context, m Metadata, s budget.Settlement) (budget.Reservation, error) {
	p.writes = append(p.writes, m)
	return budget.Reservation{ID: s.ReservationID, Released: s.Release}, nil
}
func (p *fakePort) Persist(_ context.Context, command DomainCommand) (DomainOutcome, error) {
	p.commands++
	p.writes = append(p.writes, command.Metadata)
	p.effect = DomainOutcome{OperationID: command.OperationID, AuthorizationID: command.AuthorizationID, Kind: OutcomeApplied, Revision: "revision-2", EventID: "event-1", Recorded: true}
	return DomainOutcome{}, errors.New("ambiguous timeout")
}
func (p *fakePort) Effect(_ context.Context, workspace, operation string) (DomainOutcome, bool, error) {
	return p.effect, p.effect.OperationID == operation, nil
}

func metadata() Metadata {
	return Metadata{WorkloadIdentity: "spiffe://anvilkit/agent-service", Traceparent: "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01", WorkspaceID: "workspace-01", ProjectID: "project-01", ActorID: "actor-01", Operation: "page-persistence", IdempotencyKey: "key-01", RequestDigest: "sha256:" + strings.Repeat("a", 64)}
}

func TestEveryWriteCarriesIdentityTraceScopeAndIdempotency(t *testing.T) {
	port := &fakePort{}
	client, err := New(port, NewMemoryInbox())
	if err != nil {
		t.Fatal(err)
	}
	m := metadata()
	ctx := context.Background()
	_, _ = client.Reserve(ctx, m, budget.Estimate{MaximumCostMicros: 10}, 1)
	_ = client.Observe(ctx, m, budget.Observation{})
	_, _ = client.Settle(ctx, m, budget.Settlement{ReservationID: "reservation-1", Release: true})
	for _, write := range port.writes {
		if err := write.Validate(); err != nil {
			t.Fatalf("write metadata missing: %#v", write)
		}
	}
	bad := m
	bad.WorkloadIdentity = ""
	if _, err := client.Reserve(ctx, bad, budget.Estimate{}, 1); err == nil {
		t.Fatal("write without workload identity escaped")
	}
}

func TestAmbiguousPersistReconcilesEffectWithoutDuplicateCommand(t *testing.T) {
	for _, scenario := range []string{"timeout", "http-500", "ambiguous-disconnect"} {
		t.Run(scenario, func(t *testing.T) {
			port := &fakePort{}
			client, _ := New(port, NewMemoryInbox())
			command := DomainCommand{Metadata: metadata(), OperationID: "operation-01", AuthorizationJWS: "signed.jws.value", AuthorizationID: "authorization-01", ActionDigest: "sha256:" + strings.Repeat("b", 64), ArtifactDigest: "sha256:" + strings.Repeat("c", 64), ExpectedRevision: "revision-1"}
			result, err := client.Persist(context.Background(), command)
			if err != nil || result.Kind != OutcomeApplied {
				t.Fatalf("uncertainty not reconciled: %#v %v", result, err)
			}
			if port.commands != 1 {
				t.Fatalf("duplicate command count=%d", port.commands)
			}
		})
	}
}

func TestAuthoritativeInboxDeduplicatesAndRejectsChangedReplay(t *testing.T) {
	client, _ := New(&fakePort{}, NewMemoryInbox())
	event := DomainEvent{MessageID: "message-01", OperationID: "operation-01", AuthorizationID: "authorization-01", Traceparent: metadata().Traceparent, Outcome: DomainOutcome{OperationID: "operation-01", AuthorizationID: "authorization-01", Kind: OutcomeConflict, Recorded: true}}
	_, accepted, err := client.Consume(context.Background(), event)
	if err != nil || !accepted {
		t.Fatalf("first event rejected: %v", err)
	}
	_, accepted, err = client.Consume(context.Background(), event)
	if err != nil || accepted {
		t.Fatalf("duplicate event accepted: %v", err)
	}
	changed := event
	changed.Outcome.Kind = OutcomeApplied
	_, _, err = client.Consume(context.Background(), changed)
	var details problem.Details
	if !errors.As(err, &details) || details.Code != string(problem.CodeIdempotencyConflict) {
		t.Fatalf("changed replay not rejected: %v", err)
	}
}

func TestSnapshotAndEntitlementAreAuthorizedAndScoped(t *testing.T) {
	port := &fakePort{}
	client, _ := New(port, NewMemoryInbox())
	m := metadata()
	snapshot, err := client.Snapshot(context.Background(), SnapshotRequest{Metadata: m, Target: Target{TargetType: "page", TargetID: "page-01", WorkspaceID: m.WorkspaceID}})
	if err != nil || snapshot.BaseRevision == "" {
		t.Fatalf("snapshot: %#v %v", snapshot, err)
	}
	if err := client.Entitlement(context.Background(), EntitlementRequest{Metadata: m, Capability: "agent.page.apply"}); err != nil {
		t.Fatal(err)
	}
	mismatch := m
	mismatch.WorkspaceID = "other"
	_, err = client.Snapshot(context.Background(), SnapshotRequest{Metadata: mismatch, Target: Target{WorkspaceID: "workspace-01"}})
	if err == nil {
		t.Fatal("cross-scope snapshot accepted")
	}
}
