package runapp

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/auth"
	"github.com/ancyloce/anvilkit-agent-service/internal/authority"
	"github.com/ancyloce/anvilkit-agent-service/internal/events"
	"github.com/ancyloce/anvilkit-agent-service/internal/journal"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/runs"
)

type clock struct{ now time.Time }

func (c clock) Now() time.Time { return c.now }

type trust struct{}

func (trust) KeyActive(context.Context, string) (bool, error)                { return true, nil }
func (trust) SubjectActive(context.Context, string) (bool, error)            { return true, nil }
func (trust) DelegationActive(context.Context, string, string) (bool, error) { return true, nil }

type store struct {
	snapshot        runs.Snapshot
	transitionCalls int
}

func (s *store) Create(context.Context, runs.CreateRecord) (runs.CreateOutcome, error) {
	return runs.CreateOutcome{}, nil
}
func (s *store) Get(_ context.Context, scope runs.Scope, _ runs.ID) (runs.Snapshot, error) {
	if scope.WorkspaceID != "workspace" {
		return runs.Snapshot{}, problem.New(problem.CodeResourceNotFound, "")
	}
	return s.snapshot, nil
}
func (s *store) List(context.Context, runs.Scope, runs.ListOptions) (runs.Page, error) {
	return runs.Page{Items: []runs.Snapshot{s.snapshot}}, nil
}
func (s *store) Transition(_ context.Context, _ runs.Scope, _ runs.ID, version uint64, _ runs.Command) (runs.Snapshot, error) {
	if version != s.snapshot.Version {
		return runs.Snapshot{}, problem.New(problem.CodeVersionConflict, "")
	}
	s.transitionCalls++
	s.snapshot.Version++
	return s.snapshot, nil
}

type starter struct{}

func (starter) Ensure(context.Context, runs.Start) error { return nil }

type ids struct{}

func (ids) NewID() (runs.ID, error) { return "run", nil }

type eventReader struct{}

func (eventReader) Replay(context.Context, events.ReplayRequest) (events.ReplayPage, error) {
	return events.ReplayPage{}, nil
}
func (eventReader) Snapshot(context.Context, events.Scope, string) (events.SnapshotProjection, error) {
	return events.SnapshotProjection{Cursor: "cursor"}, nil
}
func (eventReader) Wait(context.Context, events.Scope, string, uint64, time.Duration) error {
	return nil
}

type appAuthoritySource struct{}

func (appAuthoritySource) Current(context.Context, authority.Scope) (authority.Current, error) {
	return testAuthority(), nil
}

// testAuthority is a complete, active current-authority observation.
func testAuthority() authority.Current {
	return authority.Current{
		Definition:       []byte(`{"definitionId":"definition.test","definitionDigest":"sha256:` + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" + `"}`),
		ContractBOM:      []byte(`{"bom":"test"}`),
		Policy:           []byte(`{"policyId":"policy.test","version":"v1"}`),
		Budget:           []byte(`{"budget":"test"}`),
		WorkspaceActive:  true,
		ActorActive:      true,
		PermissionActive: true,
		PolicyActive:     true,
	}
}

func TestServerScopeComesOnlyFromVerifiedClaimsAndCrossWorkspaceIs404(t *testing.T) {
	now := time.Now()
	validator, _ := auth.NewValidator(auth.Config{Issuers: []string{"issuer"}, Audience: "agent", MaximumClockSkew: time.Second}, trust{}, clock{now})
	runStore := &store{snapshot: runs.Snapshot{RunID: "run", WorkspaceID: "workspace", Version: 3}}
	app := New(validator, runs.NewService(runStore, starter{}, ids{}, clock{now}, journal.NewMemoryStore(), runs.AdmitFunc(func(context.Context, runs.Scope) error { return nil })), eventReader{}, events.StreamConfig{Heartbeat: time.Second, Revalidation: time.Second, ReplayLimit: 10, Bounds: events.Bounds{MaximumBytes: 1000, MaximumFields: 10, MaximumFieldBytes: 100}}, appAuthoritySource{})
	claims := auth.Claims{Verified: true, Source: auth.SourceWorkload, Issuer: "issuer", Audience: "agent", Subject: "actor", ActorID: "actor", WorkspaceID: "workspace", ProjectID: "project", Purpose: "agent", KeyID: "key", Scopes: []string{auth.ScopeRead, auth.ScopeWrite}, ExpiresAt: now.Add(time.Hour)}
	result, err := app.Get(context.Background(), claims, "workspace", "run")
	if err != nil || result.ETag != `"run:v3"` {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	_, err = app.Get(context.Background(), claims, "other", "run")
	assertProblem(t, err, problem.CodeResourceNotFound)
	browser := claims
	browser.Source = auth.SourceBrowser
	_, err = app.Get(context.Background(), browser, "workspace", "run")
	assertProblem(t, err, problem.CodeAuthenticationInvalid)
}

func TestStrongETagPreconditionAllowsOneMutation(t *testing.T) {
	now := time.Now()
	validator, _ := auth.NewValidator(auth.Config{Issuers: []string{"issuer"}, Audience: "agent"}, trust{}, clock{now})
	runStore := &store{snapshot: runs.Snapshot{RunID: "run", WorkspaceID: "workspace", Version: 3}}
	app := New(validator, runs.NewService(runStore, starter{}, ids{}, clock{now}, journal.NewMemoryStore(), runs.AdmitFunc(func(context.Context, runs.Scope) error { return nil })), eventReader{}, events.StreamConfig{}, appAuthoritySource{})
	claims := auth.Claims{Verified: true, Source: auth.SourceWorkload, Issuer: "issuer", Audience: "agent", Subject: "actor", ActorID: "actor", WorkspaceID: "workspace", ProjectID: "project", Purpose: "agent", KeyID: "key", Scopes: []string{auth.ScopeWrite}, ExpiresAt: now.Add(time.Hour)}
	first, err := app.Transition(context.Background(), claims, auth.OpCancel, "workspace", "run", `"run:v3"`, runs.Command{Kind: runs.RequestCancellation, Traceparent: "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"})
	if err != nil || first.ETag != `"run:v4"` {
		t.Fatalf("first=%#v err=%v", first, err)
	}
	_, err = app.Transition(context.Background(), claims, auth.OpCancel, "workspace", "run", `"run:v3"`, runs.Command{Kind: runs.RequestCancellation, Traceparent: "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"})
	assertProblem(t, err, problem.CodeVersionConflict)
	if runStore.transitionCalls != 1 {
		t.Fatalf("transition calls=%d", runStore.transitionCalls)
	}
}

func assertProblem(t *testing.T, err error, code problem.Code) {
	t.Helper()
	var details problem.Details
	if !errors.As(err, &details) || details.Code != string(code) {
		t.Fatalf("got %v want %s", err, code)
	}
}
