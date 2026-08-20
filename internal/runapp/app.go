// Package runapp is the application boundary between HTTP transport and run,
// event, and authorization modules.
package runapp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/ancyloce/anvilkit-agent-service/internal/auth"
	"github.com/ancyloce/anvilkit-agent-service/internal/authority"
	"github.com/ancyloce/anvilkit-agent-service/internal/canonical"
	"github.com/ancyloce/anvilkit-agent-service/internal/events"
	"github.com/ancyloce/anvilkit-agent-service/internal/interrupts"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/runs"
)

// AuthorityProvider is the single current-authority port, shared with the
// execution pipeline and the interrupt authority. Creating a run is itself a
// guarded boundary: authority must be active and its material complete.
type AuthorityProvider = authority.Source
type App struct {
	validator    *auth.Validator
	runs         *runs.Service
	events       events.Reader
	streamConfig events.StreamConfig
	authority    AuthorityProvider
	interrupts   *interrupts.Service
}

func (a *App) WithInterrupts(service *interrupts.Service) *App { a.interrupts = service; return a }

func New(validator *auth.Validator, runService *runs.Service, eventReader events.Reader, streamConfig events.StreamConfig, authority AuthorityProvider) *App {
	return &App{validator: validator, runs: runService, events: eventReader, streamConfig: streamConfig, authority: authority}
}

type Representation struct {
	Body     []byte
	ETag     string
	Replayed bool
	Digest   string
}

func (a *App) Create(ctx context.Context, claims auth.Claims, workspaceID, key, digest, traceparent string, raw []byte) (Representation, error) {
	scope, err := a.scope(ctx, claims, auth.OpCreateRun, workspaceID)
	if err != nil {
		return Representation{}, err
	}
	current, err := a.authority.Current(ctx, scope.AuthorityScope())
	if err != nil {
		return Representation{}, fmt.Errorf("resolve create authority: %w", err)
	}
	if !current.Active() || !current.MaterialComplete() {
		denied := problem.New(problem.CodeAuthorityStale, "")
		denied.Detail = "current authority does not permit creating a run"
		return Representation{}, denied
	}
	outcome, err := a.runs.Create(ctx, runs.CreateInput{Scope: scope, Key: key, ClaimedDigest: digest, Traceparent: traceparent, Raw: raw, Authority: current})
	if err != nil {
		return Representation{}, err
	}
	return Representation{Body: outcome.Bytes, ETag: outcome.Snapshot.ETag(), Replayed: outcome.Replayed, Digest: digest}, nil
}
func (a *App) Get(ctx context.Context, claims auth.Claims, workspaceID, runID string) (Representation, error) {
	scope, err := a.scope(ctx, claims, auth.OpGetRun, workspaceID)
	if err != nil {
		return Representation{}, err
	}
	snapshot, err := a.runs.Get(ctx, scope, runs.ID(runID))
	if err != nil {
		return Representation{}, err
	}
	body, err := json.Marshal(snapshot)
	if err != nil {
		return Representation{}, err
	}
	return Representation{Body: body, ETag: snapshot.ETag()}, nil
}
func (a *App) List(ctx context.Context, claims auth.Claims, workspaceID, cursor string, limit int, state string) (Representation, error) {
	scope, err := a.scope(ctx, claims, auth.OpListRuns, workspaceID)
	if err != nil {
		return Representation{}, err
	}
	page, err := a.runs.List(ctx, scope, runs.ListOptions{Cursor: cursor, Limit: limit, State: runs.State(state)})
	if err != nil {
		return Representation{}, err
	}
	body, err := json.Marshal(page)
	return Representation{Body: body}, err
}
func (a *App) Snapshot(ctx context.Context, claims auth.Claims, workspaceID, runID string) (events.SnapshotProjection, error) {
	scope, err := a.scope(ctx, claims, auth.OpGetRun, workspaceID)
	if err != nil {
		return events.SnapshotProjection{}, err
	}
	return a.events.Snapshot(ctx, events.Scope{WorkspaceID: scope.WorkspaceID, ProjectID: scope.ProjectID}, runID)
}
func (a *App) Stream(ctx context.Context, claims auth.Claims, workspaceID, runID, cursor string, response http.ResponseWriter) error {
	scope, err := a.scope(ctx, claims, auth.OpStreamEvents, workspaceID)
	if err != nil {
		return err
	}
	authority := &streamAuthority{validator: a.validator, claims: claims}
	stream, err := events.NewStream(a.events, authority, a.streamConfig)
	if err != nil {
		return err
	}
	return stream.Serve(ctx, response, events.Scope{WorkspaceID: scope.WorkspaceID, ProjectID: scope.ProjectID}, runID, cursor)
}
func (a *App) Transition(ctx context.Context, claims auth.Claims, operation auth.Operation, workspaceID, runID, etag string, command runs.Command) (Representation, error) {
	scope, err := a.scope(ctx, claims, operation, workspaceID)
	if err != nil {
		return Representation{}, err
	}
	version, err := runs.ParseETag(etag, runs.ID(runID))
	if err != nil {
		return Representation{}, err
	}
	snapshot, err := a.runs.Transition(ctx, scope, runs.ID(runID), version, command)
	if err != nil {
		return Representation{}, err
	}
	body, _ := json.Marshal(snapshot)
	return Representation{Body: body, ETag: snapshot.ETag()}, nil
}

type ControlInput struct {
	WorkspaceID, RunID, ETag, Key, Digest, Traceparent string
}

func (a *App) RespondInput(ctx context.Context, claims auth.Claims, input ControlInput, command interrupts.InputResponseCommand) (Representation, error) {
	write, err := a.controlWrite(ctx, claims, auth.OpRespondInput, input)
	if err != nil {
		return Representation{}, err
	}
	bodyCommand := struct {
		RequestVersion uint64          `json:"requestVersion"`
		Value          json.RawMessage `json:"value"`
	}{command.RequestVersion, command.Value}
	if err := verifyControlDigest(input.Digest, bodyCommand); err != nil {
		return Representation{}, err
	}
	result, err := a.interrupts.RespondInput(ctx, write, command)
	return controlRepresentation(result.Snapshot, result.Replayed, err)
}
func (a *App) DecideApproval(ctx context.Context, claims auth.Claims, input ControlInput, command interrupts.ApprovalDecisionCommand) (Representation, error) {
	write, err := a.controlWrite(ctx, claims, auth.OpDecideApproval, input)
	if err != nil {
		return Representation{}, err
	}
	bodyCommand := struct {
		DecisionVersion uint64                  `json:"decisionVersion"`
		Decision        interrupts.DecisionKind `json:"decision"`
		Reason          string                  `json:"reason,omitempty"`
	}{command.RequestVersion, command.Decision, command.Reason}
	if err := verifyControlDigest(input.Digest, bodyCommand); err != nil {
		return Representation{}, err
	}
	result, err := a.interrupts.DecideApproval(ctx, write, command)
	return controlRepresentation(result.Snapshot, result.Replayed, err)
}
func (a *App) Cancel(ctx context.Context, claims auth.Claims, input ControlInput) (Representation, error) {
	write, err := a.controlWrite(ctx, claims, auth.OpCancel, input)
	if err != nil {
		return Representation{}, err
	}
	if err := verifyControlDigest(input.Digest, struct{}{}); err != nil {
		return Representation{}, err
	}
	result, err := a.interrupts.Cancel(ctx, write)
	return controlRepresentation(result.Snapshot, result.Replayed, err)
}
func (a *App) Retry(ctx context.Context, claims auth.Claims, input ControlInput) (Representation, error) {
	write, err := a.controlWrite(ctx, claims, auth.OpRetry, input)
	if err != nil {
		return Representation{}, err
	}
	if err := verifyControlDigest(input.Digest, struct{}{}); err != nil {
		return Representation{}, err
	}
	result, err := a.interrupts.Retry(ctx, write)
	return controlRepresentation(result.Snapshot, result.Replayed, err)
}
func (a *App) Discard(ctx context.Context, claims auth.Claims, input ControlInput) (Representation, error) {
	write, err := a.controlWrite(ctx, claims, auth.OpDiscard, input)
	if err != nil {
		return Representation{}, err
	}
	if err := verifyControlDigest(input.Digest, struct{}{}); err != nil {
		return Representation{}, err
	}
	result, err := a.interrupts.Discard(ctx, write)
	return controlRepresentation(result.Snapshot, result.Replayed, err)
}
func (a *App) controlWrite(ctx context.Context, claims auth.Claims, operation auth.Operation, input ControlInput) (interrupts.Write, error) {
	if a.interrupts == nil {
		return interrupts.Write{}, problem.New(problem.CodeInfrastructureUnavailable, "")
	}
	scope, err := a.scope(ctx, claims, operation, input.WorkspaceID)
	if err != nil {
		return interrupts.Write{}, err
	}
	version, err := runs.ParseETag(input.ETag, runs.ID(input.RunID))
	if err != nil {
		return interrupts.Write{}, err
	}
	if input.Key == "" || len(input.Key) > 256 || !validTraceparent(input.Traceparent) {
		value := problem.New(problem.CodeRequestInvalid, "")
		value.Detail = "control write requires bounded idempotency key and traceparent"
		return interrupts.Write{}, value
	}
	return interrupts.Write{Scope: scope, RunID: runs.ID(input.RunID), ExpectedVersion: version, IdempotencyKey: input.Key, CanonicalDigest: input.Digest, Traceparent: input.Traceparent}, nil
}
func controlRepresentation(snapshot runs.Snapshot, replayed bool, err error) (Representation, error) {
	if err != nil {
		return Representation{}, err
	}
	body, marshalErr := json.Marshal(snapshot)
	if marshalErr != nil {
		return Representation{}, marshalErr
	}
	return Representation{Body: body, ETag: snapshot.ETag(), Replayed: replayed}, nil
}
func verifyControlDigest(claimed string, command any) error {
	raw, err := json.Marshal(command)
	if err != nil {
		return err
	}
	digest, err := canonical.Digest(raw)
	if err != nil {
		return err
	}
	if claimed == "" || claimed != digest {
		value := problem.New(problem.CodeRequestInvalid, "")
		value.Detail = "X-AnvilKit-Request-Digest does not match the canonical control command"
		return value
	}
	return nil
}
func (a *App) scope(ctx context.Context, claims auth.Claims, operation auth.Operation, workspaceID string) (runs.Scope, error) {
	scope, err := a.validator.Authorize(ctx, claims, operation)
	if err != nil {
		return runs.Scope{}, err
	}
	if scope.WorkspaceID != workspaceID {
		return runs.Scope{}, authNonDisclosure()
	}
	return scope, nil
}

type streamAuthority struct {
	validator *auth.Validator
	claims    auth.Claims
}

func (a *streamAuthority) Revalidate(ctx context.Context) error {
	return a.validator.Revalidate(ctx, a.claims, auth.OpStreamEvents)
}
func ParseLimit(value string) (int, error) {
	if value == "" {
		return 50, nil
	}
	limit, err := strconv.Atoi(value)
	if err != nil || limit < 1 || limit > 100 {
		return 0, fmt.Errorf("limit must be between 1 and 100")
	}
	return limit, nil
}
func authNonDisclosure() error { return problem.New(problem.CodeResourceNotFound, "") }

func validTraceparent(value string) bool {
	if len(value) != 55 || value[2] != '-' || value[35] != '-' || value[52] != '-' {
		return false
	}
	for index, character := range value {
		if index == 2 || index == 35 || index == 52 {
			continue
		}
		if !lowerHexDigit(character) {
			return false
		}
	}
	return value[:2] != "ff" && value[3:35] != strings.Repeat("0", 32) && value[36:52] != strings.Repeat("0", 16)
}

// lowerHexDigit reports whether the character is a lower-case hexadecimal
// digit. Digest and trace identities are lower-case only, so an upper-case
// digit is rejected rather than normalized.
func lowerHexDigit(character rune) bool {
	return character >= '0' && character <= '9' || character >= 'a' && character <= 'f'
}
