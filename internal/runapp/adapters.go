package runapp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/interrupts"
	"github.com/ancyloce/anvilkit-agent-service/internal/runs"
	"github.com/ancyloce/anvilkit-agent-service/internal/workflow"
)

type RuntimeStarter struct{ runtime workflow.Runtime }

func NewRuntimeStarter(runtime workflow.Runtime) *RuntimeStarter {
	return &RuntimeStarter{runtime: runtime}
}
func (s *RuntimeStarter) Ensure(ctx context.Context, start runs.Start) error {
	_, err := s.runtime.Execute(ctx, workflow.Request{WorkflowID: workflow.ID(start.WorkflowID), Version: start.Version, Scope: workflow.Scope{WorkspaceID: start.Scope.WorkspaceID, ProjectID: start.Scope.ProjectID}, State: json.RawMessage(fmt.Sprintf(`{"runId":%q,"version":%d}`, start.RunID, start.Version))})
	return err
}

type RandomIDs struct{}

func (RandomIDs) NewID() (runs.ID, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return runs.ID("run." + hex.EncodeToString(raw)), nil
}

func (RandomIDs) NewRequestID() (interrupts.RequestID, error) {
	id, err := randomHex("request.")
	return interrupts.RequestID(id), err
}
func (RandomIDs) NewRunID() (runs.ID, error) { return RandomIDs{}.NewID() }
func randomHex(prefix string) (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(raw), nil
}

type SystemClock struct{}

func (SystemClock) Now() time.Time { return time.Now() }

type StaticAuthority struct{ Value runs.Authority }

func (a StaticAuthority) Current(context.Context, runs.Scope) (runs.Authority, error) {
	if len(a.Value.ContractBOM) == 0 || len(a.Value.Policy) == 0 || len(a.Value.Budget) == 0 {
		return runs.Authority{}, fmt.Errorf("authority material is unavailable")
	}
	return a.Value, nil
}
