package runapp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
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

// Ensure starts the canonical AgentRunWorkflow for the run's execution
// generation without awaiting its outcome. Repeating a start is idempotent.
func (s *RuntimeStarter) Ensure(ctx context.Context, start runs.Start) error {
	return s.runtime.StartRun(ctx, workflow.RunInput{
		Key:         workflow.RunKey{RunID: string(start.RunID), Generation: start.Generation},
		Scope:       workflow.Scope{WorkspaceID: start.Scope.WorkspaceID, ProjectID: start.Scope.ProjectID, ActorID: start.Scope.ActorID},
		Traceparent: start.Traceparent,
	})
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
