package runner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/ancyloce/anvilkit-agent-service/internal/contextcompiler"
)

// compileContext is the first stage of a turn: the authorized trust layers a
// runtime may be disclosed, compiled under the definition's pinned guardrail
// and redaction policy and bounded by the configured token budget.
//
// It runs before any task exists. Compiling after admitting the work would
// mean a task could be dispatched with nothing to execute, and compiling
// content the guardrail policy would have removed is exactly the disclosure
// this stage exists to prevent.
func (r *Runner) compileContext(ctx context.Context, instruction string, request TurnRequest) ([]byte, error) {
	sources := []contextcompiler.Source{
		{ID: "instruction", Trust: contextcompiler.System, Classification: contextcompiler.Internal, Content: instruction, WorkspaceID: request.Run.WorkspaceID, TokenBudget: r.limits.ContextTokens / 4},
		{ID: "task", Trust: contextcompiler.Agent, Classification: contextcompiler.Internal, Content: taskDescription(request), WorkspaceID: request.Run.WorkspaceID, TokenBudget: r.limits.ContextTokens / 4},
	}
	if len(request.InputValue) > 0 {
		sources = append(sources, contextcompiler.Source{ID: "input-response", Trust: contextcompiler.User, Classification: contextcompiler.Internal, Content: string(request.InputValue), WorkspaceID: request.Run.WorkspaceID, TokenBudget: r.limits.ContextTokens / 8})
	}
	if request.ReviewReason != "" {
		sources = append(sources, contextcompiler.Source{ID: "review-guidance", Trust: contextcompiler.User, Classification: contextcompiler.Internal, Content: request.ReviewReason, WorkspaceID: request.Run.WorkspaceID, TokenBudget: r.limits.ContextTokens / 8})
	}
	for index, note := range boundedNotes(request.Notes) {
		sources = append(sources, contextcompiler.Source{ID: fmt.Sprintf("note-%02d", index), Trust: contextcompiler.ToolOutput, Classification: contextcompiler.Internal, Content: note, WorkspaceID: request.Run.WorkspaceID, TokenBudget: r.limits.ContextTokens / 16})
	}
	compiled, err := r.compiler.Compile(ctx, contextcompiler.Request{
		WorkspaceID:     request.Run.WorkspaceID,
		ProjectID:       request.Run.ProjectID,
		RunID:           request.Run.RunID,
		Sources:         sources,
		Policy:          contextcompiler.PolicyReference{PolicyID: request.Definition.GuardrailPolicy.PolicyID, Version: request.Definition.GuardrailPolicy.Version, Digest: request.Definition.GuardrailPolicy.Digest},
		RedactionPolicy: contextcompiler.PolicyReference{PolicyID: request.Definition.GuardrailPolicy.PolicyID, Version: request.Definition.GuardrailPolicy.Version, Digest: request.Definition.GuardrailPolicy.Digest},
		TotalTokens:     r.limits.ContextTokens,
		CompiledAt:      r.clock.Now(),
	})
	if err != nil {
		return nil, err
	}
	var builder strings.Builder
	for _, layer := range compiled.Disclosure {
		builder.WriteString("[" + string(layer.Trust) + ":" + layer.LayerID + "]\n")
		builder.WriteString(layer.Content)
		builder.WriteString("\n")
	}
	return []byte(builder.String()), nil
}

func taskDescription(request TurnRequest) string {
	return fmt.Sprintf("phase=%s turn=%d domain=%s operation=%s target=%s:%s", request.Phase, request.Turn, request.Run.Domain, request.Run.Operation, request.Run.TargetType, request.Run.TargetID)
}

func boundedNotes(notes []string) []string {
	const maximumNotes = 16
	if len(notes) <= maximumNotes {
		return notes
	}
	return notes[len(notes)-maximumNotes:]
}

// contentDigest is the identity of a compiled disclosure. The task pins it, so
// what a runtime executes against is provably the disclosure this service
// compiled for that attempt and not a later one.
func contentDigest(content []byte) string {
	sum := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(sum[:])
}
