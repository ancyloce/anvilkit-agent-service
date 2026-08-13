package persistence

import (
	"fmt"
	"strings"
)

type Scope struct {
	WorkspaceID string
	ProjectID   string
}

func (s Scope) Validate() error {
	if strings.TrimSpace(s.WorkspaceID) == "" {
		return fmt.Errorf("repository scope: workspace is required")
	}
	if strings.TrimSpace(s.ProjectID) == "" {
		return fmt.Errorf("repository scope: project is required")
	}
	return nil
}

// OperatorScope can only be constructed with a named audit reason. It is kept
// out of ordinary repositories and is reserved for audited operator tooling.
type OperatorScope struct{ Reason string }

func NewOperatorScope(reason string) (OperatorScope, error) {
	if strings.TrimSpace(reason) == "" {
		return OperatorScope{}, fmt.Errorf("operator scope: audited reason is required")
	}
	return OperatorScope{Reason: reason}, nil
}
