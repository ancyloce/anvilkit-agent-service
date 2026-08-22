package api

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// OperationsManifest is the checked-in account of what the production router
// serves. The repository-level conformance gate reads it and compares it with
// the canonical service description, so the two halves together prove that
// every declared operation has a production handler and that the router serves
// nothing the description does not declare.
const operationsManifest = "operations.json"

type manifest struct {
	ServedPrefix string      `json:"servedPrefix"`
	Operations   []Operation `json:"operations"`
}

// The manifest is generated from the routing table, so it cannot describe
// something the router does not serve. Drift is a failure with the exact
// content to write, because a manifest edited by hand is a description again.
func TestTheRoutedOperationManifestMatchesTheRouter(t *testing.T) {
	rendered, err := json.MarshalIndent(manifest{ServedPrefix: ServedPrefix, Operations: Operations()}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	rendered = append(rendered, '\n')
	recorded, err := os.ReadFile(operationsManifest)
	if err != nil {
		t.Fatalf("the routed-operation manifest is unreadable: %v\nwrite %s with:\n%s", err, operationsManifest, rendered)
	}
	if string(recorded) != string(rendered) {
		t.Fatalf("the routed-operation manifest has drifted from the router\nwrite %s with:\n%s", operationsManifest, rendered)
	}
}

// Every operation the router names resolves to itself when its template is
// addressed, and to nothing when it is addressed wrongly. Without the second
// half a table that matched everything would pass the first.
func TestEveryRoutedOperationResolvesToItselfAndNothingElse(t *testing.T) {
	for _, operation := range Operations() {
		t.Run(operation.ID, func(t *testing.T) {
			parts := concretePath(operation.Template)
			resolved, routed := routedOperation(operation.Method, parts)
			if !routed || resolved.ID != operation.ID {
				t.Fatalf("addressing %s %s resolved to %+v routed=%v", operation.Method, strings.Join(parts, "/"), resolved, routed)
			}
			if _, routed := routedOperation("PATCH", parts); routed {
				t.Fatal("a method the operation does not declare was routed")
			}
			// A path with one segment too many or too few is a different
			// address. It may legitimately be another operation — a run
			// collection and a run resource differ by exactly one segment —
			// but it is never this one.
			longer, routedLonger := routedOperation(operation.Method, append(append([]string(nil), parts...), "extra"))
			if routedLonger && longer.ID == operation.ID {
				t.Fatal("a path with a segment too many resolved to this operation")
			}
			shorter, routedShorter := routedOperation(operation.Method, parts[:len(parts)-1])
			if routedShorter && shorter.ID == operation.ID {
				t.Fatal("a path with a segment too few resolved to this operation")
			}
			// A placeholder accepts one non-empty segment. An empty one is a
			// path naming nothing, and naming nothing is not addressing a
			// resource.
			empty := append([]string(nil), parts...)
			empty[len(empty)-1] = ""
			if _, routed := routedOperation(operation.Method, empty); routed {
				t.Fatal("a path with an empty addressed segment was routed")
			}
		})
	}
}

// The router serves nothing outside its table, and nothing outside the served
// prefix at all.
func TestTheRouterServesNothingOutsideItsTable(t *testing.T) {
	for name, path := range map[string][]string{
		"an undeclared collection":         {"v1", "workspaces", "workspace-01", "invoices"},
		"an undeclared run sub-resource":   {"v1", "workspaces", "workspace-01", "agent-runs", "run-01", "secrets"},
		"an undeclared artifact action":    {"v1", "workspaces", "workspace-01", "artifacts", "artifact-01", "download"},
		"the workspaces collection itself": {"v1", "workspaces"},
		"another version prefix":           {"v2", "workspaces", "workspace-01", "agent-runs"},
		"no prefix at all":                 {"workspaces", "workspace-01", "agent-runs"},
	} {
		t.Run(name, func(t *testing.T) {
			for _, method := range []string{"GET", "POST", "PUT", "DELETE"} {
				if _, routed := routedOperation(method, path); routed {
					t.Fatalf("%s %s was routed", method, strings.Join(path, "/"))
				}
			}
		})
	}
}

// concretePath instantiates one path template with identifiers, split the way
// the router receives them.
func concretePath(template string) []string {
	segments := strings.Split(strings.TrimPrefix(template, "/"), "/")
	parts := []string{strings.TrimPrefix(ServedPrefix, "/")}
	for _, segment := range segments {
		if strings.HasPrefix(segment, "{") && strings.HasSuffix(segment, "}") {
			parts = append(parts, "identifier-"+strings.Trim(segment, "{}"))
			continue
		}
		parts = append(parts, segment)
	}
	return parts
}
