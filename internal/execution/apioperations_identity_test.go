package execution

import (
	"reflect"
	"strings"
	"testing"

	"github.com/ancyloce/anvilkit-agent-service/internal/runs"
)

// The durable operation identity one apply-authorization issuance is recorded
// under must cover every field of the canonical command.
//
// The media type, the size, and the target's own workspace and project were
// carried into the issuance but left out of its identity. Two requests
// differing only in those fields therefore collided on one durable operation,
// and the second silently received a capability minted for the first — which
// is the opposite of what an idempotency key is for. Every field is varied
// here, one at a time, and each variation has to be a different operation.
func TestApplyAuthorizationOperationIdentityCoversEveryDeclaredField(t *testing.T) {
	snapshot := runs.Snapshot{
		RunID:       "run.identity",
		WorkspaceID: "workspace.identity",
		Target:      runs.Target{Type: "page", ID: "page.one", WorkspaceID: "workspace.identity", ProjectID: "project.identity"},
	}
	base := ApplyAuthorizationIntent{
		RunID: "run.identity", ActionDigest: "sha256:" + strings.Repeat("1", 64),
		ArtifactID: "artifact.one", ArtifactDigest: "sha256:" + strings.Repeat("2", 64),
		ArtifactMedia: "application/json", ArtifactSize: 4096,
		TargetType: "page", TargetID: "page.one",
		TargetWorkspace: "workspace.identity", TargetProject: "project.identity",
		BaseRevision: "rev:request.0001", ApprovalRequestID: "request.0001",
		ApprovalDecisionVersion: 3, ExpectedRunRevision: 7,
	}
	identity := applyAuthorizationOperationKey(snapshot, base)
	if applyAuthorizationOperationKey(snapshot, base) != identity {
		t.Fatal("the same declared decision produced two durable operation identities")
	}
	seen := map[string]string{identity: "the unaltered command"}

	for name, vary := range map[string]func(*ApplyAuthorizationIntent){
		"the run":               func(i *ApplyAuthorizationIntent) { i.RunID = "run.other" },
		"the action":            func(i *ApplyAuthorizationIntent) { i.ActionDigest = "sha256:" + strings.Repeat("9", 64) },
		"the artifact identity": func(i *ApplyAuthorizationIntent) { i.ArtifactID = "artifact.two" },
		"the artifact digest":   func(i *ApplyAuthorizationIntent) { i.ArtifactDigest = "sha256:" + strings.Repeat("8", 64) },
		"the media type":        func(i *ApplyAuthorizationIntent) { i.ArtifactMedia = "text/html" },
		"the size":              func(i *ApplyAuthorizationIntent) { i.ArtifactSize = 8192 },
		"the target type":       func(i *ApplyAuthorizationIntent) { i.TargetType = "component" },
		"the target":            func(i *ApplyAuthorizationIntent) { i.TargetID = "page.two" },
		"the target workspace":  func(i *ApplyAuthorizationIntent) { i.TargetWorkspace = "workspace.other" },
		"the target project":    func(i *ApplyAuthorizationIntent) { i.TargetProject = "project.other" },
		"the base revision":     func(i *ApplyAuthorizationIntent) { i.BaseRevision = "rev:request.0002" },
		"the approval":          func(i *ApplyAuthorizationIntent) { i.ApprovalRequestID = "request.0002" },
		"the decision version":  func(i *ApplyAuthorizationIntent) { i.ApprovalDecisionVersion = 4 },
		"the run revision":      func(i *ApplyAuthorizationIntent) { i.ExpectedRunRevision = 8 },
	} {
		altered := base
		vary(&altered)
		value := applyAuthorizationOperationKey(snapshot, altered)
		if previous, collision := seen[value]; collision {
			t.Fatalf("varying %s collided on the durable operation identity of %s", name, previous)
		}
		seen[value] = name
	}

	// The tenant and run the issuance is read under are part of the identity
	// too, so the same declared command elsewhere is a different operation.
	for name, vary := range map[string]func(*runs.Snapshot){
		"another workspace": func(s *runs.Snapshot) { s.WorkspaceID = "workspace.other" },
		"another project":   func(s *runs.Snapshot) { s.Target.ProjectID = "project.other" },
		"another run":       func(s *runs.Snapshot) { s.RunID = "run.other" },
	} {
		elsewhere := snapshot
		vary(&elsewhere)
		value := applyAuthorizationOperationKey(elsewhere, base)
		if previous, collision := seen[value]; collision {
			t.Fatalf("%s collided on the durable operation identity of %s", name, previous)
		}
		seen[value] = name
	}
}

// Every field of the intent has to reach the identity, and a field added later
// has to reach it too. The struct is walked rather than listed so a new
// declared fact cannot be added to the command and left out of the identity
// without this failing.
func TestEveryApplyAuthorizationIntentFieldReachesTheOperationIdentity(t *testing.T) {
	snapshot := runs.Snapshot{
		RunID:       "run.identity",
		WorkspaceID: "workspace.identity",
		Target:      runs.Target{Type: "page", ID: "page.one", WorkspaceID: "workspace.identity", ProjectID: "project.identity"},
	}
	base := ApplyAuthorizationIntent{
		RunID: "run.identity", ActionDigest: "digest.action",
		ArtifactID: "artifact.one", ArtifactDigest: "digest.artifact",
		ArtifactMedia: "application/json", ArtifactSize: 4096,
		TargetType: "page", TargetID: "page.one",
		TargetWorkspace: "workspace.identity", TargetProject: "project.identity",
		BaseRevision: "rev:request.0001", ApprovalRequestID: "request.0001",
		ApprovalDecisionVersion: 3, ExpectedRunRevision: 7,
	}
	identity := applyAuthorizationOperationKey(snapshot, base)
	value := reflect.ValueOf(&base).Elem()
	for index := 0; index < value.NumField(); index++ {
		altered := base
		field := reflect.ValueOf(&altered).Elem().Field(index)
		switch field.Kind().String() {
		case "string":
			field.SetString(field.String() + ".altered")
		case "int64":
			field.SetInt(field.Int() + 1)
		case "uint64":
			field.SetUint(field.Uint() + 1)
		default:
			t.Fatalf("field %s has kind %s, which this walk does not know how to alter", value.Type().Field(index).Name, field.Kind())
		}
		if applyAuthorizationOperationKey(snapshot, altered) == identity {
			t.Fatalf("altering %s left the durable operation identity unchanged", value.Type().Field(index).Name)
		}
	}
}
