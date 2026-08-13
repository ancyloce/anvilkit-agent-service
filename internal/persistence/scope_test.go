package persistence

import "testing"

func TestScopeRejectsUnscopedAccess(t *testing.T) {
	for _, scope := range []Scope{{}, {WorkspaceID: "workspace"}, {ProjectID: "project"}} {
		if scope.Validate() == nil {
			t.Fatalf("scope %#v should fail", scope)
		}
	}
	if err := (Scope{WorkspaceID: "workspace", ProjectID: "project"}).Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestOperatorScopeRequiresAuditedReason(t *testing.T) {
	if _, err := NewOperatorScope(""); err == nil {
		t.Fatal("empty operator reason accepted")
	}
}
