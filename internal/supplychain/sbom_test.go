package supplychain

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"
)

// The committed bill of materials is release evidence, so it must describe
// the module graph the service builds from today. It once recorded the
// durable runtime at a superseded version while the module file already
// required the current one, which this check makes impossible to miss.
func TestCommittedBillOfMaterialsMatchesTheModuleGraph(t *testing.T) {
	if err := Verify("../.."); err != nil {
		requireRepositoryHistory(t, err)
		t.Fatal(err)
	}
}

// requireRepositoryHistory skips a check that needs the repository's history
// when the tree being measured has none — a materialised clean checkout, for
// instance. It never converts a real failure into a skip.
func requireRepositoryHistory(t *testing.T, err error) {
	t.Helper()
	if errors.Is(err, NoRepositoryError{}) {
		t.Skip("this tree carries no repository history, so the recorded application revision cannot be resolved here")
	}
}

// The durable workflow runtime is pinned by decision, so its recorded
// version is asserted explicitly rather than only through the generic graph
// comparison.
func TestBillOfMaterialsRecordsThePinnedDurableRuntime(t *testing.T) {
	document, err := LoadBillOfMaterials("../..")
	if err != nil {
		t.Fatal(err)
	}
	_, requirements, err := LoadRequirements("../..")
	if err != nil {
		t.Fatal(err)
	}
	const runtimeModule = "github.com/dbos-inc/dbos-transact-golang"
	var pinned string
	for _, requirement := range requirements {
		if requirement.Path == runtimeModule {
			pinned = requirement.Version
		}
	}
	if pinned == "" {
		t.Fatalf("%s is not a declared requirement", runtimeModule)
	}
	if !strings.HasPrefix(pinned, "v1.") {
		t.Fatalf("the durable runtime is pinned to %s, want the 1.x line", pinned)
	}
	for _, component := range document.Components {
		if component.Name == runtimeModule {
			if component.Version != pinned {
				t.Fatalf("bill of materials records the durable runtime at %s, want %s", component.Version, pinned)
			}
			return
		}
	}
	t.Fatalf("bill of materials does not record %s", runtimeModule)
}

// A bill of materials that still names a removed module, or names a
// dependency at a superseded version, must fail the check.
func TestBillOfMaterialsDriftFailsClosed(t *testing.T) {
	document, err := LoadBillOfMaterials("../..")
	if err != nil {
		t.Fatal(err)
	}
	modulePath, requirements, err := LoadRequirements("../..")
	if err != nil {
		t.Fatal(err)
	}
	if modulePath == "" || len(requirements) == 0 {
		t.Fatal("module graph is empty")
	}
	if len(document.Components) == 0 {
		t.Fatal("bill of materials records no components")
	}
	// Every recorded component is a real requirement at the same version, so
	// the positive check above cannot be passing vacuously.
	versions := map[string]string{}
	for _, requirement := range requirements {
		versions[requirement.Path] = requirement.Version
	}
	matched := 0
	for _, component := range document.Components {
		if versions[component.Name] == component.Version {
			matched++
		}
	}
	if matched != len(document.Components) {
		t.Fatalf("components matching the module graph = %d, want %d", matched, len(document.Components))
	}
}

// The gate is release evidence, so every way a document can stop describing
// this application at this revision must fail it. Each case starts from the
// committed document and changes exactly one thing.
func TestBillOfMaterialsRejectsStaleIncompleteAndMismatchedDocuments(t *testing.T) {
	if err := Verify("../.."); err != nil {
		requireRepositoryHistory(t, err)
		t.Fatalf("the committed document does not pass the gate it is measured against: %v", err)
	}
	graph, err := LoadBuildGraph("../..")
	if err != nil {
		t.Fatal(err)
	}
	modulePath, _, err := LoadRequirements("../..")
	if err != nil {
		t.Fatal(err)
	}
	var indirect Component
	for _, component := range mustLoad(t).Components {
		if _, built := graph[component.Name]; built && component.Name != "github.com/dbos-inc/dbos-transact-golang" {
			indirect = component
			break
		}
	}
	if indirect.Name == "" {
		t.Fatal("no built dependency was found, so the omission cases would pass vacuously")
	}
	tests := []struct {
		name   string
		mutate func(Document) Document
		want   string
	}{
		{
			name: "a built dependency is missing",
			mutate: func(document Document) Document {
				kept := make([]Component, 0, len(document.Components))
				for _, component := range document.Components {
					if component.Name != indirect.Name {
						kept = append(kept, component)
					}
				}
				document.Components = kept
				return document
			},
			want: "does not record " + indirect.Name,
		},
		{
			name: "a built dependency is recorded at another version",
			mutate: func(document Document) Document {
				components := append([]Component(nil), document.Components...)
				for index := range components {
					if components[index].Name == indirect.Name {
						components[index].Version = components[index].Version + "-drift"
					}
				}
				document.Components = components
				return document
			},
			want: indirect.Name,
		},
		{
			name: "the document describes another application",
			mutate: func(document Document) Document {
				document.Metadata.Component.Name = modulePath + "-fork"
				return document
			},
			want: "this module is",
		},
		{
			name: "the application version carries no revision",
			mutate: func(document Document) Document {
				document.Metadata.Component.Version = "v1.4.2"
				document.Metadata.Component.PURL = "pkg:golang/" + modulePath + "@v1.4.2?type=module"
				return document
			},
			want: "does not carry a source revision",
		},
		{
			name: "the application revision is not a commit of this repository",
			mutate: func(document Document) Document {
				document.Metadata.Component.Version = "v0.0.0-20260101000000-000000000000"
				document.Metadata.Component.PURL = "pkg:golang/" + modulePath + "@v0.0.0-20260101000000-000000000000?type=module"
				return document
			},
			want: "is not a commit of this repository",
		},
		{
			name: "the package URL does not carry the recorded version",
			mutate: func(document Document) Document {
				document.Metadata.Component.PURL = "pkg:golang/" + modulePath + "@v0.0.0-20200101000000-aaaaaaaaaaaa?type=module"
				return document
			},
			want: "package URL does not carry",
		},
		{
			name: "the metadata component is not the application",
			mutate: func(document Document) Document {
				document.Metadata.Component.Type = "library"
				return document
			},
			want: "want the application it describes",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := VerifyDocument("../..", test.mutate(mustLoad(t)))
			if err == nil {
				t.Fatalf("the gate accepted a document that %s", test.name)
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want it to name %q", err, test.want)
			}
		})
	}
}

// A document generated before a dependency change describes a module graph
// that no longer exists. The revision check is what catches that, so it is
// asserted against a real earlier commit of this repository whose module file
// differs from the tree's.
func TestBillOfMaterialsRevisionRejectsAModuleFileChangedSinceGeneration(t *testing.T) {
	current, err := os.ReadFile("../../go.mod")
	if err != nil {
		t.Fatal(err)
	}
	commits, err := git("../..", "log", "--format=%h", "-n", "200", "--", "go.mod")
	if err != nil {
		t.Skipf("module file history is unavailable in this checkout: %v", err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(commits)), "\n") {
		short := strings.TrimSpace(line)
		if short == "" {
			continue
		}
		full, err := git("../..", "rev-parse", short)
		if err != nil {
			t.Fatal(err)
		}
		commit := strings.TrimSpace(string(full))[:12]
		recorded, err := git("../..", "show", commit+":go.mod")
		if err != nil {
			continue
		}
		if bytes.Equal(recorded, current) {
			continue
		}
		err = VerifyRevision("../..", Revision{Module: "github.com/ancyloce/anvilkit-agent-service", Commit: commit})
		if err == nil {
			t.Fatalf("the gate accepted a document generated at %s, before the module file changed", commit)
		}
		if !strings.Contains(err.Error(), "is stale") {
			t.Fatalf("error = %v, want it to report a stale document", err)
		}
		return
	}
	t.Skip("this checkout has no earlier commit whose module file differs from the tree's")
}

func mustLoad(t *testing.T) Document {
	t.Helper()
	document, err := LoadBillOfMaterials("../..")
	if err != nil {
		t.Fatal(err)
	}
	return document
}
