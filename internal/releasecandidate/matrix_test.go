package releasecandidate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPinnedReleaseMatrixIsCompleteAndReferencesExecutableTests(t *testing.T) {
	raw, err := os.ReadFile("testdata/release-candidate-matrix.v1.json")
	if err != nil {
		t.Fatal(err)
	}
	matrix, err := DecodeMatrix(raw)
	if err != nil {
		t.Fatal(err)
	}
	moduleRoot, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range matrix.Cases {
		directory := filepath.Join(moduleRoot, filepath.FromSlash(strings.TrimPrefix(candidate.TestPackage, "./")))
		entries, err := os.ReadDir(directory)
		if err != nil {
			t.Fatalf("case %s package: %v", candidate.ID, err)
		}
		needle := "func " + candidate.TestName + "("
		found := false
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), "_test.go") {
				continue
			}
			body, err := os.ReadFile(filepath.Join(directory, entry.Name()))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(body), needle) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("case %s references missing %s in %s", candidate.ID, candidate.TestName, candidate.TestPackage)
		}
	}
}

func TestBlockedEntryCannotContainReleasePass(t *testing.T) {
	raw, err := os.ReadFile("testdata/release-candidate-matrix.v1.json")
	if err != nil {
		t.Fatal(err)
	}
	raw = []byte(strings.Replace(string(raw), `"releaseStatus": "blocked"`, `"releaseStatus": "passed"`, 1))
	if _, err := DecodeMatrix(raw); err == nil {
		t.Fatal("blocked candidate entry accepted release evidence")
	}
}

func TestMatrixRejectsUnknownOrTrailingInput(t *testing.T) {
	for _, raw := range [][]byte{
		[]byte(`{"schemaVersion":1,"unknown":true}`),
		[]byte(`{} {}`),
	} {
		if _, err := DecodeMatrix(raw); err == nil {
			t.Fatalf("malformed matrix accepted: %s", raw)
		}
	}
}
