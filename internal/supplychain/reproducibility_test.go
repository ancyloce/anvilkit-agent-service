package supplychain

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// A committable tree is tracked files plus untracked files git does not
// ignore, so anything the build reads that git ignores is simply absent from
// a clean checkout. Committed code once embedded a directory that was not
// part of any commit, and the build failed for everyone who cloned it. Every
// build input is checked here against git's own ignore rules.
func TestNoBuildInputIsExcludedFromTheCommittableTree(t *testing.T) {
	repositoryRoot, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is unavailable, so ignore rules cannot be evaluated")
	}
	inputs := buildInputs(t, repositoryRoot)
	if len(inputs) == 0 {
		t.Fatal("no build inputs were discovered, so this check would pass vacuously")
	}
	inputs = append(inputs, BillOfMaterialsFile, "go.mod", "go.sum")
	for _, input := range inputs {
		if ignored(t, repositoryRoot, input) {
			t.Errorf("%s is a build input but git ignores it, so a clean checkout would not contain it", input)
		}
		if _, err := os.Stat(filepath.Join(repositoryRoot, input)); err != nil {
			t.Errorf("build input %s is not present: %v", input, err)
		}
	}
}

// buildInputs collects every path the build embeds and every test data
// directory, relative to the repository root.
func buildInputs(t *testing.T, repositoryRoot string) []string {
	t.Helper()
	directive := regexp.MustCompile(`^//go:embed\s+(.+)$`)
	seen := map[string]struct{}{}
	err := filepath.WalkDir(repositoryRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(repositoryRoot, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", "vendor":
				return filepath.SkipDir
			case "testdata":
				seen[relative] = struct{}{}
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		directory := filepath.ToSlash(filepath.Dir(relative))
		for _, line := range strings.Split(string(raw), "\n") {
			match := directive.FindStringSubmatch(strings.TrimSpace(strings.TrimRight(line, "\r")))
			if match == nil {
				continue
			}
			for _, pattern := range strings.Fields(match[1]) {
				pattern = strings.Trim(pattern, `"`)
				if pattern == "" || strings.HasPrefix(pattern, "all:") {
					pattern = strings.TrimPrefix(pattern, "all:")
				}
				if pattern == "" {
					continue
				}
				seen[filepath.ToSlash(filepath.Join(directory, pattern))] = struct{}{}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	inputs := make([]string, 0, len(seen))
	for input := range seen {
		// Glob patterns are checked through their containing directory,
		// which is what an ignore rule would exclude.
		if strings.ContainsAny(input, "*?[") {
			input = filepath.ToSlash(filepath.Dir(input))
		}
		inputs = append(inputs, input)
	}
	return inputs
}

func ignored(t *testing.T, repositoryRoot, path string) bool {
	t.Helper()
	command := exec.Command("git", "check-ignore", "--quiet", "--no-index", "--", path)
	command.Dir = repositoryRoot
	err := command.Run()
	return err == nil
}

// The clean-checkout gate itself must be present and runnable, so the
// reproducibility claim is verifiable rather than asserted.
func TestCleanCheckoutGateIsPresent(t *testing.T) {
	info, err := os.Stat(filepath.Join("../..", "scripts", "clean-checkout.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&0o111 == 0 {
		t.Fatal("the clean-checkout gate is not executable")
	}
}
