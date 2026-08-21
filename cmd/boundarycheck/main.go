// Command boundarycheck enforces modular-monolith dependency rules which are
// intentionally stricter than Go's internal-package visibility.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

func main() {
	root := flag.String("root", ".", "module root")
	flag.Parse()
	var failures []string
	// Delivery-stage naming is forbidden in code: a milestone, work-package,
	// phase, or gate marker in a file name, directory, identifier, test name,
	// comment, metric, or configuration key binds the code to a delivery
	// schedule that stops being true the moment the schedule moves.
	deliveryMarker := regexp.MustCompile(deliveryLabelPattern)
	// The canonical scope names ADR-018 established are readable only at the
	// exact governance-owned locations that own them. Everywhere else the only
	// allowance is measurement vocabulary, which is not a delivery label at
	// all. Two allowlists, selected per path, are what keeps a governed name
	// from becoming a licence to spell it anywhere.
	governed := governedLocations(*root)
	ordinary := regexp.MustCompile(governedNamePattern(measurementNames()))
	canonical := regexp.MustCompile(governedNamePattern(append(measurementNames(), canonicalScopeNames()...)))
	deliveryIdentifier := regexp.MustCompile(deliveryIdentifierPattern)
	deliveryCamel := regexp.MustCompile(deliveryCamelPattern)
	err := filepath.WalkDir(*root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if entry.Name() == ".git" || entry.Name() == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		relative, err := filepath.Rel(*root, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		allowed := ordinary
		if governed[relative] {
			allowed = canonical
		}
		if entry.Type().IsRegular() {
			body, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			// The path is scanned in every case; the body only when it is
			// text, because a binary run of bytes is not a name anyone reads.
			if label := deliveryLabel(deliveryMarker, allowed, []byte(relative)); label != "" {
				failures = append(failures, relative+": delivery-stage naming is forbidden ("+label+")")
			} else if bytes.IndexByte(body, 0) < 0 {
				if label := deliveryLabel(deliveryMarker, allowed, body); label != "" {
					failures = append(failures, relative+": delivery-stage naming is forbidden ("+label+")")
				}
			}
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		if isEvidenceCommand(relative) || strings.HasPrefix(relative, "cmd/boundarycheck/") || strings.HasPrefix(relative, "contracts/generated/") {
			return nil
		}
		// Test files are parsed for the names they declare and nothing else.
		// A test name is a name someone reads, so it is held to the same
		// naming rule as production code; the import, package-state, and
		// environment rules are production boundaries that say nothing about
		// a test, and applying them here would only teach people to keep
		// tests out of the checker's way.
		test := strings.HasSuffix(path, "_test.go")
		parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ParseComments)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: parse: %v", relative, err))
			return nil
		}

		for _, declaration := range parsed.Decls {
			general, ok := declaration.(*ast.GenDecl)
			if ok && !test && general.Tok == token.VAR && !isEmbedded(general) && !isCompileAssertion(general) {
				failures = append(failures, relative+": package-level mutable state is forbidden")
			}
		}
		// Declared names are checked with the camel-case-aware pattern, which
		// free text cannot use without matching digests.
		for _, name := range declaredNames(parsed) {
			for _, marker := range []*regexp.Regexp{deliveryIdentifier, deliveryCamel} {
				if label := deliveryLabel(marker, allowed, []byte(name)); label != "" {
					failures = append(failures, relative+": delivery-stage naming is forbidden in identifier "+name+" ("+label+")")
					break
				}
			}
		}
		if test {
			return nil
		}
		for _, imported := range parsed.Imports {
			name, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				continue
			}
			if strings.Contains(name, "dbos-transact-golang") && !strings.HasPrefix(relative, "internal/workflow/dbos/") {
				failures = append(failures, relative+": DBOS SDK import outside internal/workflow/dbos")
			}
			if isProviderSDK(name) && !strings.HasPrefix(relative, "internal/modelgateway/") {
				failures = append(failures, relative+": provider SDK import outside modelgateway adapter")
			}
			if strings.HasPrefix(relative, "internal/api/") && strings.Contains(name, "/internal/runs") {
				failures = append(failures, relative+": transport imports run aggregate directly")
			}
			if strings.Contains(name, "anvilkit-platform/") {
				failures = append(failures, relative+": cross-repository source import is forbidden")
			}
		}
		if relative != "internal/config/config.go" && !isEvidenceCommand(relative) {
			ast.Inspect(parsed, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				selector, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				identifier, ok := selector.X.(*ast.Ident)
				if ok && identifier.Name == "os" && (selector.Sel.Name == "Getenv" || selector.Sel.Name == "LookupEnv" || selector.Sel.Name == "Environ") {
					failures = append(failures, relative+": process environment read outside config package")
				}
				return true
			})
		}
		return nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if len(failures) > 0 {
		for _, failure := range failures {
			fmt.Fprintln(os.Stderr, failure)
		}
		os.Exit(1)
	}
	fmt.Println("module boundary check passed")
}

// deliveryLabelAlternation spells every delivery-stage label this repository
// forbids: the bare milestone, work-package, and phase prefixes as well as the
// spelled-out forms, in any case, joined by any separator a file name,
// identifier, or configuration key would use. The separator set is the
// punctuation naming uses — hyphen, underscore, dot, or nothing — and
// deliberately not a space, because a space-separated "phase 2" is a sentence
// describing a step, not a label bound to a delivery schedule.
//
// It is written entirely from character classes so the pattern's own source
// text cannot match it.
const deliveryLabelAlternation = `([Mm][0-9]+|[Ww][Pp][0-9]+|[Pp][0-9]+|[Ww][Oo][Rr][Kk][-_.]?[Pp][Aa][Cc][Kk][Aa][Gg][Ee][-_.]?[0-9]+|[Mm][Ii][Ll][Ee][Ss][Tt][Oo][Nn][Ee][-_.]?[0-9]+|[Pp][Hh][Aa][Ss][Ee][-_.]?[0-9]+|[Gg][Aa][Tt][Ee][-_.]?[0-9]+)`

// deliveryLabelPattern scans free text — paths, comments, configuration. Its
// boundaries require the label to stand alone between non-alphanumerics, which
// is what keeps it off the base64 and hex digests that fill lockfiles and
// signed contract material: a run of random characters is not a name.
const deliveryLabelPattern = `(^|[^A-Za-z0-9])` + deliveryLabelAlternation + `([^A-Za-z0-9]|$)`

// deliveryLabelCapitalAlternation is the same set restricted to labels that
// begin with a capital, which is the only form a camel-case hump can take.
const deliveryLabelCapitalAlternation = `(M[0-9]+|W[Pp][0-9]+|P[0-9]+|W[Oo][Rr][Kk][-_.]?[Pp][Aa][Cc][Kk][Aa][Gg][Ee][-_.]?[0-9]+|M[Ii][Ll][Ee][Ss][Tt][Oo][Nn][Ee][-_.]?[0-9]+|P[Hh][Aa][Ss][Ee][-_.]?[0-9]+|G[Aa][Tt][Ee][-_.]?[0-9]+)`

// deliveryIdentifierPattern scans declared Go identifiers, where a label can
// end in an uppercase letter that free text could not afford to admit: an
// identifier is a name someone chose, never a digest, so the looser trailing
// boundary costs nothing here.
const deliveryIdentifierPattern = `(^|[^A-Za-z0-9])` + deliveryLabelAlternation + `([^a-z0-9]|$)`

// deliveryCamelPattern catches the other half of an identifier — a label that
// begins a camel-case hump partway through a name, where no separator precedes
// it. Requiring the capital is what keeps it off ordinary words: item0 and sum0
// carry no hump, so they are names, not labels.
const deliveryCamelPattern = `([a-z0-9])` + deliveryLabelCapitalAlternation + `([^a-z0-9]|$)`

// canonicalScopeNames are the exact names ADR-018 established for the
// canonical contract profile and the scope it governs. This service does not
// own the freedom to rename them: they are the profile artifact's own name and
// the scope identity quoted throughout the canonical contract descriptions.
//
// They are readable only at the exact governance-owned locations
// governedLocations names. That path scoping is the whole point — a bare
// allowance for these names would let any file anywhere spell a delivery
// label and call it canonical, which is exactly the bypass this guard exists
// to close.
func canonicalScopeNames() []string {
	return []string{"p0-kernel-profile", "p0-kernel", "P0-Kernel", "P0"}
}

// measurementNames are not delivery labels. They are the latency percentiles a
// metric reports under — measurement vocabulary with a fixed meaning that no
// schedule can move — so they are readable anywhere, exactly as they are
// written.
func measurementNames() []string {
	return []string{"p999", "p99", "p95", "p90", "p50"}
}

// governedLocations is the exact set of repository-relative paths permitted to
// carry a canonical scope name, in their own name or in their contents.
//
// It is derived rather than listed, from the canonical lock ADR-018 makes the
// authority on what the canonical contract set is: the profile it pins and
// every source it enumerates. Deriving it is what keeps it exact and current —
// a hand-written list drifts, and a directory prefix would readmit the bypass.
// The few remaining entries are spelled out because they are not contract
// artifacts: the pinned intake reference, the drift script that names the
// profile file, the package that verifies the pinned identity, and the
// governance sources that necessarily spell the names they govern.
//
// A missing or unreadable lock yields no governed locations at all, so the
// scan gets stricter rather than more permissive when the authority is absent.
func governedLocations(root string) map[string]bool {
	locations := map[string]bool{
		"contracts/pin.json":              true,
		"scripts/check-contract-drift.sh": true,
		"internal/contracts/material.go":  true,
		"cmd/boundarycheck/main.go":       true,
	}
	body, err := os.ReadFile(filepath.Join(root, canonicalLockPath))
	if err != nil {
		return locations
	}
	var lock struct {
		Profile struct {
			Path string `json:"path"`
		} `json:"profile"`
		Sources map[string]string `json:"sources"`
	}
	if err := json.Unmarshal(body, &lock); err != nil {
		return locations
	}
	locations[canonicalLockPath] = true
	if lock.Profile.Path != "" {
		locations[lock.Profile.Path] = true
	}
	for source := range lock.Sources {
		locations[source] = true
	}
	return locations
}

// canonicalLockPath is the canonical lock's own repository-relative path.
const canonicalLockPath = "contracts/agent/lock/contracts.lock.json"

// governedNamePattern renders an allowlist longest-first, so a longer governed
// name is preferred over a shorter one it contains.
func governedNamePattern(names []string) string {
	ordered := append([]string(nil), names...)
	sort.SliceStable(ordered, func(i, j int) bool { return len(ordered[i]) > len(ordered[j]) })
	quoted := make([]string, 0, len(ordered))
	for _, name := range ordered {
		quoted = append(quoted, regexp.QuoteMeta(name))
	}
	return `(?i)(` + strings.Join(quoted, "|") + `)`
}

// deliveryLabel reports the first delivery-stage label in the text that no
// governed name accounts for, or the empty string when the text is clean. A
// label is excused only when it lies wholly inside an occurrence of a governed
// name, so the same characters inside an ordinary identifier still fail.
func deliveryLabel(marker, governed *regexp.Regexp, text []byte) string {
	matches := marker.FindAllSubmatchIndex(text, -1)
	if len(matches) == 0 {
		return ""
	}
	allowed := governed.FindAllIndex(text, -1)
	for _, match := range matches {
		start, end := match[4], match[5]
		covered := false
		for _, span := range allowed {
			if span[0] <= start && end <= span[1] {
				covered = true
				break
			}
		}
		if !covered {
			return string(text[start:end])
		}
	}
	return ""
}

// declaredNames collects every name this file declares — packages, functions,
// methods, types, fields, constants, and variables — so an identifier check
// sees the names the file introduces rather than every token it mentions.
func declaredNames(file *ast.File) []string {
	names := []string{file.Name.Name}
	ast.Inspect(file, func(node ast.Node) bool {
		switch declared := node.(type) {
		case *ast.FuncDecl:
			names = append(names, declared.Name.Name)
		case *ast.TypeSpec:
			names = append(names, declared.Name.Name)
		case *ast.ValueSpec:
			for _, name := range declared.Names {
				names = append(names, name.Name)
			}
		case *ast.Field:
			for _, name := range declared.Names {
				names = append(names, name.Name)
			}
		}
		return true
	})
	return names
}

func isEvidenceCommand(path string) bool {
	for _, prefix := range []string{
		"cmd/dbos-benchmark/",
		"cmd/dbos-restart-probe/",
	} {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func isEmbedded(declaration *ast.GenDecl) bool {
	if declaration.Doc == nil {
		return false
	}
	for _, comment := range declaration.Doc.List {
		if strings.HasPrefix(comment.Text, "//go:embed ") {
			return true
		}
	}
	return false
}

func isCompileAssertion(declaration *ast.GenDecl) bool {
	for _, item := range declaration.Specs {
		specification, ok := item.(*ast.ValueSpec)
		if !ok {
			return false
		}
		for _, name := range specification.Names {
			if name.Name != "_" {
				return false
			}
		}
	}
	return true
}

func isProviderSDK(path string) bool {
	providers := []string{"openai-go", "anthropic-sdk-go", "generative-ai-go", "google.golang.org/genai"}
	for _, provider := range providers {
		if strings.Contains(path, provider) {
			return true
		}
	}
	return false
}
