// Command boundarycheck enforces modular-monolith dependency rules which are
// intentionally stricter than Go's internal-package visibility.
package main

import (
	"bytes"
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
	governedPath := regexp.MustCompile(governedNamePattern(governedPathNames()))
	governedContent := regexp.MustCompile(governedNamePattern(governedContentNames()))
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
		if entry.Type().IsRegular() {
			body, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			// The path is scanned in every case; the body only when it is
			// text, because a binary run of bytes is not a name anyone reads.
			if label := deliveryLabel(deliveryMarker, governedPath, []byte(relative)); label != "" {
				failures = append(failures, relative+": delivery-stage naming is forbidden ("+label+")")
			} else if bytes.IndexByte(body, 0) < 0 {
				if label := deliveryLabel(deliveryMarker, governedContent, body); label != "" {
					failures = append(failures, relative+": delivery-stage naming is forbidden ("+label+")")
				}
			}
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		if isEvidenceCommand(relative) || strings.HasPrefix(relative, "cmd/boundarycheck/") || strings.HasPrefix(relative, "contracts/generated/") {
			return nil
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ParseComments)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: parse: %v", relative, err))
			return nil
		}

		for _, declaration := range parsed.Decls {
			general, ok := declaration.(*ast.GenDecl)
			if ok && general.Tok == token.VAR && !isEmbedded(general) && !isCompileAssertion(general) {
				failures = append(failures, relative+": package-level mutable state is forbidden")
			}
		}
		// Declared names are checked with the camel-case-aware pattern, which
		// free text cannot use without matching digests.
		for _, name := range declaredNames(parsed) {
			for _, marker := range []*regexp.Regexp{deliveryIdentifier, deliveryCamel} {
				if label := deliveryLabel(marker, governedContent, []byte(name)); label != "" {
					failures = append(failures, relative+": delivery-stage naming is forbidden in identifier "+name+" ("+label+")")
					break
				}
			}
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

// governedPathNames are the exact names permitted to appear in a file or
// directory name: the canonical contract profile ADR-018 names, and the
// directory that profile's scope owns. Keeping this tier separate from the
// content tier is what stops the allowlist from becoming a licence to create
// new delivery-labelled files — a name not spelled here cannot be a path.
func governedPathNames() []string {
	return []string{"p0-kernel-profile", "p0-kernel", "P0-Kernel"}
}

// governedContentNames are additionally permitted inside file contents. They
// are names this service does not own the freedom to rename: the profile scope
// identity ADR-018 established, and the latency percentiles a metric reports
// under. Every entry is an exact string matched verbatim — not a directory
// prefix and not a file bypass — so an entry excuses the governed name it
// spells and nothing else. Adding one is a governance decision.
func governedContentNames() []string {
	return append(governedPathNames(), "P0", "p999", "p99", "p95", "p90", "p50")
}

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
