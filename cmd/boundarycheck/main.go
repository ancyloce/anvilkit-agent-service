// Command boundarycheck enforces modular-monolith dependency rules which are
// intentionally stricter than Go's internal-package visibility.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
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
			// The runtime units are a process boundary, not a library. The
			// control plane reaches a Manager or Specialist only by
			// dispatching a canonical task over authenticated transport and
			// verifying the signed result that comes back; importing the
			// runtime implementation would let the same work happen
			// in-process, beside every check that boundary exists to
			// enforce.
			if strings.Contains(name, "anvilkit-agent-runtimes") {
				failures = append(failures, relative+": runtime unit implementation import is forbidden; runtimes are reached only by dispatch")
			}
			// The in-process runtime stand-in is test-profile material. It is
			// kept in its own package so that the production binary never links
			// it: a test composition imports it and hands it through the
			// composition root's seam, and nothing else may import it at all.
			// This rule is what turns "the binary does not carry it" from an
			// observation about today's imports into a boundary.
			if strings.Contains(name, "/internal/runtimes/inprocess") {
				failures = append(failures, relative+": in-process runtime stand-in import outside test code; production reaches a runtime only by dispatch")
			}
			// Model reasoning lives behind the governed Model Gateway, which a
			// dispatched runtime unit calls back across the boundary. Nothing in
			// the run pipeline — the runner, the workflow, the executor, the
			// API — reaches a model itself: a turn is executed by dispatching a
			// canonical task, and an import of the gateway or the planning
			// engine anywhere else would be the in-process execution path
			// coming back under another name.
			if (strings.Contains(name, "/internal/modelgateway") || strings.Contains(name, "/internal/planning")) && !reasonsWithModels(relative) {
				failures = append(failures, relative+": model gateway or planning import outside the governed gateway; a turn reaches a model only by dispatching a task to a runtime")
			}
			// Outbound HTTP is mediated. An agent's tools reach outside
			// through the egress guard, which resolves the name once, pins
			// the connection to what it resolved, re-decides every redirect,
			// and bounds the duration and the response — and none of that is
			// worth anything if an adapter can construct its own client
			// beside it. The list below is every package that legitimately
			// speaks HTTP, and adding to it is a decision somebody makes here
			// rather than a dependency that appears.
			if name == "net/http" && !mediatesOutboundHTTP(relative) {
				failures = append(failures, relative+": net/http outside the mediated egress boundary; outbound requests go through internal/security")
			}
			if name == "crypto/tls" && !verifiesPeersDirectly(relative) {
				failures = append(failures, relative+": crypto/tls outside the mediated egress boundary; outbound requests go through internal/security")
			}
		}
		// The same rule one level down: a file that cannot import net/http
		// must not reach the network through a raw dialer either.
		//
		// Both spellings are caught. net.Dial and its siblings are calls
		// through the package, and a Dialer is a value: (&net.Dialer{...}).
		// DialContext is a dial that the call check alone never saw, because
		// what it selects from is a composite literal rather than the package
		// name.
		if !dialsDirectly(relative) {
			ast.Inspect(parsed, func(node ast.Node) bool {
				switch typed := node.(type) {
				case *ast.CallExpr:
					selector, ok := typed.Fun.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					identifier, ok := selector.X.(*ast.Ident)
					if ok && (identifier.Name == "net" || identifier.Name == "tls") && strings.HasPrefix(selector.Sel.Name, "Dial") {
						failures = append(failures, relative+": direct network dial outside the mediated egress boundary")
					}
				case *ast.CompositeLit:
					selector, ok := typed.Type.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					identifier, ok := selector.X.(*ast.Ident)
					if ok && (identifier.Name == "net" || identifier.Name == "tls") && strings.HasSuffix(selector.Sel.Name, "Dialer") {
						failures = append(failures, relative+": direct network dialer outside the mediated egress boundary")
					}
				}
				return true
			})
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
	pinned, err := stalePinnedSchemas(*root)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	failures = append(failures, pinned...)
	providers, err := providerSDKRequirements(*root)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	failures = append(failures, providers...)
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

// outboundHTTPBoundary is every file permitted to speak HTTP directly: the
// inbound server and its streaming surface, the readiness probes, the clients
// for the named internal authorities this service is configured with, the
// telemetry exporter, the composition root that builds them, and the egress
// transport itself — which is the one that carries an agent's traffic.
//
// It is exact files rather than package prefixes, and the difference is the
// whole point. A prefix admits every file that will ever be added under it:
// "internal/security/" permitted the egress guard and, with it, anything
// anyone later put beside the egress guard, and "cmd/agent-service/" permitted
// any new file in the composition root. The boundary is meant to be a decision
// somebody makes, and a decision that a new file inherits by where it was
// saved is not one. Adding a file here is now a line in this list.
//
// A tool adapter is deliberately absent. That is what makes the guard a
// boundary rather than a convention: an adapter cannot make its own request,
// so the mediated exchange is the only exchange there is.
func outboundHTTPBoundary() map[string]bool {
	return map[string]bool{
		"cmd/agent-service/main.go":       true,
		"internal/api/api.go":             true,
		"internal/events/sse.go":          true,
		"internal/lifecycle/checks.go":    true,
		"internal/lifecycle/lifecycle.go": true,
		"internal/runapp/app.go":          true,
		"internal/runapp/receipts.go":     true,
		// The runtime dispatcher reaches an operator-configured deployment
		// address — the runtime unit a verified release names — in the same way
		// the time authority and telemetry clients reach theirs. The egress
		// guard governs destinations an agent named, which is a different
		// problem: no part of a task decides where a runtime lives.
		"internal/runtimes/httpdispatcher.go": true,
		// The runtime boundary is an inbound surface: the handlers that answer
		// a dispatched unit's callbacks. They import net/http to serve, never
		// to reach out — the boundary composes no client at all.
		"internal/runtimeboundary/boundary.go":        true,
		"internal/runtimeboundary/modelinvocation.go": true,
		"internal/runtimeboundary/submission.go":      true,
		"internal/runtimeboundary/grants.go":          true,
		"internal/runtimeboundary/contract.go":        true,
		"internal/security/egresstransport.go":        true,
		"internal/securityaudit/time_http.go":         true,
		"internal/telemetry/telemetry.go":             true,
	}
}

func mediatesOutboundHTTP(relative string) bool {
	return outboundHTTPBoundary()[relative]
}

// dialsDirectly names the exact files permitted to open a socket themselves.
// There is one: the egress transport, which pins every connection to the
// addresses the guard resolved. Nothing else in the service reaches the
// network at all — a raw dialer beside the guard is the same bypass an HTTP
// client beside it would be, and the two used to be admitted by the same three
// package prefixes.
func dialsDirectly(relative string) bool {
	return relative == "internal/security/egresstransport.go"
}

// verifiesPeersDirectly names the exact files permitted to configure TLS. A
// TLS client is a way to reach the network that does not go through net/http
// at all, so it is bounded in the same place and to the same file.
func verifiesPeersDirectly(relative string) bool {
	return relative == "internal/security/egresstransport.go"
}

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

// reasonsWithModels names the exact files permitted to import the governed
// Model Gateway or the planning engine: the gateway itself, the engine itself,
// the boundary handlers that serve the gateway to a dispatched unit, the
// allowance the boundary enforces from a task, the controlled model stack the
// gateway is implemented over, and the composition root that builds it. It is
// exact files rather than package prefixes for the same reason the outbound
// HTTP boundary is: a decision a new file inherits by where it was saved is
// not one.
func reasonsWithModels(relative string) bool {
	if strings.HasPrefix(relative, "internal/modelgateway/") || strings.HasPrefix(relative, "internal/planning/") {
		return true
	}
	// The in-process stand-in is the one component that reasons with models
	// inside this process, which is exactly why the rule above confines it
	// to test code: it may reason, and nothing production may import it.
	if strings.HasPrefix(relative, "internal/runtimes/inprocess/") {
		return true
	}
	return map[string]bool{
		"internal/runtimeboundary/boundary.go":        true,
		"internal/runtimeboundary/modelinvocation.go": true,
		"internal/runtimes/allowance.go":              true,
		"internal/execution/controlled.go":            true,
		"cmd/agent-service/main.go":                   true,
	}[relative]
}

// providerSDKRequirements proves the module requires no model provider SDK at
// all. The per-file rule above confines an SDK import to the gateway adapter;
// this one says there is nothing to confine: a provider is reached over the
// mediated egress transport, and a dependency on a provider's own client is a
// decision somebody makes here, not one that appears in go.mod.
func providerSDKRequirements(root string) ([]string, error) {
	body, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if errors.Is(err, fs.ErrNotExist) {
		// A tree with no module file requires nothing; the import rule above
		// still holds every file in it.
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var failures []string
	for _, line := range strings.Split(string(body), "\n") {
		if isProviderSDK(line) {
			failures = append(failures, "go.mod: requires a model provider SDK ("+strings.TrimSpace(line)+"); providers are reached over the mediated egress transport")
		}
	}
	return failures, nil
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

// pinnedSchemaURI matches a logical schema reference written into Go source.
var pinnedSchemaURI = regexp.MustCompile(`anvilkit://schema/([a-z0-9-]+)\?digest=sha256:([0-9a-f]{64})`)

// stalePinnedSchemas proves every schema URI hard-coded in Go still names the
// pinned bytes it claims.
//
// The contract gates check contract material against other contract material;
// nothing checked the digests copied into Go against the schemas they point at.
// When a schema changed, those constants silently stopped resolving, and the
// runtime validator answered "no such schema" — which every boundary reports as
// a refusal. A governed write then fails closed in production for a reason no
// gate could see, and no test that stubs the validator would notice either.
//
// Whether the digest is in production code or a test is irrelevant: both assert
// the same fact about the pinned tree, and a stale one in a test hides the
// production break behind a passing suite.
func stalePinnedSchemas(root string) ([]string, error) {
	var failures []string
	err := filepath.Walk(filepath.Join(root, "internal"), func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") {
			return err
		}
		source, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, match := range pinnedSchemaURI.FindAllStringSubmatch(string(source), -1) {
			name, claimed := match[1], match[2]
			schema, err := os.ReadFile(filepath.Join(root, "contracts", "agent", "schemas", name+".schema.json"))
			if err != nil {
				failures = append(failures, fmt.Sprintf("%s: pins %s, which is not in the pinned contract tree", path, name))
				continue
			}
			actual := sha256.Sum256(schema)
			if hex.EncodeToString(actual[:]) != claimed {
				failures = append(failures, fmt.Sprintf(
					"%s: pinned %s digest is stale (claims %s…, pinned bytes are %s…) — regenerate the constant",
					path, name, claimed[:16], hex.EncodeToString(actual[:])[:16]))
			}
		}
		return nil
	})
	sort.Strings(failures)
	return failures, err
}
