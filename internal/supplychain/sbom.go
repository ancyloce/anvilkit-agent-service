// Package supplychain verifies that the committed software bill of materials
// still describes the module graph the service actually builds from.
package supplychain

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// NoRepositoryError reports that the tree being checked carries no repository
// history, so the recorded application revision cannot be resolved here. It is
// deliberately distinguishable from a failed revision check: a materialised
// clean checkout has no history by construction, and treating that as a pass
// would silently disable the strongest half of the gate.
type NoRepositoryError struct{}

func (NoRepositoryError) Error() string {
	return "bill of materials: this tree carries no repository history"
}

// Component is one module recorded in the bill of materials.
type Component struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version"`
	PURL    string `json:"purl"`
}

// Document is the subset of the CycloneDX bill of materials this check reads.
type Document struct {
	BOMFormat   string `json:"bomFormat"`
	SpecVersion string `json:"specVersion"`
	Metadata    struct {
		Component Component `json:"component"`
	} `json:"metadata"`
	Components []Component `json:"components"`
}

// Revision is the exact application identity a bill of materials records: the
// module it describes and the source commit it was generated from. The
// generator stamps the commit into the application component's module
// pseudo-version, which is what makes the document attributable to one
// revision rather than to "some build of this project".
type Revision struct {
	Module string
	Commit string
}

// Requirement is one module requirement declared by the module file.
type Requirement struct {
	Path     string
	Version  string
	Indirect bool
}

const (
	// BillOfMaterialsFile is the committed bill of materials.
	BillOfMaterialsFile = "sbom.cdx.json"
	moduleFile          = "go.mod"
	maximumBOMBytes     = 8 << 20
)

// Verify proves the committed bill of materials matches the module graph:
// every direct requirement is recorded at its exact version, and every
// recorded component is still a requirement at that exact version. A stale
// bill of materials — one still naming a removed module, or naming a
// dependency at a version the module file no longer requires — fails.
func Verify(repositoryRoot string) error {
	document, err := LoadBillOfMaterials(repositoryRoot)
	if err != nil {
		return err
	}
	return VerifyDocument(repositoryRoot, document)
}

// VerifyDocument runs the whole gate against an already-loaded document. It
// exists so the negative cases — a stale document, one missing a module the
// service actually builds from, one naming a foreign or hand-edited revision —
// can be driven directly.
func VerifyDocument(repositoryRoot string, document Document) error {
	modulePath, requirements, err := LoadRequirements(repositoryRoot)
	if err != nil {
		return err
	}
	if document.BOMFormat != "CycloneDX" || document.SpecVersion == "" {
		return fmt.Errorf("bill of materials: format or specification version is missing")
	}
	if document.Metadata.Component.Name != modulePath {
		return fmt.Errorf("bill of materials: describes %q, but this module is %q", document.Metadata.Component.Name, modulePath)
	}
	required := make(map[string]Requirement, len(requirements))
	for _, requirement := range requirements {
		required[requirement.Path] = requirement
	}
	recorded := make(map[string]string, len(document.Components))
	for _, component := range document.Components {
		if component.Name == "" || component.Version == "" {
			return fmt.Errorf("bill of materials: a component has no name or no version")
		}
		if _, duplicate := recorded[component.Name]; duplicate {
			return fmt.Errorf("bill of materials: duplicate component %s", component.Name)
		}
		recorded[component.Name] = component.Version
		requirement, known := required[component.Name]
		if !known {
			return fmt.Errorf("bill of materials: records %s, which the module file no longer requires", component.Name)
		}
		if requirement.Version != component.Version {
			return fmt.Errorf("bill of materials: records %s at %s, but the module file requires %s", component.Name, component.Version, requirement.Version)
		}
	}
	for _, requirement := range requirements {
		if requirement.Indirect {
			// Indirect requirements are checked against the real build graph
			// below rather than against the module file: a requirement the
			// toolchain never links is not part of what ships, and demanding
			// it here would make the gate disagree with the binary.
			continue
		}
		if _, known := recorded[requirement.Path]; !known {
			return fmt.Errorf("bill of materials: does not record the direct dependency %s", requirement.Path)
		}
	}
	// Every module the service actually builds from — direct and indirect
	// alike — must be recorded at the exact version the toolchain resolved.
	// Indirect modules are most of the shipped dependency surface, so leaving
	// them unverified made the gate report a complete bill of materials for a
	// document that named barely a third of the code in the binary.
	graph, err := LoadBuildGraph(repositoryRoot)
	if err != nil {
		return err
	}
	for module, version := range graph {
		if module == modulePath {
			continue
		}
		recordedVersion, known := recorded[module]
		if !known {
			return fmt.Errorf("bill of materials: does not record %s, which the service builds from", module)
		}
		if recordedVersion != version {
			return fmt.Errorf("bill of materials: records %s at %s, but the service builds from %s", module, recordedVersion, version)
		}
	}
	revision, err := ApplicationRevision(document)
	if err != nil {
		return err
	}
	if revision.Module != modulePath {
		return fmt.Errorf("bill of materials: the application component is %q, but this module is %q", revision.Module, modulePath)
	}
	return VerifyRevision(repositoryRoot, revision)
}

// LoadBuildGraph returns every module the main module's packages build from,
// as the Go toolchain resolves them. It is the authority for the shipped
// dependency surface: the module file states requirements, but only the
// toolchain knows which of them the binary actually links.
func LoadBuildGraph(repositoryRoot string) (map[string]string, error) {
	command := exec.Command("go", "list", "-deps", "-f", "{{with .Module}}{{.Path}} {{.Version}}{{end}}", "./...")
	command.Dir = repositoryRoot
	var stderr bytes.Buffer
	command.Stderr = &stderr
	output, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("resolve build graph: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	graph := make(map[string]string)
	scanner := bufio.NewScanner(bytes.NewReader(output))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		switch len(fields) {
		case 0:
			continue
		case 1:
			graph[fields[0]] = ""
		default:
			graph[fields[0]] = fields[1]
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read build graph: %w", err)
	}
	if len(graph) == 0 {
		return nil, fmt.Errorf("build graph is empty, so no dependency could be verified")
	}
	return graph, nil
}

// ApplicationRevision extracts the application identity and the source commit
// the bill of materials was generated from. The generator records them as the
// module path and a module pseudo-version whose final field is the commit; a
// document whose version does not carry one cannot be attributed to a
// revision at all and is refused rather than accepted unattributed.
func ApplicationRevision(document Document) (Revision, error) {
	component := document.Metadata.Component
	if component.Type != "application" {
		return Revision{}, fmt.Errorf("bill of materials: the metadata component is %q, want the application it describes", component.Type)
	}
	if component.Name == "" || component.Version == "" {
		return Revision{}, fmt.Errorf("bill of materials: the application component has no name or no version")
	}
	if !strings.Contains(component.PURL, "@"+component.Version) {
		return Revision{}, fmt.Errorf("bill of materials: the application package URL does not carry the recorded version %s", component.Version)
	}
	commit, ok := pseudoVersionCommit(component.Version)
	if !ok {
		return Revision{}, fmt.Errorf("bill of materials: the application version %q does not carry a source revision", component.Version)
	}
	return Revision{Module: component.Name, Commit: commit}, nil
}

// pseudoVersionCommit returns the commit identity a Go module pseudo-version
// ends with: <base>-<utc timestamp>-<12 lowercase hex>.
func pseudoVersionCommit(version string) (string, bool) {
	index := strings.LastIndex(version, "-")
	if index < 0 {
		return "", false
	}
	commit, timestamp := version[index+1:], version[:index]
	if len(commit) != 12 || !lowerHex(commit) {
		return "", false
	}
	stamp := timestamp[strings.LastIndex(timestamp, "-")+1:]
	if len(stamp) != 14 || !digits(stamp) {
		return "", false
	}
	return commit, true
}

func lowerHex(value string) bool {
	for index := 0; index < len(value); index++ {
		character := value[index]
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func digits(value string) bool {
	for index := 0; index < len(value); index++ {
		if value[index] < '0' || value[index] > '9' {
			return false
		}
	}
	return true
}

// VerifyRevision proves the recorded revision is a real commit of this
// repository and that the dependency surface has not moved since it was
// generated: the module file and its checksum database at that commit must be
// byte-identical to the ones in the tree. A document produced from another
// checkout names a commit this repository cannot resolve, and a document
// produced before a dependency change describes a module graph that no longer
// exists.
func VerifyRevision(repositoryRoot string, revision Revision) error {
	if revision.Commit == "" {
		return fmt.Errorf("bill of materials: no application revision to verify")
	}
	if inside, err := git(repositoryRoot, "rev-parse", "--is-inside-work-tree"); err != nil || strings.TrimSpace(string(inside)) != "true" {
		return NoRepositoryError{}
	}
	resolved, err := git(repositoryRoot, "rev-parse", "--verify", "--quiet", revision.Commit+"^{commit}")
	if err != nil {
		return fmt.Errorf("bill of materials: application revision %s is not a commit of this repository: %w", revision.Commit, err)
	}
	if len(strings.TrimSpace(string(resolved))) < len(revision.Commit) {
		return fmt.Errorf("bill of materials: application revision %s did not resolve to a commit", revision.Commit)
	}
	for _, name := range []string{moduleFile, "go.sum"} {
		recorded, err := git(repositoryRoot, "show", revision.Commit+":"+name)
		if err != nil {
			return fmt.Errorf("bill of materials: %s is not readable at application revision %s: %w", name, revision.Commit, err)
		}
		current, err := os.ReadFile(filepath.Join(repositoryRoot, name))
		if err != nil {
			return fmt.Errorf("read %s: %w", name, err)
		}
		if !bytes.Equal(bytes.ReplaceAll(recorded, []byte("\r\n"), []byte("\n")), bytes.ReplaceAll(current, []byte("\r\n"), []byte("\n"))) {
			return fmt.Errorf("bill of materials: %s changed after application revision %s, so the document is stale", name, revision.Commit)
		}
	}
	return nil
}

func git(repositoryRoot string, arguments ...string) ([]byte, error) {
	command := exec.Command("git", arguments...)
	command.Dir = repositoryRoot
	var stderr bytes.Buffer
	command.Stderr = &stderr
	output, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return output, nil
}

// LoadBillOfMaterials reads and decodes the committed bill of materials.
func LoadBillOfMaterials(repositoryRoot string) (Document, error) {
	raw, err := os.ReadFile(filepath.Join(repositoryRoot, BillOfMaterialsFile))
	if err != nil {
		return Document{}, fmt.Errorf("read bill of materials: %w", err)
	}
	if len(raw) == 0 || len(raw) > maximumBOMBytes {
		return Document{}, fmt.Errorf("bill of materials: document is empty or unbounded")
	}
	var document Document
	if err := json.Unmarshal(raw, &document); err != nil {
		return Document{}, fmt.Errorf("decode bill of materials: %w", err)
	}
	if len(document.Components) == 0 {
		return Document{}, fmt.Errorf("bill of materials: records no components")
	}
	return document, nil
}

// LoadRequirements reads the module path and every requirement the module
// file declares.
func LoadRequirements(repositoryRoot string) (string, []Requirement, error) {
	raw, err := os.ReadFile(filepath.Join(repositoryRoot, moduleFile))
	if err != nil {
		return "", nil, fmt.Errorf("read module file: %w", err)
	}
	var modulePath string
	var requirements []Requirement
	inBlock := false
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if index := strings.Index(line, "//"); index >= 0 {
			line = strings.TrimSpace(line[:index]) + commentMarker(line[index:])
		}
		switch {
		case strings.HasPrefix(line, "module "):
			modulePath = strings.TrimSpace(strings.TrimPrefix(line, "module "))
		case line == "require (":
			inBlock = true
		case inBlock && line == ")":
			inBlock = false
		case inBlock:
			if requirement, ok := parseRequirement(line); ok {
				requirements = append(requirements, requirement)
			}
		case strings.HasPrefix(line, "require "):
			if requirement, ok := parseRequirement(strings.TrimPrefix(line, "require ")); ok {
				requirements = append(requirements, requirement)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return "", nil, fmt.Errorf("scan module file: %w", err)
	}
	if modulePath == "" {
		return "", nil, fmt.Errorf("module file declares no module path")
	}
	if len(requirements) == 0 {
		return "", nil, fmt.Errorf("module file declares no requirements")
	}
	return modulePath, requirements, nil
}

// commentMarker keeps only the indirect marker from a trailing comment.
func commentMarker(comment string) string {
	if strings.Contains(comment, "indirect") {
		return " // indirect"
	}
	return ""
}

func parseRequirement(line string) (Requirement, bool) {
	indirect := strings.HasSuffix(line, "// indirect")
	line = strings.TrimSpace(strings.TrimSuffix(line, "// indirect"))
	fields := strings.Fields(line)
	if len(fields) != 2 || !strings.HasPrefix(fields[1], "v") {
		return Requirement{}, false
	}
	return Requirement{Path: fields[0], Version: fields[1], Indirect: indirect}, true
}
