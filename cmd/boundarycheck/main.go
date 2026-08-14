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
	"strconv"
	"strings"
)

func main() {
	root := flag.String("root", ".", "module root")
	flag.Parse()
	var failures []string
	deliveryMarker := regexp.MustCompile(`(?i)(^|[^a-z0-9])(m[0-9]+|p` + `0)([^a-z0-9]|$)`)
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
		if !strings.HasPrefix(relative, "contracts/") && entry.Type().IsRegular() {
			body, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if bytes.IndexByte(body, 0) < 0 && (deliveryMarker.MatchString(relative) || deliveryMarker.Match(body)) {
				failures = append(failures, relative+": delivery-stage naming is forbidden")
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
