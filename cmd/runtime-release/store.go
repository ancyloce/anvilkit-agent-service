package main

// store.go loads and writes the two approved stores a release cut touches: the
// runtime release catalog with its manifest documents, and the definition
// catalog with the definitions that pin each release. They are read as ordered
// documents so a cut rewrites only the members it means to change.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// catalogEntry is one release named by the runtime release catalog.
type catalogEntry struct {
	runtimeUnitID string
	definitionID  string
	document      string
}

// definitionEntry is one definition named by the definition catalog.
type definitionEntry struct {
	definitionID string
	document     string
	instruction  string
}

// releaseStore is both approved stores, parsed and addressable.
type releaseStore struct {
	releasesDir    string
	definitionsDir string

	releaseCatalog *documentNode
	releaseDocs    map[string]*documentNode
	entries        []catalogEntry

	definitionCatalog *documentNode
	definitionDocs    map[string]*documentNode
	definitions       []definitionEntry
}

func loadStore(releasesDir, definitionsDir string) (*releaseStore, error) {
	store := &releaseStore{
		releasesDir:    releasesDir,
		definitionsDir: definitionsDir,
		releaseDocs:    map[string]*documentNode{},
		definitionDocs: map[string]*documentNode{},
	}
	catalog, err := parseDocumentFile(filepath.Join(releasesDir, "catalog.json"))
	if err != nil {
		return nil, fmt.Errorf("release catalog: %w", err)
	}
	store.releaseCatalog = catalog
	releaseList, err := catalog.child("releases")
	if err != nil {
		return nil, fmt.Errorf("release catalog: %w", err)
	}
	for _, item := range releaseList.items {
		entry := catalogEntry{}
		if entry.runtimeUnitID, err = item.stringAt("runtimeUnitId"); err != nil {
			return nil, fmt.Errorf("release catalog entry: %w", err)
		}
		if entry.definitionID, err = item.stringAt("definitionId"); err != nil {
			return nil, fmt.Errorf("release catalog entry: %w", err)
		}
		if entry.document, err = item.stringAt("document"); err != nil {
			return nil, fmt.Errorf("release catalog entry: %w", err)
		}
		if err := boundedDocumentName(entry.document); err != nil {
			return nil, fmt.Errorf("release catalog entry: %w", err)
		}
		document, err := parseDocumentFile(filepath.Join(releasesDir, entry.document))
		if err != nil {
			return nil, fmt.Errorf("release document %s: %w", entry.document, err)
		}
		store.releaseDocs[entry.document] = document
		store.entries = append(store.entries, entry)
	}

	definitionCatalog, err := parseDocumentFile(filepath.Join(definitionsDir, "catalog.json"))
	if err != nil {
		return nil, fmt.Errorf("definition catalog: %w", err)
	}
	store.definitionCatalog = definitionCatalog
	definitionList, err := definitionCatalog.child("definitions")
	if err != nil {
		return nil, fmt.Errorf("definition catalog: %w", err)
	}
	for _, item := range definitionList.items {
		entry := definitionEntry{}
		if entry.definitionID, err = item.stringAt("definitionId"); err != nil {
			return nil, fmt.Errorf("definition catalog entry: %w", err)
		}
		if entry.document, err = item.stringAt("document"); err != nil {
			return nil, fmt.Errorf("definition catalog entry: %w", err)
		}
		if entry.instruction, err = item.stringAt("instruction"); err != nil {
			return nil, fmt.Errorf("definition catalog entry: %w", err)
		}
		if err := boundedDocumentName(entry.document); err != nil {
			return nil, fmt.Errorf("definition catalog entry: %w", err)
		}
		document, err := parseDocumentFile(filepath.Join(definitionsDir, entry.document))
		if err != nil {
			return nil, fmt.Errorf("definition document %s: %w", entry.document, err)
		}
		store.definitionDocs[entry.document] = document
		store.definitions = append(store.definitions, entry)
	}
	return store, nil
}

func parseDocumentFile(path string) (*documentNode, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	document, err := parseDocument(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return document, nil
}

// boundedDocumentName refuses a document reference that could escape its
// store directory.
func boundedDocumentName(name string) error {
	if name == "" || strings.ContainsAny(name, `/\`) {
		return fmt.Errorf("document name %q is not a bounded store entry", name)
	}
	return nil
}

// writeStore writes both stores into the target directories, carrying every
// file of the source stores so the result is a complete, standalone store:
// instructions and policy documents travel with the definitions they govern.
func (s *releaseStore) writeStore(releasesOut, definitionsOut string) error {
	if err := copyDirectoryFiles(s.releasesDir, releasesOut); err != nil {
		return err
	}
	if err := copyDirectoryFiles(s.definitionsDir, definitionsOut); err != nil {
		return err
	}
	if err := writeFile(filepath.Join(releasesOut, "catalog.json"), s.releaseCatalog.encodedBytes(), 0o644); err != nil {
		return err
	}
	for name, document := range s.releaseDocs {
		if err := writeFile(filepath.Join(releasesOut, name), document.encodedBytes(), 0o644); err != nil {
			return err
		}
	}
	if err := writeFile(filepath.Join(definitionsOut, "catalog.json"), s.definitionCatalog.encodedBytes(), 0o644); err != nil {
		return err
	}
	for name, document := range s.definitionDocs {
		if err := writeFile(filepath.Join(definitionsOut, name), document.encodedBytes(), 0o644); err != nil {
			return err
		}
	}
	return nil
}

func copyDirectoryFiles(source, target string) error {
	if sameDirectory(source, target) {
		return nil
	}
	entries, err := os.ReadDir(source)
	if err != nil {
		return fmt.Errorf("read store %s: %w", source, err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(source, entry.Name()))
		if err != nil {
			return fmt.Errorf("read store file: %w", err)
		}
		if err := writeFile(filepath.Join(target, entry.Name()), raw, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func sameDirectory(left, right string) bool {
	leftAbsolute, leftErr := filepath.Abs(left)
	rightAbsolute, rightErr := filepath.Abs(right)
	return leftErr == nil && rightErr == nil && leftAbsolute == rightAbsolute
}

func writeFile(path string, raw []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create %s: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, raw, mode); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
