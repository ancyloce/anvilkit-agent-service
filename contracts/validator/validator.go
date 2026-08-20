// Package validator provides the pinned Go contract adapter. It performs strict
// byte admission before Draft 2020-12 validation and never resolves a network
// reference.
package validator

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
)

const maximumSafeInteger = 9007199254740991

const (
	maximumFindingCount = 100
	maximumSchemaBytes  = 1_048_576
	maximumSchemaCount  = 128
)

type Finding struct{ Code, InstancePath, SchemaPath string }

type Adapter struct{ schemas map[string]*jsonschema.Schema }

func logicalURI(name string, bytes []byte) string {
	digest := sha256.Sum256(bytes)
	return fmt.Sprintf("anvilkit://schema/%s?digest=sha256:%s", name, hex.EncodeToString(digest[:]))
}

func New(repositoryRoot string) (*Adapter, error) {
	directory := filepath.Join(repositoryRoot, "contracts", "agent", "schemas")
	schemaRoot, err := os.OpenRoot(directory)
	if err != nil {
		return nil, fmt.Errorf("open schema root: %w", err)
	}
	// The root is opened only to bound reads; closing it cannot fail in a
	// way that changes the schemas already loaded.
	defer func() { _ = schemaRoot.Close() }()
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, fmt.Errorf("read schema directory: %w", err)
	}
	if len(entries) > maximumSchemaCount {
		return nil, fmt.Errorf("schema directory exceeds %d entries", maximumSchemaCount)
	}
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	compiler.UseLoader(denyLoader{})
	type source struct {
		uri   string
		value any
	}
	sources := make([]source, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".schema.json") {
			continue
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("schema %s must not be a symbolic link", entry.Name())
		}
		info, err := entry.Info()
		if err != nil {
			return nil, fmt.Errorf("inspect %s: %w", entry.Name(), err)
		}
		if !info.Mode().IsRegular() || info.Size() > maximumSchemaBytes {
			return nil, fmt.Errorf("schema %s is not a regular bounded file", entry.Name())
		}
		raw, err := schemaRoot.ReadFile(entry.Name())
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", entry.Name(), err)
		}
		admitted, err := Admit(raw)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", entry.Name(), err)
		}
		value, ok := admitted.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("parse %s: schema root must be an object", entry.Name())
		}
		metadata, ok := value["x-anvilkit-contract"].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s lacks metadata", entry.Name())
		}
		if _, ok := metadata["logicalId"].(string); !ok {
			return nil, fmt.Errorf("%s lacks a logical ID", entry.Name())
		}
		name := strings.TrimSuffix(entry.Name(), ".schema.json")
		uri := logicalURI(name, raw)
		value["$schema"] = "https://json-schema.org/draft/2020-12/schema"
		value["$id"] = uri
		delete(value, "x-anvilkit-contract")
		sources = append(sources, source{uri, value})
	}
	for _, source := range sources {
		if err := compiler.AddResource(source.uri, source.value); err != nil {
			return nil, fmt.Errorf("register %s: %w", source.uri, err)
		}
	}
	compiled := make(map[string]*jsonschema.Schema, len(sources))
	for _, source := range sources {
		schema, err := compiler.Compile(source.uri)
		if err != nil {
			return nil, fmt.Errorf("compile %s: %w", source.uri, err)
		}
		compiled[source.uri] = schema
	}
	return &Adapter{schemas: compiled}, nil
}

type denyLoader struct{}

func (denyLoader) Load(url string) (any, error) {
	return nil, fmt.Errorf("network/unknown schema resolution denied: %s", url)
}

func (a *Adapter) Validate(schemaURI string, raw []byte) []Finding {
	value, err := Admit(raw)
	if err != nil {
		return []Finding{{Code: "PARSE_REJECTED", InstancePath: "/", SchemaPath: "/profile/strictAdmission"}}
	}
	schema := a.schemas[schemaURI]
	if schema == nil {
		return []Finding{{Code: "VALIDATION_FAILED", InstancePath: "/", SchemaPath: "/profile/closedResolver"}}
	}
	if err := schema.Validate(value); err != nil {
		var validation *jsonschema.ValidationError
		if !errors.As(err, &validation) {
			return []Finding{{Code: "VALIDATION_FAILED", InstancePath: "/", SchemaPath: "/"}}
		}
		findings := make([]Finding, 0, maximumFindingCount)
		if flatten(validation, &findings, maximumFindingCount-1) {
			findings = append(findings, Finding{Code: "VALIDATION_FAILED", InstancePath: "/", SchemaPath: "/profile/findingLimit"})
		}
		sort.Slice(findings, func(i, j int) bool {
			if findings[i].Code != findings[j].Code {
				return findings[i].Code < findings[j].Code
			}
			if findings[i].InstancePath != findings[j].InstancePath {
				return findings[i].InstancePath < findings[j].InstancePath
			}
			return findings[i].SchemaPath < findings[j].SchemaPath
		})
		return findings
	}
	return nil
}

func pointer(parts []string) string {
	if len(parts) == 0 {
		return "/"
	}
	escaped := make([]string, len(parts))
	for i, part := range parts {
		escaped[i] = strings.ReplaceAll(strings.ReplaceAll(part, "~", "~0"), "/", "~1")
	}
	return "/" + strings.Join(escaped, "/")
}
func flatten(err *jsonschema.ValidationError, findings *[]Finding, limit int) bool {
	if len(*findings) >= limit {
		return true
	}
	if len(err.Causes) > 0 {
		for _, cause := range err.Causes {
			if flatten(cause, findings, limit) {
				return true
			}
		}
		return false
	}
	schemaPath := err.SchemaURL
	if keywordPath := err.ErrorKind.KeywordPath(); len(keywordPath) > 0 {
		schemaPath = strings.TrimSuffix(schemaPath, "#") + "#" + pointer(keywordPath)
	}
	*findings = append(*findings, Finding{Code: "VALIDATION_FAILED", InstancePath: pointer(err.InstanceLocation), SchemaPath: schemaPath})
	return false
}

func Admit(raw []byte) (any, error) {
	if len(raw) == 0 || len(raw) > 1_048_576 {
		return nil, errors.New("byte limit")
	}
	if !utf8.Valid(raw) || bytes.HasPrefix(raw, []byte{0xef, 0xbb, 0xbf}) {
		return nil, errors.New("invalid UTF-8/BOM")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	value, err := decodeValue(decoder, 0)
	if err != nil {
		return nil, err
	}
	if _, err = decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("trailing value")
		}
		return nil, err
	}
	return value, nil
}

func decodeValue(decoder *json.Decoder, depth int) (any, error) {
	if depth > 64 {
		return nil, errors.New("depth limit")
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			object := make(map[string]any)
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return nil, err
				}
				key, ok := keyToken.(string)
				if !ok {
					return nil, errors.New("object key")
				}
				if _, exists := object[key]; exists {
					return nil, errors.New("duplicate key")
				}
				child, err := decodeValue(decoder, depth+1)
				if err != nil {
					return nil, err
				}
				object[key] = child
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				return nil, errors.New("object end")
			}
			return object, nil
		case '[':
			array := make([]any, 0)
			for decoder.More() {
				if len(array) >= 100000 {
					return nil, errors.New("item limit")
				}
				child, err := decodeValue(decoder, depth+1)
				if err != nil {
					return nil, err
				}
				array = append(array, child)
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				return nil, errors.New("array end")
			}
			return array, nil
		}
	case json.Number:
		wire := value.String()
		if strings.HasPrefix(wire, "-") {
			number, err := strconv.ParseFloat(wire, 64)
			if err != nil || math.IsInf(number, 0) || number == 0 {
				return nil, errors.New("negative zero/range")
			}
		}
		if !strings.ContainsAny(wire, ".eE") {
			integer, err := strconv.ParseInt(wire, 10, 64)
			if err != nil || integer > maximumSafeInteger || integer < -maximumSafeInteger {
				return nil, errors.New("unsafe integer")
			}
			return integer, nil
		}
		number, err := strconv.ParseFloat(wire, 64)
		if err != nil || math.IsInf(number, 0) || number == 0 && wire != "0.0" {
			return nil, errors.New("number range")
		}
		return number, nil
	default:
		return token, nil
	}
	return nil, errors.New("invalid delimiter")
}
