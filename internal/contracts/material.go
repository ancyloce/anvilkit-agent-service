package contracts

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/lattice-substrate/json-canon/jcs"

	"github.com/ancyloce/anvilkit-agent-service/contracts/validator"
)

const maximumMaterialBytes = 1_048_576

type materialPin struct {
	PinVersion             int    `json:"pinVersion"`
	BOMVersion             string `json:"bomVersion"`
	BOMDigest              string `json:"bomDigest"`
	OCIManifestDigest      string `json:"ociManifestDigest"`
	EvidenceManifestDigest string `json:"evidenceManifestDigest"`
	ConsumerGeneration     int    `json:"consumerGeneration"`
	State                  string `json:"state"`
	Source                 string `json:"source"`
}

type releaseBOM struct {
	Version       string         `json:"version"`
	Digest        string         `json:"digest"`
	Compatibility compatibility  `json:"compatibility"`
	Components    []bomComponent `json:"components"`
}

type compatibility struct {
	MinimumConsumerGeneration int `json:"minimumConsumerGeneration"`
	MaximumConsumerGeneration int `json:"maximumConsumerGeneration"`
}

type bomComponent struct {
	Kind             string `json:"kind"`
	Name             string `json:"name"`
	Size             int64  `json:"size"`
	ProvenanceDigest string `json:"provenanceDigest"`
}

// VerifyPinnedMaterial verifies the local pin, root BOM identity, and every
// schema byte binding. Published material can be required at production
// startup and readiness boundaries.
func VerifyPinnedMaterial(repositoryRoot string, requirePublished bool) error {
	contractRoot, err := os.OpenRoot(filepath.Join(repositoryRoot, "contracts"))
	if err != nil {
		return fmt.Errorf("open pinned contract root: %w", err)
	}
	defer contractRoot.Close()

	pinBytes, err := readRegularMaterial(contractRoot, "pin.json")
	if err != nil {
		return err
	}
	var pin materialPin
	if err := decodeStrict(pinBytes, &pin); err != nil {
		return fmt.Errorf("decode contract pin: %w", err)
	}
	if err := validatePin(pin, requirePublished); err != nil {
		return err
	}

	bomBytes, err := readRegularMaterial(contractRoot, "bom/release-bom.json")
	if err != nil {
		return err
	}
	if _, err := validator.Admit(bomBytes); err != nil {
		return fmt.Errorf("admit release BOM: %w", err)
	}
	var bom releaseBOM
	if err := json.Unmarshal(bomBytes, &bom); err != nil {
		return fmt.Errorf("decode release BOM: %w", err)
	}
	computedDigest, err := contractBOMDigest(bomBytes)
	if err != nil {
		return err
	}
	if !equalDigest(computedDigest, bom.Digest) || !equalDigest(bom.Digest, pin.BOMDigest) {
		return errors.New("release BOM identity does not match the pinned digest")
	}
	if bom.Version != pin.BOMVersion {
		return errors.New("release BOM version does not match the pin")
	}
	if pin.ConsumerGeneration < bom.Compatibility.MinimumConsumerGeneration || pin.ConsumerGeneration > bom.Compatibility.MaximumConsumerGeneration {
		return errors.New("consumer generation is outside release BOM compatibility")
	}
	if err := verifySchemaBindings(contractRoot, bom.Components); err != nil {
		return err
	}
	return nil
}

func validatePin(pin materialPin, requirePublished bool) error {
	if pin.PinVersion != 1 || pin.BOMVersion == "" || pin.ConsumerGeneration < 1 || pin.Source == "" {
		return errors.New("contract pin metadata is incomplete")
	}
	for name, digest := range map[string]string{
		"BOM": pin.BOMDigest, "OCI manifest": pin.OCIManifestDigest, "evidence manifest": pin.EvidenceManifestDigest,
	} {
		if !validDigest(digest) {
			return fmt.Errorf("%s digest is invalid", name)
		}
	}
	if pin.State != "published" && pin.State != "candidate-unpublished" {
		return fmt.Errorf("contract pin state %q is not recognized", pin.State)
	}
	if requirePublished && pin.State != "published" {
		return errors.New("production requires published contract material")
	}
	return nil
}

func verifySchemaBindings(contractRoot *os.Root, components []bomComponent) error {
	const prefix = "anvilkit.contract.schema."
	const suffix = ".v1"
	expected := make(map[string]bomComponent)
	for _, component := range components {
		if component.Kind != "json-schema" {
			continue
		}
		if !strings.HasPrefix(component.Name, prefix) || !strings.HasSuffix(component.Name, suffix) || !validDigest(component.ProvenanceDigest) || component.Size < 1 || component.Size > maximumMaterialBytes {
			return fmt.Errorf("release BOM contains invalid schema component %q", component.Name)
		}
		name := strings.TrimSuffix(strings.TrimPrefix(component.Name, prefix), suffix) + ".schema.json"
		if _, duplicate := expected[name]; duplicate {
			return fmt.Errorf("release BOM contains duplicate schema component %q", component.Name)
		}
		expected[name] = component
	}

	entries, err := fs.ReadDir(contractRoot.FS(), "schemas/v1")
	if err != nil {
		return fmt.Errorf("read pinned schema directory: %w", err)
	}
	seen := make(map[string]bool, len(expected))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".schema.json") {
			continue
		}
		component, ok := expected[entry.Name()]
		if !ok {
			return fmt.Errorf("pinned schema %s is absent from the release BOM", entry.Name())
		}
		raw, err := readRegularMaterial(contractRoot, "schemas/v1/"+entry.Name())
		if err != nil {
			return err
		}
		digest := sha256.Sum256(raw)
		actualDigest := "sha256:" + hex.EncodeToString(digest[:])
		if int64(len(raw)) != component.Size || !equalDigest(actualDigest, component.ProvenanceDigest) {
			return fmt.Errorf("pinned schema %s does not match the release BOM", entry.Name())
		}
		seen[entry.Name()] = true
	}
	if len(seen) != len(expected) {
		return errors.New("release BOM schema set is incomplete on disk")
	}
	return nil
}

func contractBOMDigest(raw []byte) (string, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil || object == nil {
		return "", errors.New("release BOM root must be an object")
	}
	if _, ok := object["digest"]; !ok {
		return "", errors.New("release BOM digest is absent")
	}
	delete(object, "digest")
	withoutDigest, err := json.Marshal(object)
	if err != nil {
		return "", fmt.Errorf("encode release BOM identity: %w", err)
	}
	canonical, err := jcs.Canonicalize(withoutDigest)
	if err != nil {
		return "", fmt.Errorf("canonicalize release BOM identity: %w", err)
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte("anvilkit.contract-bom.identity.v1\x00"))
	_, _ = hash.Write([]byte("application/vnd.anvilkit.contract-bom.v1+json"))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(canonical)
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func readRegularMaterial(root *os.Root, name string) ([]byte, error) {
	info, err := root.Lstat(name)
	if err != nil {
		return nil, fmt.Errorf("inspect pinned material %s: %w", name, err)
	}
	if !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maximumMaterialBytes {
		return nil, fmt.Errorf("pinned material %s must be a regular bounded file", name)
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, fmt.Errorf("open pinned material %s: %w", name, err)
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maximumMaterialBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read pinned material %s: %w", name, err)
	}
	if len(raw) > maximumMaterialBytes {
		return nil, fmt.Errorf("pinned material %s exceeds the byte limit", name)
	}
	return raw, nil
}

func decodeStrict(raw []byte, target any) error {
	if _, err := validator.Admit(raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON value")
	}
	return nil
}

func validDigest(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(value[7:])
	return err == nil
}

func equalDigest(left, right string) bool {
	return len(left) == len(right) && subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}
