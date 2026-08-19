package contracts

import (
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

	"github.com/ancyloce/anvilkit-agent-service/contracts/validator"
)

const maximumMaterialBytes = 1_048_576

// materialPin binds the service's contract intake to the exact canonical
// P0-Kernel Profile and lock produced by the platform repository (ADR-018).
// Contract identity is the canonical path, content digest, profile, lock, and
// repository commit — no release generation, consumer generation window, or
// publication state machine exists in the canonical system.
type materialPin struct {
	PinVersion int          `json:"pinVersion"`
	State      string       `json:"state"`
	Profile    materialFile `json:"profile"`
	Lock       materialFile `json:"lock"`
	Source     string       `json:"source"`
}

type materialFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type canonicalLock struct {
	LockVersion int               `json:"lockVersion"`
	Profile     materialFile      `json:"profile"`
	Sources     map[string]string `json:"sources"`
}

// VerifyPinnedMaterial verifies the local pin, the pinned canonical profile
// and lock copies, and every canonical schema byte binding. It is
// self-contained: only material inside the service checkout is read, so the
// same verification runs at production startup and readiness boundaries.
func VerifyPinnedMaterial(repositoryRoot string) error {
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
	if pin.PinVersion != 1 || pin.State != "canonical" || pin.Source == "" {
		return errors.New("contract pin metadata is incomplete or not canonical")
	}
	if pin.Profile.Path != "agent/profile/p0-kernel-profile.json" || pin.Lock.Path != "agent/lock/contracts.lock.json" {
		return errors.New("contract pin does not reference the canonical profile and lock")
	}
	if !validDigest(pin.Profile.SHA256) || !validDigest(pin.Lock.SHA256) {
		return errors.New("contract pin digests are invalid")
	}

	profileBytes, err := readRegularMaterial(contractRoot, pin.Profile.Path)
	if err != nil {
		return err
	}
	if !equalDigest(digestOf(profileBytes), pin.Profile.SHA256) {
		return errors.New("pinned profile bytes do not match the pin digest")
	}
	lockBytes, err := readRegularMaterial(contractRoot, pin.Lock.Path)
	if err != nil {
		return err
	}
	if !equalDigest(digestOf(lockBytes), pin.Lock.SHA256) {
		return errors.New("pinned lock bytes do not match the pin digest")
	}
	if _, err := validator.Admit(lockBytes); err != nil {
		return fmt.Errorf("admit canonical lock: %w", err)
	}
	var lock canonicalLock
	if err := json.Unmarshal(lockBytes, &lock); err != nil {
		return fmt.Errorf("decode canonical lock: %w", err)
	}
	if lock.LockVersion != 1 || len(lock.Sources) == 0 {
		return errors.New("canonical lock is incomplete")
	}
	if !equalDigest(lock.Profile.SHA256, pin.Profile.SHA256) {
		return errors.New("canonical lock does not bind the pinned profile")
	}
	return verifySchemaBindings(contractRoot, lock.Sources)
}

// verifySchemaBindings requires every canonical schema recorded in the lock to
// be present in the intake with exactly the locked bytes, and rejects any
// intake schema absent from the lock.
func verifySchemaBindings(contractRoot *os.Root, sources map[string]string) error {
	const lockPrefix = "contracts/agent/schemas/"
	expected := make(map[string]string)
	for path, digest := range sources {
		if !strings.HasPrefix(path, lockPrefix) || !strings.HasSuffix(path, ".schema.json") {
			continue
		}
		if !validDigest(digest) {
			return fmt.Errorf("canonical lock digest for %s is invalid", path)
		}
		expected[strings.TrimPrefix(path, "contracts/")] = digest
	}
	if len(expected) == 0 {
		return errors.New("canonical lock contains no schema sources")
	}
	seen := 0
	for _, directory := range []string{"agent/schemas", "agent/schemas/meta"} {
		entries, err := fs.ReadDir(contractRoot.FS(), directory)
		if err != nil {
			return fmt.Errorf("read pinned schema directory %s: %w", directory, err)
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".schema.json") {
				continue
			}
			name := directory + "/" + entry.Name()
			digest, ok := expected[name]
			if !ok {
				return fmt.Errorf("pinned schema %s is absent from the canonical lock", name)
			}
			raw, err := readRegularMaterial(contractRoot, name)
			if err != nil {
				return err
			}
			if !equalDigest(digestOf(raw), digest) {
				return fmt.Errorf("pinned schema %s does not match the canonical lock", name)
			}
			seen++
		}
	}
	if seen != len(expected) {
		return errors.New("canonical schema set is incomplete on disk")
	}
	return nil
}

func digestOf(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
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
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
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
