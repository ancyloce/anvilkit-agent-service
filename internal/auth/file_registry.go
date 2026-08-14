package auth

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	contractvalidator "github.com/ancyloce/anvilkit-agent-service/contracts/validator"
)

type FileRegistry struct{ path string }
type registryFile struct {
	Keys        map[string]registryKey `json:"keys"`
	Subjects    map[string]string      `json:"subjects"`
	Delegations map[string]string      `json:"delegations"`
}
type registryKey struct {
	PublicKey string `json:"publicKey"`
	Status    string `json:"status"`
}

func NewFileRegistry(path string) (*FileRegistry, error) {
	if path == "" {
		return nil, fmt.Errorf("trust registry path is required")
	}
	registry := &FileRegistry{path: path}
	if _, err := registry.load(); err != nil {
		return nil, err
	}
	return registry, nil
}
func (r *FileRegistry) PublicKey(_ context.Context, keyID string) (ed25519.PublicKey, error) {
	registry, err := r.load()
	if err != nil {
		return nil, err
	}
	entry, ok := registry.Keys[keyID]
	if !ok || entry.Status != "active" {
		return nil, fmt.Errorf("key is not active")
	}
	raw, err := base64.RawURLEncoding.DecodeString(entry.PublicKey)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("key material is invalid")
	}
	return ed25519.PublicKey(raw), nil
}
func (r *FileRegistry) KeyActive(ctx context.Context, keyID string) (bool, error) {
	registry, err := r.load()
	if err != nil {
		return false, err
	}
	entry, ok := registry.Keys[keyID]
	return ok && entry.Status == "active", nil
}
func (r *FileRegistry) SubjectActive(_ context.Context, subject string) (bool, error) {
	registry, err := r.load()
	if err != nil {
		return false, err
	}
	return registry.Subjects[subject] == "active", nil
}
func (r *FileRegistry) DelegationActive(_ context.Context, subject, actor string) (bool, error) {
	registry, err := r.load()
	if err != nil {
		return false, err
	}
	return registry.Delegations[subject+"\x00"+actor] == "active", nil
}
func (r *FileRegistry) load() (registryFile, error) {
	raw, err := os.ReadFile(r.path)
	if err != nil {
		return registryFile{}, fmt.Errorf("read trust registry: %w", err)
	}
	if _, err := contractvalidator.Admit(raw); err != nil {
		return registryFile{}, fmt.Errorf("admit trust registry: %w", err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	var registry registryFile
	if err := decoder.Decode(&registry); err != nil {
		return registryFile{}, fmt.Errorf("decode trust registry: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return registryFile{}, fmt.Errorf("decode trust registry: trailing JSON")
	}
	if len(registry.Keys) == 0 {
		return registryFile{}, fmt.Errorf("trust registry has no keys")
	}
	if len(registry.Keys) > 10_000 || len(registry.Subjects) > 100_000 || len(registry.Delegations) > 100_000 {
		return registryFile{}, fmt.Errorf("trust registry exceeds bounded entries")
	}
	for keyID, entry := range registry.Keys {
		raw, decodeErr := base64.RawURLEncoding.DecodeString(entry.PublicKey)
		if keyID == "" || len(keyID) > 256 || !validStatus(entry.Status) || decodeErr != nil || len(raw) != ed25519.PublicKeySize {
			return registryFile{}, fmt.Errorf("trust registry key entry is invalid")
		}
	}
	for subject, status := range registry.Subjects {
		if subject == "" || len(subject) > 256 || !validStatus(status) {
			return registryFile{}, fmt.Errorf("trust registry subject entry is invalid")
		}
	}
	for delegation, status := range registry.Delegations {
		if delegation == "" || len(delegation) > 513 || !strings.Contains(delegation, "\x00") || !validStatus(status) {
			return registryFile{}, fmt.Errorf("trust registry delegation entry is invalid")
		}
	}
	return registry, nil
}

func validStatus(value string) bool { return value == "active" || value == "revoked" }

var _ KeyResolver = (*FileRegistry)(nil)
var _ Trust = (*FileRegistry)(nil)
