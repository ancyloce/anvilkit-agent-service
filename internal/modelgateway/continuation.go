package modelgateway

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"sync"
	"time"
)

type RestartPolicy string

const (
	ResumeIfValid RestartPolicy = "resume-if-valid"
	RestartStage  RestartPolicy = "restart-stage"
	RestartRun    RestartPolicy = "restart-run"
)

type Continuation struct {
	Kind             string        `json:"kind"`
	EncryptedBinding string        `json:"encryptedBinding"`
	Provider         ProviderID    `json:"provider"`
	ExpiresAt        string        `json:"expiresAt"`
	RestartPolicy    RestartPolicy `json:"restartPolicy"`
	BindingDigest    string        `json:"bindingDigest"`
	// KeyReference is persistence metadata, not part of ProviderContinuation.
	KeyReference string `json:"-"`
}
type KeySource interface {
	Key(context.Context, string) ([]byte, error)
}
type ContinuationStore interface {
	Put(context.Context, string, Continuation) error
	Get(context.Context, string) (Continuation, bool, error)
	Delete(context.Context, string) error
}
type Continuations struct {
	keys   KeySource
	keyRef string
	store  ContinuationStore
	clock  Clock
	random io.Reader
}

func NewContinuations(keys KeySource, keyRef string, store ContinuationStore, clock Clock) (*Continuations, error) {
	if keys == nil || !validKeyReference(keyRef) || store == nil || clock == nil {
		return nil, fmt.Errorf("continuation encryption dependencies required")
	}
	return &Continuations{keys, keyRef, store, clock, rand.Reader}, nil
}
func (c *Continuations) Save(ctx context.Context, id string, provider ProviderID, plaintext []byte, bindingDigest string, expires time.Time, policy RestartPolicy) error {
	if id == "" || provider == "" || len(plaintext) == 0 || len(plaintext) > 16384 || !expires.After(c.clock.Now()) || !isSHA256(bindingDigest) || policy != ResumeIfValid && policy != RestartStage && policy != RestartRun {
		return fmt.Errorf("invalid continuation")
	}
	key, err := c.keys.Key(ctx, c.keyRef)
	if err != nil {
		return fmt.Errorf("load continuation key: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(c.random, nonce); err != nil {
		return err
	}
	record := Continuation{Kind: "ProviderContinuation", Provider: provider, ExpiresAt: expires.UTC().Truncate(time.Millisecond).Format("2006-01-02T15:04:05.000Z"), RestartPolicy: policy, BindingDigest: bindingDigest, KeyReference: c.keyRef}
	sealed := aead.Seal(nonce, nonce, plaintext, continuationAAD(id, record))
	record.EncryptedBinding = base64.RawURLEncoding.EncodeToString(sealed)
	return c.store.Put(ctx, id, record)
}

type Resume struct {
	Continuation []byte
	Checkpoint   string
	Restarted    bool
}

func (c *Continuations) Resume(ctx context.Context, id, bindingDigest, safeCheckpoint string) (Resume, error) {
	if id == "" || !isSHA256(bindingDigest) || safeCheckpoint == "" {
		return Resume{}, fmt.Errorf("invalid continuation resume binding")
	}
	record, ok, err := c.store.Get(ctx, id)
	if err != nil || !ok {
		return Resume{Checkpoint: safeCheckpoint, Restarted: true}, nil
	}
	expires, err := time.Parse("2006-01-02T15:04:05.000Z", record.ExpiresAt)
	if err != nil || record.Kind != "ProviderContinuation" || record.Provider == "" || !isSHA256(record.BindingDigest) || record.RestartPolicy != ResumeIfValid && record.RestartPolicy != RestartStage && record.RestartPolicy != RestartRun || !c.clock.Now().Before(expires) || record.BindingDigest != bindingDigest {
		return Resume{Checkpoint: safeCheckpoint, Restarted: true}, nil
	}
	keyReference := record.KeyReference
	if keyReference == "" {
		keyReference = c.keyRef
	}
	if !validKeyReference(keyReference) {
		return Resume{Checkpoint: safeCheckpoint, Restarted: true}, nil
	}
	key, err := c.keys.Key(ctx, keyReference)
	if err != nil {
		return Resume{Checkpoint: safeCheckpoint, Restarted: true}, nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return Resume{Checkpoint: safeCheckpoint, Restarted: true}, nil
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return Resume{Checkpoint: safeCheckpoint, Restarted: true}, nil
	}
	sealed, err := base64.RawURLEncoding.DecodeString(record.EncryptedBinding)
	if err != nil || len(sealed) < aead.NonceSize() {
		return Resume{Checkpoint: safeCheckpoint, Restarted: true}, nil
	}
	plaintext, err := aead.Open(nil, sealed[:aead.NonceSize()], sealed[aead.NonceSize():], continuationAAD(id, record))
	if err != nil {
		return Resume{Checkpoint: safeCheckpoint, Restarted: true}, nil
	}
	return Resume{Continuation: plaintext}, nil
}
func continuationAAD(id string, record Continuation) []byte {
	return []byte(id + "\x00" + record.KeyReference + "\x00" + string(record.Provider) + "\x00" + record.ExpiresAt + "\x00" + string(record.RestartPolicy) + "\x00" + record.BindingDigest)
}

func validKeyReference(value string) bool {
	if len(value) < 1 || len(value) > 512 {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character == 0x7f {
			return false
		}
	}
	return true
}

type MemoryContinuationStore struct {
	lock   sync.Mutex
	values map[string]Continuation
}

func NewMemoryContinuationStore() *MemoryContinuationStore {
	return &MemoryContinuationStore{values: map[string]Continuation{}}
}
func (s *MemoryContinuationStore) Put(_ context.Context, id string, value Continuation) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.values[id] = value
	return nil
}
func (s *MemoryContinuationStore) Get(_ context.Context, id string) (Continuation, bool, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	value, ok := s.values[id]
	return value, ok, nil
}
func (s *MemoryContinuationStore) Delete(_ context.Context, id string) error {
	s.lock.Lock()
	defer s.lock.Unlock()
	delete(s.values, id)
	return nil
}
func (s *MemoryContinuationStore) Corrupt(id string) {
	s.lock.Lock()
	defer s.lock.Unlock()
	value := s.values[id]
	value.EncryptedBinding = "corrupt"
	s.values[id] = value
}
