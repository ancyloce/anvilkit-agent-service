package modelgateway

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	contractvalidator "github.com/ancyloce/anvilkit-agent-service/contracts/validator"
)

type keys struct{ value []byte }

func (k keys) Key(context.Context, string) ([]byte, error) {
	return append([]byte(nil), k.value...), nil
}

type keyring map[string][]byte

func (k keyring) Key(_ context.Context, reference string) ([]byte, error) {
	value, ok := k[reference]
	if !ok {
		return nil, context.Canceled
	}
	return append([]byte(nil), value...), nil
}
func TestContinuationEncryptedOptionalAndLossRestartsSafely(t *testing.T) {
	store := NewMemoryContinuationStore()
	clock := clock{time.Unix(100, 0)}
	service, _ := NewContinuations(keys{bytes.Repeat([]byte{1}, 32)}, "kms://continuation", store, clock)
	service.random = bytes.NewReader(bytes.Repeat([]byte{2}, 64))
	plain := []byte("provider-secret-continuation")
	digest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := service.Save(context.Background(), "run:stage", FakeProviderID, plain, digest, time.Unix(200, 0), RestartStage); err != nil {
		t.Fatal(err)
	}
	record, _, _ := store.Get(context.Background(), "run:stage")
	if bytes.Contains([]byte(record.EncryptedBinding), plain) {
		t.Fatal("continuation stored in plaintext")
	}
	raw, _ := json.Marshal(record)
	validator, err := contractvalidator.New("../..")
	if err != nil {
		t.Fatal(err)
	}
	const schema = "anvilkit://schema/provider-continuation.v1@1.0.0?digest=sha256:68810769703a8bb093f06deec27b822877a655ffef7770d06144a4c5c10143fb"
	if findings := validator.Validate(schema, raw); len(findings) != 0 {
		t.Fatalf("ProviderContinuationV1 findings: %#v", findings)
	}
	resumed, err := service.Resume(context.Background(), "run:stage", digest, "planning:checkpoint")
	if err != nil || !bytes.Equal(resumed.Continuation, plain) || resumed.Restarted {
		t.Fatalf("resume=%#v err=%v", resumed, err)
	}
	store.Corrupt("run:stage")
	fallback, _ := service.Resume(context.Background(), "run:stage", digest, "planning:checkpoint")
	if !fallback.Restarted || fallback.Checkpoint != "planning:checkpoint" || len(fallback.Continuation) != 0 {
		t.Fatalf("fallback=%#v", fallback)
	}
	_ = store.Delete(context.Background(), "run:stage")
	missing, _ := service.Resume(context.Background(), "run:stage", digest, "planning:checkpoint")
	if !missing.Restarted || !reflect.DeepEqual(fallback, missing) {
		t.Fatal("missing continuation became authority")
	}
}

func TestContinuationPinsEncryptionKeyReferenceAcrossRotation(t *testing.T) {
	store := NewMemoryContinuationStore()
	clock := clock{time.Unix(100, 0)}
	ring := keyring{"kms://old": bytes.Repeat([]byte{1}, 32), "kms://new": bytes.Repeat([]byte{2}, 32)}
	old, err := NewContinuations(ring, "kms://old", store, clock)
	if err != nil {
		t.Fatal(err)
	}
	old.random = bytes.NewReader(bytes.Repeat([]byte{3}, 64))
	digest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := old.Save(context.Background(), "run:rotated", FakeProviderID, []byte("opaque"), digest, time.Unix(200, 0), ResumeIfValid); err != nil {
		t.Fatal(err)
	}
	current, _ := NewContinuations(ring, "kms://new", store, clock)
	resumed, err := current.Resume(context.Background(), "run:rotated", digest, "planning:safe")
	if err != nil || string(resumed.Continuation) != "opaque" || resumed.Restarted {
		t.Fatalf("rotated key resume=%#v err=%v", resumed, err)
	}
	record, _, _ := store.Get(context.Background(), "run:rotated")
	if record.KeyReference != "kms://old" {
		t.Fatalf("key reference not pinned: %#v", record)
	}
	record.KeyReference = "kms://new"
	_ = store.Put(context.Background(), "run:rotated", record)
	tampered, _ := current.Resume(context.Background(), "run:rotated", digest, "planning:safe")
	if !tampered.Restarted || tampered.Checkpoint != "planning:safe" {
		t.Fatalf("key-reference substitution was authoritative: %#v", tampered)
	}
}
