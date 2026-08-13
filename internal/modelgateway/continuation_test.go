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
