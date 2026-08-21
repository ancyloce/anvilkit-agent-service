package applyauth

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestSeededKeyRingIsDeterministicPerMaterial(t *testing.T) {
	material := []byte("operator-signing-material-01")
	first, err := NewSeededKeyRing(material)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewSeededKeyRing(material)
	if err != nil {
		t.Fatal(err)
	}
	firstKey, err := first.ActiveKeyID(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	secondKey, err := second.ActiveKeyID(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if firstKey != secondKey || !validKeyID(firstKey) || !strings.HasPrefix(firstKey, "urn:anvilkit:key:") {
		t.Fatalf("key identities %q and %q must be the same valid identity", firstKey, secondKey)
	}
	message := []byte("signing-input")
	firstSignature, err := first.Sign(context.Background(), firstKey, message)
	if err != nil {
		t.Fatal(err)
	}
	secondSignature, err := second.Sign(context.Background(), secondKey, message)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstSignature, secondSignature) {
		t.Fatal("the same material must derive the same signing key across restarts")
	}
	public, err := first.PublicKey(context.Background(), firstKey)
	if err != nil {
		t.Fatal(err)
	}
	rotatedPublic, err := second.PublicKey(context.Background(), secondKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(public, rotatedPublic) {
		t.Fatal("public verification material must be stable per material")
	}
}

func TestSeededKeyRingSeparatesMaterialAndRejectsWeakMaterial(t *testing.T) {
	first, err := NewSeededKeyRing([]byte("operator-signing-material-01"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewSeededKeyRing([]byte("operator-signing-material-02"))
	if err != nil {
		t.Fatal(err)
	}
	firstKey, _ := first.ActiveKeyID(context.Background())
	secondKey, _ := second.ActiveKeyID(context.Background())
	if firstKey == secondKey {
		t.Fatal("different material must derive different key identities")
	}
	if _, err := NewSeededKeyRing([]byte("short")); err == nil {
		t.Fatal("weak signing material must be rejected")
	}
}
