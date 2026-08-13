package auth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
)

type keys map[string]ed25519.PublicKey

func (k keys) PublicKey(_ context.Context, id string) (ed25519.PublicKey, error) {
	key := k[id]
	if key == nil {
		return nil, fmt.Errorf("missing")
	}
	return key, nil
}

func TestJWSVerifierProjectsOnlySignedClaims(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	verifier, _ := NewJWSVerifier(keys{"key": public})
	payload := tokenClaims{Issuer: "issuer", Audience: "agent", Subject: "workload", ActorID: "actor", TenantID: "tenant", WorkspaceID: "workspace", ProjectID: "project", Purpose: "agent", Source: SourceDelegated, Scopes: []string{ScopeRead}, ExpiresAt: 2000, NotBefore: 1000}
	token := signToken(t, private, protectedHeader{Algorithm: "EdDSA", KeyID: "key", Type: "JWT"}, payload)
	claims, err := verifier.Verify(context.Background(), token)
	if err != nil || !claims.Verified || claims.WorkspaceID != "workspace" || claims.ActorID != "actor" {
		t.Fatalf("claims=%#v err=%v", claims, err)
	}
	parts := stringsSplit(token)
	parts[1] = base64.RawURLEncoding.EncodeToString([]byte(`{"workspaceId":"attacker"}`))
	if _, err := verifier.Verify(context.Background(), parts[0]+"."+parts[1]+"."+parts[2]); err == nil {
		t.Fatal("tampered browser claim accepted")
	}
}
func TestJWSVerifierRejectsAlgorithmAndUnknownFields(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	verifier, _ := NewJWSVerifier(keys{"key": public})
	token := signToken(t, private, protectedHeader{Algorithm: "none", KeyID: "key", Type: "JWT"}, tokenClaims{})
	if _, err := verifier.Verify(context.Background(), token); err == nil {
		t.Fatal("algorithm confusion accepted")
	}
	header := encodeJSON(t, protectedHeader{Algorithm: "EdDSA", KeyID: "key", Type: "JWT"})
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"issuer","unknown":true}`))
	signature := ed25519.Sign(private, []byte(header+"."+payload))
	if _, err := verifier.Verify(context.Background(), header+"."+payload+"."+base64.RawURLEncoding.EncodeToString(signature)); err == nil {
		t.Fatal("unknown signed claim accepted")
	}
}
func signToken(t *testing.T, private ed25519.PrivateKey, header protectedHeader, claims tokenClaims) string {
	t.Helper()
	encodedHeader, encodedPayload := encodeJSON(t, header), encodeJSON(t, claims)
	signature := ed25519.Sign(private, []byte(encodedHeader+"."+encodedPayload))
	return encodedHeader + "." + encodedPayload + "." + base64.RawURLEncoding.EncodeToString(signature)
}
func encodeJSON(t *testing.T, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}
func stringsSplit(value string) []string {
	result := make([]string, 0, 3)
	start := 0
	for index, character := range value {
		if character == '.' {
			result = append(result, value[start:index])
			start = index + 1
		}
	}
	return append(result, value[start:])
}
