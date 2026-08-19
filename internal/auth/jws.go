package auth

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	contractvalidator "github.com/ancyloce/anvilkit-agent-service/contracts/validator"
)

type KeyResolver interface {
	PublicKey(context.Context, string) (ed25519.PublicKey, error)
}
type JWSVerifier struct{ keys KeyResolver }

func NewJWSVerifier(keys KeyResolver) (*JWSVerifier, error) {
	if keys == nil {
		return nil, fmt.Errorf("JWS key resolver is required")
	}
	return &JWSVerifier{keys: keys}, nil
}

type protectedHeader struct {
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
	Type      string `json:"typ"`
}
type tokenClaims struct {
	Issuer      string   `json:"iss"`
	Audience    string   `json:"aud"`
	Subject     string   `json:"sub"`
	ActorID     string   `json:"actorId"`
	WorkspaceID string   `json:"workspaceId"`
	ProjectID   string   `json:"projectId"`
	Purpose     string   `json:"purpose"`
	Source      Source   `json:"source"`
	Scopes      []string `json:"scopes"`
	ExpiresAt   int64    `json:"exp"`
	NotBefore   int64    `json:"nbf"`
}

func (v *JWSVerifier) Verify(ctx context.Context, compact string) (Claims, error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return Claims{}, fmt.Errorf("verify JWS: compact token must have three segments")
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Claims{}, fmt.Errorf("verify JWS header: %w", err)
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Claims{}, fmt.Errorf("verify JWS payload: %w", err)
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return Claims{}, fmt.Errorf("verify JWS signature: %w", err)
	}
	var header protectedHeader
	if err := strictJSON(headerBytes, &header); err != nil || header.Algorithm != "EdDSA" || header.KeyID == "" || header.Type != "JWT" {
		return Claims{}, fmt.Errorf("verify JWS: protected header is invalid")
	}
	key, err := v.keys.PublicKey(ctx, header.KeyID)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return Claims{}, fmt.Errorf("verify JWS: key is unavailable")
	}
	if !ed25519.Verify(key, []byte(parts[0]+"."+parts[1]), signature) {
		return Claims{}, fmt.Errorf("verify JWS: signature is invalid")
	}
	var token tokenClaims
	if err := strictJSON(payloadBytes, &token); err != nil {
		return Claims{}, fmt.Errorf("verify JWS claims: %w", err)
	}
	return Claims{Verified: true, Source: token.Source, Issuer: token.Issuer, Audience: token.Audience, Subject: token.Subject, ActorID: token.ActorID, WorkspaceID: token.WorkspaceID, ProjectID: token.ProjectID, Purpose: token.Purpose, KeyID: header.KeyID, Scopes: append([]string(nil), token.Scopes...), ExpiresAt: time.Unix(token.ExpiresAt, 0), NotBefore: time.Unix(token.NotBefore, 0)}, nil
}

func strictJSON(raw []byte, target any) error {
	if _, err := contractvalidator.Admit(raw); err != nil {
		return fmt.Errorf("strict JSON admission: %w", err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("trailing JSON")
		}
		return err
	}
	return nil
}
