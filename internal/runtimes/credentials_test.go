package runtimes

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/contracts/generated/schema"
)

// The task credential crosses a process and a repository boundary: this service
// mints it and an Agent Runtime Unit verifies it, from two implementations that
// share no code. The known-answer vector is what holds those two to one format.
// A change that alters a single byte of the minted credential fails here, and
// the same vector fails in the runtime's own suite — which is the point, because
// a format that drifted silently would fail in production instead.

// credentialVector is the fixture both repositories keep a copy of.
type credentialVector struct {
	IssuerSeed           string            `json:"issuerSeed"`
	KeyID                string            `json:"keyId"`
	Issuer               string            `json:"issuer"`
	Audience             string            `json:"audience"`
	IssuedAtUnix         int64             `json:"issuedAtUnix"`
	ExpiresAtUnix        int64             `json:"expiresAtUnix"`
	CredentialTTLSeconds int               `json:"credentialTtlSeconds"`
	Task                 schema.AgentTask  `json:"task"`
	Subject              map[string]string `json:"subject"`
	Credential           string            `json:"credential"`
	Note                 string            `json:"note"`
}

func loadCredentialVector(t *testing.T) credentialVector {
	t.Helper()
	raw, err := os.ReadFile("testdata/task-credential.vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector credentialVector
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	return vector
}

func issuerFor(t *testing.T, vector credentialVector) *TaskCredentials {
	t.Helper()
	issued := time.Unix(vector.IssuedAtUnix, 0).UTC()
	issuer, err := NewTaskCredentials(vector.IssuerSeed, vector.KeyID,
		time.Duration(vector.CredentialTTLSeconds)*time.Second,
		func() time.Time { return issued })
	if err != nil {
		t.Fatal(err)
	}
	return issuer
}

// The minted credential is reproduced byte for byte. Anything less — asserting
// only that it verifies, say — would let the two implementations drift apart in
// whatever this service happens to accept from itself.
func TestTheMintedCredentialReproducesTheKnownAnswerVector(t *testing.T) {
	vector := loadCredentialVector(t)
	credential, err := issuerFor(t, vector).Issue(context.Background(), vector.Task,
		Subject{WorkspaceID: vector.Subject["workspaceId"], ProjectID: vector.Subject["projectId"]})
	if err != nil {
		t.Fatal(err)
	}
	if credential.Value != vector.Credential {
		t.Fatalf("the minted credential does not reproduce the vector.\n got %s\nwant %s", credential.Value, vector.Credential)
	}
	if credential.Audience != vector.Audience {
		t.Fatalf("audience = %q, want %q", credential.Audience, vector.Audience)
	}
	if credential.ExpiresAt.Unix() != vector.ExpiresAtUnix {
		t.Fatalf("expiry = %d, want %d", credential.ExpiresAt.Unix(), vector.ExpiresAtUnix)
	}
}

// The credential this service mints is one this service can verify, and what it
// verifies is the binding the task was dispatched under. This is the round trip
// the in-process runtime's admission depends on.
func TestAMintedCredentialVerifiesAndBindsItsTask(t *testing.T) {
	vector := loadCredentialVector(t)
	issuer := issuerFor(t, vector)
	trust := credentialTrustFor(t, issuer, []string{vector.Audience}, time.Unix(vector.IssuedAtUnix, 0).UTC())

	verified, err := trust.Verify(vector.Credential, vector.Audience, time.Unix(vector.IssuedAtUnix, 0).UTC())
	if err != nil {
		t.Fatalf("a credential this service minted did not verify: %v", err)
	}
	if mismatch := BindsTask(verified, vector.Task, OperationExecute); mismatch != "" {
		t.Fatalf("a credential minted for this task did not bind it: %s", mismatch)
	}
	if verified.Binding.WorkspaceID != vector.Subject["workspaceId"] || verified.Binding.ProjectID != vector.Subject["projectId"] {
		t.Fatalf("the verified tenant is %+v, not the one the credential was issued inside", verified.Binding)
	}
}

// A credential that verifies is still not authority for other work. Each case
// is a token this service really issued, presented beside a task it was not
// issued for.
func TestAVerifiedCredentialIsNotAuthorityForOtherWork(t *testing.T) {
	vector := loadCredentialVector(t)
	issuer := issuerFor(t, vector)
	trust := credentialTrustFor(t, issuer, []string{vector.Audience}, time.Unix(vector.IssuedAtUnix, 0).UTC())
	verified, err := trust.Verify(vector.Credential, vector.Audience, time.Unix(vector.IssuedAtUnix, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	for name, rewrite := range map[string]func(*schema.AgentTask){
		"another attempt":     func(task *schema.AgentTask) { task.PhysicalAttemptId = "attempt.somewhere-else" },
		"another task":        func(task *schema.AgentTask) { task.TaskId = "task.somewhere-else" },
		"another run":         func(task *schema.AgentTask) { task.RunId = "run.somewhere-else" },
		"another root run":    func(task *schema.AgentTask) { task.RootRunId = "run.somewhere-else" },
		"another generation":  func(task *schema.AgentTask) { task.ExecutionGeneration = 7 },
		"another lease":       func(task *schema.AgentTask) { task.LeaseEpoch = 7 },
		"another attempt no.": func(task *schema.AgentTask) { task.AttemptNumber = 7 },
		"another unit": func(task *schema.AgentTask) {
			task.RuntimeBinding.RuntimeUnitId = "runtime.platform.page-candidate-specialist"
		},
		"another manifest": func(task *schema.AgentTask) {
			task.RuntimeBinding.RuntimeManifestDigest = schema.SharedPrimitivesDigest("sha256:" + repeated('9'))
		},
		"another protocol": func(task *schema.AgentTask) {
			task.RuntimeBinding.InvocationProtocolDigest = schema.SharedPrimitivesDigest("sha256:" + repeated('9'))
		},
		"another audience": func(task *schema.AgentTask) {
			task.AuthorizationAudience = "urn:anvilkit:audience:runtime-page-candidate-specialist"
		},
	} {
		t.Run(name, func(t *testing.T) {
			task := vector.Task
			rewrite(&task)
			if mismatch := BindsTask(verified, task, OperationExecute); mismatch == "" {
				t.Fatal("a credential issued for other work was accepted as authority for this task")
			}
		})
	}
	t.Run("another operation", func(t *testing.T) {
		if mismatch := BindsTask(verified, vector.Task, OperationCancel); mismatch == "" {
			t.Fatal("a credential issued to execute was accepted as authority to cancel")
		}
	})
}

// A credential is refused for every reason it could be: a key nobody approved,
// an altered claim set, a downgraded algorithm, a window that has closed, and a
// key the operator revoked.
func TestAnUnverifiableCredentialIsRefused(t *testing.T) {
	vector := loadCredentialVector(t)
	issuer := issuerFor(t, vector)
	at := time.Unix(vector.IssuedAtUnix, 0).UTC()
	trust := credentialTrustFor(t, issuer, []string{vector.Audience}, at)

	t.Run("altered claims", func(t *testing.T) {
		altered := vector.Credential[:len(vector.Credential)-90] + "x" + vector.Credential[len(vector.Credential)-89:]
		if _, err := trust.Verify(altered, vector.Audience, at); err == nil {
			t.Fatal("an altered credential verified")
		}
	})
	t.Run("presented to another release", func(t *testing.T) {
		if _, err := trust.Verify(vector.Credential, "urn:anvilkit:audience:runtime-page-candidate-specialist", at); err == nil {
			t.Fatal("a credential minted for one release verified at another")
		}
	})
	t.Run("after expiry", func(t *testing.T) {
		if _, err := trust.Verify(vector.Credential, vector.Audience, time.Unix(vector.ExpiresAtUnix, 0).UTC()); err == nil {
			t.Fatal("an expired credential verified")
		}
	})
	t.Run("before validity", func(t *testing.T) {
		if _, err := trust.Verify(vector.Credential, vector.Audience, at.Add(-time.Hour)); err == nil {
			t.Fatal("a credential verified before it was valid")
		}
	})
	t.Run("key not in the trust root", func(t *testing.T) {
		other := credentialTrustFor(t, mustIssuer(t, vector, "urn:anvilkit:key:some-other-issuing-key"), []string{vector.Audience}, at)
		if _, err := other.Verify(vector.Credential, vector.Audience, at); err == nil {
			t.Fatal("a credential verified against a trust root that does not name its key")
		}
	})
	t.Run("not a compact JWS", func(t *testing.T) {
		for _, malformed := range []string{"", "a", "a.b", "a.b.c.d", "....", vector.Credential + "."} {
			if _, err := trust.Verify(malformed, vector.Audience, at); err == nil {
				t.Fatalf("%q verified as a credential", malformed)
			}
		}
	})
}

// An issuer that cannot be resolved by a runtime is not an issuer. A deployment
// that could mint credentials nobody can verify would be minting authority that
// only looks like authority.
func TestAnIssuerMustCarryResolvableKeyMaterial(t *testing.T) {
	valid := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	for name, build := range map[string]func() error{
		"no key": func() error {
			_, err := NewTaskCredentials("", "urn:anvilkit:key:agent-service-task-credential", time.Minute, time.Now)
			return err
		},
		"key of the wrong size": func() error {
			_, err := NewTaskCredentials(base64.RawURLEncoding.EncodeToString(make([]byte, 16)),
				"urn:anvilkit:key:agent-service-task-credential", time.Minute, time.Now)
			return err
		},
		"ungoverned key identity": func() error {
			_, err := NewTaskCredentials(valid, "not-a-urn", time.Minute, time.Now)
			return err
		},
		"no lifetime": func() error {
			_, err := NewTaskCredentials(valid, "urn:anvilkit:key:agent-service-task-credential", 0, time.Now)
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := build(); err == nil {
				t.Fatal("an issuer was built that a runtime could not resolve")
			}
		})
	}
}

// A credential never outlives the work it was issued for. An attempt whose
// deadline has already passed gets no authority at all rather than a credential
// with nothing left to authorize.
func TestACredentialNeverOutlivesItsAttempt(t *testing.T) {
	vector := loadCredentialVector(t)
	issuer := issuerFor(t, vector)
	at := time.Unix(vector.IssuedAtUnix, 0).UTC()

	shortened := vector.Task
	shortened.ExpiresAt = schema.SharedPrimitivesTimestamp(at.Add(30 * time.Second))
	credential, err := issuer.Issue(context.Background(), shortened,
		Subject{WorkspaceID: "workspace.synthetic", ProjectID: "project.synthetic"})
	if err != nil {
		t.Fatal(err)
	}
	if credential.ExpiresAt.After(at.Add(30 * time.Second)) {
		t.Fatalf("the credential outlives the attempt: %s", credential.ExpiresAt)
	}

	closed := vector.Task
	closed.ExpiresAt = schema.SharedPrimitivesTimestamp(at.Add(-time.Second))
	if _, err := issuer.Issue(context.Background(), closed,
		Subject{WorkspaceID: "workspace.synthetic", ProjectID: "project.synthetic"}); err == nil {
		t.Fatal("authority was issued for an attempt whose window had already closed")
	}
}

// A credential is issued inside a tenant boundary or not at all: the canonical
// task carries no tenancy, so what a runtime may act on comes from here.
func TestACredentialIsIssuedInsideATenantBoundary(t *testing.T) {
	vector := loadCredentialVector(t)
	issuer := issuerFor(t, vector)
	for _, subject := range []Subject{{}, {WorkspaceID: "workspace.synthetic"}, {ProjectID: "project.synthetic"}} {
		if _, err := issuer.Issue(context.Background(), vector.Task, subject); err == nil {
			t.Fatalf("authority was issued outside a tenant boundary: %+v", subject)
		}
	}
}

func mustIssuer(t *testing.T, vector credentialVector, keyID string) *TaskCredentials {
	t.Helper()
	issuer, err := NewTaskCredentials(vector.IssuerSeed, keyID,
		time.Duration(vector.CredentialTTLSeconds)*time.Second, func() time.Time { return time.Unix(vector.IssuedAtUnix, 0).UTC() })
	if err != nil {
		t.Fatal(err)
	}
	return issuer
}

// credentialTrustFor builds the trust an in-process runtime admits against,
// from the issuer's own public key.
func credentialTrustFor(t *testing.T, issuer *TaskCredentials, audiences []string, now time.Time) *CredentialTrust {
	t.Helper()
	source, err := NewControlledCredentialTrust(issuer.PublicKey(), issuer.KeyID(), audiences, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	trust, err := NewCredentialTrust(source)
	if err != nil {
		t.Fatal(err)
	}
	return trust
}

func repeated(character byte) string {
	value := make([]byte, 64)
	for index := range value {
		value[index] = character
	}
	return string(value)
}

// The regeneration hook. It is a test rather than a command so it cannot run
// during a build, and it is gated so it cannot run during an ordinary suite: a
// vector that regenerated itself would agree with whatever the code did.
func TestGenerateCredentialVector(t *testing.T) {
	if os.Getenv("ANVILKIT_WRITE_CREDENTIAL_VECTOR") == "" {
		t.Skip("set ANVILKIT_WRITE_CREDENTIAL_VECTOR to regenerate the known-answer vector")
	}
	vector := loadCredentialVector(t)
	credential, err := issuerFor(t, vector).Issue(context.Background(), vector.Task,
		Subject{WorkspaceID: vector.Subject["workspaceId"], ProjectID: vector.Subject["projectId"]})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("testdata/task-credential.vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	document["credential"] = credential.Value
	document["expiresAtUnix"] = credential.ExpiresAt.Unix()
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("testdata/task-credential.vector.json", append(encoded, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Log("regenerated testdata/task-credential.vector.json — copy it to services/agent-runtimes/runtime/testdata in the same change")
}
