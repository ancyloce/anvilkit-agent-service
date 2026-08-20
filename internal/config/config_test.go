package config

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
)

func TestPagixBoundaryHasNoDatabaseCredentialSurface(t *testing.T) {
	typ := reflect.TypeOf(Config{})
	for index := 0; index < typ.NumField(); index++ {
		name := strings.ToLower(typ.Field(index).Name)
		if strings.Contains(name, "pagix") && (strings.Contains(name, "database") || strings.Contains(name, "password") || strings.Contains(name, "username")) {
			t.Fatalf("Pagix database credential surface exists: %s", typ.Field(index).Name)
		}
	}
}

func TestBudgetHeadroomPolicyIsTypedAndBounded(t *testing.T) {
	t.Setenv("ANVILKIT_BUDGET_REVIEW_BASIS_POINTS", "10001")
	if _, err := Load(); err == nil {
		t.Fatal("invalid budget review threshold accepted")
	}
}

func TestLoadRejectsInvalidTypedValueWithStableField(t *testing.T) {
	t.Setenv("ANVILKIT_WORKFLOW_POOL_SIZE", "many")
	_, err := Load()
	var details problem.Details
	if !errors.As(err, &details) {
		t.Fatalf("expected problem details, got %T: %v", err, err)
	}
	if details.Code != "CONFIG_INVALID" || details.Fields["ANVILKIT_WORKFLOW_POOL_SIZE"] == "" {
		t.Fatalf("unexpected problem: %#v", details)
	}
}

func TestProductionRejectsFakeProvider(t *testing.T) {
	t.Setenv("ANVILKIT_ENVIRONMENT", "production")
	t.Setenv("ANVILKIT_PROVIDER_ENABLED", "true")
	t.Setenv("ANVILKIT_PROVIDER_PRIORITY", "fake-provider")
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "fake and mock providers") {
		t.Fatalf("expected production fake rejection, got %v", err)
	}
}
func TestProductionRejectsFakeWorker(t *testing.T) {
	t.Setenv("ANVILKIT_ENVIRONMENT", "production")
	t.Setenv("ANVILKIT_WORKER_IMPLEMENTATION", "fake-worker")
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "fake and mock workers") {
		t.Fatalf("fake worker accepted: %v", err)
	}
}

func TestProductionEndpointCannotResolveToAStandIn(t *testing.T) {
	for name, endpoint := range map[string]Endpoint{
		"mock host":        {URL: "https://pagix-mock.example.test"},
		"fake path":        {URL: "https://pagix.example.test/fake"},
		"localhost":        {URL: "http://localhost:8080"},
		"loopback":         {URL: "http://127.0.0.1:8080"},
		"local domain":     {URL: "https://pagix.local"},
		"stand-in trust":   {URL: "https://pagix.example.test", TrustRef: "spiffe://local-dev/pagix"},
		"mock trust":       {URL: "https://pagix.example.test", TrustRef: "kms://mock-key"},
		"unspecified host": {URL: "http://[::]:8080"},
	} {
		t.Run(name, func(t *testing.T) {
			if !productionStandIn(endpoint) {
				t.Fatalf("production stand-in accepted: %#v", endpoint)
			}
		})
	}
	if productionStandIn(Endpoint{URL: "https://pagix.prod.example.com", TrustRef: "spiffe://anvilkit/pagix"}) {
		t.Fatal("production endpoint was classified as a stand-in")
	}
}

func TestFeatureGatesDefaultSafe(t *testing.T) {
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.FeatureGates["real-provider"] {
		t.Fatal("unconfigured gate must be false")
	}
}

func TestFeatureGateSyntaxFailsClosed(t *testing.T) {
	t.Setenv("ANVILKIT_FEATURE_GATES", "real-provider")
	if _, err := Load(); err == nil {
		t.Fatal("invalid feature gate was ignored")
	}
}

func TestCandidateMutationGateRequiresCompleteNonProductionAuthority(t *testing.T) {
	t.Setenv("ANVILKIT_FEATURE_GATES", "candidate-mutations=true")
	_, err := Load()
	var details problem.Details
	if !errors.As(err, &details) || len(details.Fields) != 1 {
		t.Fatalf("incomplete candidate mutation gate was accepted: %v", err)
	}
}

func TestCandidateMutationGateRequiresControlDatabase(t *testing.T) {
	t.Setenv("ANVILKIT_FEATURE_GATES", "candidate-mutations=true")
	t.Setenv("ANVILKIT_AUTH_TRUST_SNAPSHOT", "trust.json")
	t.Setenv("ANVILKIT_AUTH_ISSUERS", "https://issuer.example.com")
	t.Setenv("ANVILKIT_EVENTS_DATABASE_URL", "postgres://events@db.example.com/anvilkit")
	t.Setenv("ANVILKIT_RUN_AUTHORITY_FILE", "authority.json")
	_, err := Load()
	var details problem.Details
	if !errors.As(err, &details) || details.Fields["ANVILKIT_CONTROL_DATABASE_URL"] == "" {
		t.Fatalf("candidate mutations accepted without control authority database: %v", err)
	}
}

// The approved Agent definition catalog must be authenticated against an
// operator-distributed trust root in production. The repository ships no
// signing key, so a production deployment that supplies none is rejected
// rather than trusting its own copy of the catalog.
func TestProductionRequiresAnOperatorDistributedDefinitionTrustRoot(t *testing.T) {
	required := requiredProductionSettings()
	for _, missing := range []string{"ANVILKIT_DEFINITION_TRUST_ROOT", "ANVILKIT_DEFINITION_ATTESTATION"} {
		t.Run(missing, func(t *testing.T) {
			for name, value := range required {
				if name != missing {
					t.Setenv(name, value)
				}
			}
			_, err := Load()
			var details problem.Details
			if !errors.As(err, &details) || details.Fields[missing] == "" {
				t.Fatalf("production configuration without %s was accepted: %v", missing, err)
			}
		})
	}
	// With both present, the definition trust material is no longer what
	// blocks the configuration.
	for name, value := range required {
		t.Setenv(name, value)
	}
	_, err := Load()
	var details problem.Details
	if errors.As(err, &details) {
		for _, name := range []string{"ANVILKIT_DEFINITION_TRUST_ROOT", "ANVILKIT_DEFINITION_ATTESTATION"} {
			if details.Fields[name] != "" {
				t.Fatalf("a supplied %s was still reported missing: %v", name, details.Fields)
			}
		}
	}
}

// requiredProductionSettings is the environment a production configuration
// needs before the definition trust material is the only thing left to check.
func requiredProductionSettings() map[string]string {
	return map[string]string{
		"ANVILKIT_ENVIRONMENT":             "production",
		"ANVILKIT_AUTH_TRUST_SNAPSHOT":     "/etc/anvilkit/trust.json",
		"ANVILKIT_AUTH_ISSUERS":            "urn:anvilkit:issuer:platform",
		"ANVILKIT_MIGRATION_DATABASE_URL":  "postgres://owner@db.internal:5432/anvilkit",
		"ANVILKIT_CONTROL_DATABASE_URL":    "postgres://owner@db.internal:5432/anvilkit",
		"ANVILKIT_WORKFLOW_DATABASE_URL":   "postgres://owner@db.internal:5432/anvilkit",
		"ANVILKIT_EVENTS_DATABASE_URL":     "postgres://owner@db.internal:5432/anvilkit",
		"ANVILKIT_ARTIFACTS_DATABASE_URL":  "postgres://owner@db.internal:5432/anvilkit",
		"ANVILKIT_EVALUATION_DATABASE_URL": "postgres://owner@db.internal:5432/anvilkit",
		"ANVILKIT_RECEIPT_JOURNAL_URL":     "https://journal.internal",
		"ANVILKIT_RECOVERY_REGISTER_URL":   "https://register.internal",
		"ANVILKIT_AUTHORITATIVE_TIME_URL":  "https://time.internal",
		"ANVILKIT_PROTECTED_AUDIT_URL":     "https://audit.internal",
		"ANVILKIT_POLICY_SNAPSHOT":         "/etc/anvilkit/policy.json",
		"ANVILKIT_CAPABILITY_SNAPSHOT":     "/etc/anvilkit/capability.json",
		"ANVILKIT_DEFINITION_TRUST_ROOT":   "/etc/anvilkit/definition-trust-root.json",
		"ANVILKIT_DEFINITION_ATTESTATION":  "/etc/anvilkit/definition-catalog.dsse.json",
	}
}
