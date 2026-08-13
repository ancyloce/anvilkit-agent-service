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
