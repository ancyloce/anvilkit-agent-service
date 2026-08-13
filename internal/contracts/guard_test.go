package contracts

import (
	"context"
	"testing"
)

func TestTrustBoundaryCoverageFailsWhenAnyBoundaryIsUnvalidated(t *testing.T) {
	guard, err := NewGuard("../..")
	if err != nil {
		t.Fatal(err)
	}
	if err := guard.AssertCoverage(); err == nil {
		t.Fatal("empty coverage accepted")
	}
	for _, boundary := range RequiredBoundaries() {
		_ = guard.Validate(context.Background(), boundary, "missing-schema", []byte(`{}`))
	}
	if err := guard.AssertCoverage(); err != nil {
		t.Fatal(err)
	}
}

func TestUnknownTrustBoundaryFailsClosed(t *testing.T) {
	guard, err := NewGuard("../..")
	if err != nil {
		t.Fatal(err)
	}
	findings := guard.Validate(context.Background(), Boundary("invented"), "missing", []byte(`{}`))
	if len(findings) != 1 || findings[0].Code != "VALIDATION_BOUNDARY_UNKNOWN" {
		t.Fatalf("unexpected findings %#v", findings)
	}
}
