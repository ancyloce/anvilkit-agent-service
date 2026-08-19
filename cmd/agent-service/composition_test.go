package main

import (
	"strings"
	"testing"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/config"
	"github.com/ancyloce/anvilkit-agent-service/internal/execution"
	"github.com/ancyloce/anvilkit-agent-service/internal/runapp"
)

// The production composition must never construct the agent pipeline over a
// controlled fake, and no implementation is ever selected implicitly.

func TestSelectImplementationsFailClosedWithoutExplicitSelection(t *testing.T) {
	cfg := config.Config{}
	if _, err := selectModelImplementation(cfg, runapp.SystemClock{}); err == nil {
		t.Fatal("unset model implementation must fail closed")
	}
	if _, _, err := selectToolImplementation(cfg); err == nil {
		t.Fatal("unset tool implementation must fail closed")
	}
	if _, _, err := selectDomainImplementation(cfg); err == nil {
		t.Fatal("unset domain implementation must fail closed")
	}
	cfg.ModelImplementation = "provider-x"
	if _, err := selectModelImplementation(cfg, runapp.SystemClock{}); err == nil {
		t.Fatal("unknown model implementation must fail closed")
	}
}

func TestControlledImplementationsAreExplicitlySelectable(t *testing.T) {
	cfg := config.Config{ModelImplementation: execution.ControlledImplementation, ToolImplementation: execution.ControlledImplementation, DomainImplementation: execution.ControlledImplementation}
	if _, err := selectModelImplementation(cfg, runapp.SystemClock{}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := selectToolImplementation(cfg); err != nil {
		t.Fatal(err)
	}
	if _, _, err := selectDomainImplementation(cfg); err != nil {
		t.Fatal(err)
	}
}

func TestProductionConfigurationRejectsControlledImplementations(t *testing.T) {
	base := config.Config{
		ServiceName:        "agent-service",
		Environment:        config.EnvironmentProduction,
		HTTPAddress:        ":8080",
		MigrationMode:      "validate",
		Limits:             config.Limits{Tools: 5},
		ControlPoolSize:    1,
		WorkflowPoolSize:   1,
		EventsPoolSize:     1,
		ArtifactsPoolSize:  1,
		EvaluationPoolSize: 1,
	}
	base.ModelImplementation = execution.ControlledImplementation
	err := base.Validate()
	if err == nil || !strings.Contains(err.Error(), "forbidden in production") {
		t.Fatalf("production must reject controlled model implementation, got %v", err)
	}
	base.ModelImplementation = ""
	base.ToolImplementation = "fake-tools"
	if err := base.Validate(); err == nil || !strings.Contains(err.Error(), "forbidden in production") {
		t.Fatalf("production must reject fake tool implementation, got %v", err)
	}
	base.ToolImplementation = ""
	base.DomainImplementation = "mock-domain"
	if err := base.Validate(); err == nil || !strings.Contains(err.Error(), "forbidden in production") {
		t.Fatalf("production must reject mock domain implementation, got %v", err)
	}
}

func TestInterruptDeadlinesMustBePositive(t *testing.T) {
	cfg := config.Config{
		ServiceName:   "agent-service",
		Environment:   config.EnvironmentDevelopment,
		HTTPAddress:   ":8080",
		MigrationMode: "validate",
		Limits:        config.Limits{Tools: 5},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("zero interrupt deadlines must be rejected")
	}
	cfg.ControlPoolSize = 1
	cfg.WorkflowPoolSize = 1
	cfg.EventsPoolSize = 1
	cfg.ArtifactsPoolSize = 1
	cfg.EvaluationPoolSize = 1
	cfg.InputRequestTTL = time.Minute
	cfg.ApprovalRequestTTL = time.Minute
	cfg.RunTimeout = time.Minute
	cfg.DwellDeadline = time.Minute
	cfg.AuthRevalidation = time.Second
	cfg.BudgetUnits = 1
	cfg.BudgetHeadroomMicros = 1
	cfg.BudgetReviewBasisPoints = 1
	cfg.TurnLimit = 1
	cfg.CircuitFailures = 1
	if err := cfg.Validate(); err != nil {
		t.Fatalf("bounded development configuration must validate: %v", err)
	}
}
