// Package config is the sole environment-reading boundary for agent-service.
package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
)

type Environment string

const (
	EnvironmentDevelopment Environment = "development"
	EnvironmentTest        Environment = "test"
	EnvironmentStaging     Environment = "staging"
	EnvironmentProduction  Environment = "production"
)

// SecretRef points to secret material managed outside configuration. Value is
// intentionally unexported so callers cannot accidentally serialize it.
type SecretRef struct {
	Name  string
	value string
}

func (s SecretRef) Present() bool { return s.value != "" }

// RedactionValue is the only supported extraction mechanism and exists solely
// for registration with the telemetry redactor during composition.
func (s SecretRef) RedactionValue() string { return s.value }

type Endpoint struct {
	URL      string
	TrustRef string
}

type Limits struct {
	HTTPBodyBytes        int64
	SSEConnections       int
	SSEHeartbeat         time.Duration
	ContextTokens        int
	Tools                int
	RepairAttempts       int
	RetryAttempts        int
	EventBytes           int
	ArtifactBytes        int64
	ConcurrentRuns       int
	WorkspaceConcurrency int
	ChildDepth           int
	ChildFanout          int
}

type Config struct {
	ServiceName             string
	ServiceVersion          string
	Environment             Environment
	HTTPAddress             string
	MigrationMode           string
	MigrationDatabase       string
	ContractRoot            string
	AuthTrustSnapshot       string
	AuthIssuers             []string
	AuthAudience            string
	AuthRevalidation        time.Duration
	RunAuthorityFile        string
	ControlDatabase         string
	ControlPoolSize         int
	WorkflowDatabase        string
	WorkflowPoolSize        int
	EventsDatabase          string
	EventsPoolSize          int
	ArtifactsDatabase       string
	ArtifactsPoolSize       int
	EvaluationDatabase      string
	EvaluationPoolSize      int
	ExecutorID              string
	Pagix                   Endpoint
	ContractRuntime         Endpoint
	ObjectStore             Endpoint
	QueueName               string
	DLQName                 string
	WorkerImplementation    string
	ModelImplementation     string
	ToolImplementation      string
	DomainImplementation    string
	InputRequestTTL         time.Duration
	ApprovalRequestTTL      time.Duration
	ProviderEnabled         bool
	ProviderPriority        []string
	PolicySnapshot          string
	CapabilitySnapshot      string
	ArtifactPolicy          string
	BudgetUnits             int64 // per-child reservation upper bound in currency micros
	BudgetHeadroomMicros    int64
	BudgetReviewBasisPoints int
	RunTimeout              time.Duration
	TurnLimit               int
	DwellDeadline           time.Duration
	CircuitFailures         int
	EgressAllowlist         []string
	SigningKey              SecretRef
	EncryptionKey           SecretRef
	RecoveryRegister        Endpoint
	ReceiptJournal          Endpoint
	AuthoritativeTime       Endpoint
	MaximumClockSkew        time.Duration
	ProtectedAudit          Endpoint
	OTelEndpoint            string
	OTelSampleRatio         float64
	FeatureGates            map[string]bool
	Limits                  Limits
}

// Load reads the complete typed configuration surface. No other package may
// read process environment directly; cmd/boundarycheck enforces that rule.
func Load() (Config, error) {
	cfg := Config{
		ServiceName:          env("ANVILKIT_SERVICE_NAME", "agent-service"),
		ServiceVersion:       env("ANVILKIT_SERVICE_VERSION", "dev"),
		Environment:          Environment(env("ANVILKIT_ENVIRONMENT", "development")),
		HTTPAddress:          env("ANVILKIT_HTTP_ADDRESS", ":8080"),
		MigrationMode:        env("ANVILKIT_MIGRATION_MODE", "validate"),
		MigrationDatabase:    os.Getenv("ANVILKIT_MIGRATION_DATABASE_URL"),
		ContractRoot:         env("ANVILKIT_CONTRACT_ROOT", "."),
		AuthTrustSnapshot:    os.Getenv("ANVILKIT_AUTH_TRUST_SNAPSHOT"),
		AuthIssuers:          csv(os.Getenv("ANVILKIT_AUTH_ISSUERS")),
		AuthAudience:         env("ANVILKIT_AUTH_AUDIENCE", "urn:anvilkit:audience:agent-service"),
		RunAuthorityFile:     os.Getenv("ANVILKIT_RUN_AUTHORITY_FILE"),
		ControlDatabase:      os.Getenv("ANVILKIT_CONTROL_DATABASE_URL"),
		WorkflowDatabase:     os.Getenv("ANVILKIT_WORKFLOW_DATABASE_URL"),
		EventsDatabase:       os.Getenv("ANVILKIT_EVENTS_DATABASE_URL"),
		ArtifactsDatabase:    os.Getenv("ANVILKIT_ARTIFACTS_DATABASE_URL"),
		EvaluationDatabase:   os.Getenv("ANVILKIT_EVALUATION_DATABASE_URL"),
		ExecutorID:           env("ANVILKIT_EXECUTOR_ID", "local-1"),
		Pagix:                endpoint("ANVILKIT_PAGIX"),
		ContractRuntime:      endpoint("ANVILKIT_CONTRACT_RUNTIME"),
		ObjectStore:          endpoint("ANVILKIT_OBJECT_STORE"),
		QueueName:            env("ANVILKIT_QUEUE_NAME", "agent-tasks"),
		DLQName:              env("ANVILKIT_DLQ_NAME", "agent-tasks-dlq"),
		WorkerImplementation: env("ANVILKIT_WORKER_IMPLEMENTATION", "external"),
		ModelImplementation:  os.Getenv("ANVILKIT_MODEL_IMPLEMENTATION"),
		ToolImplementation:   os.Getenv("ANVILKIT_TOOL_IMPLEMENTATION"),
		DomainImplementation: os.Getenv("ANVILKIT_DOMAIN_IMPLEMENTATION"),
		ProviderPriority:     csv(os.Getenv("ANVILKIT_PROVIDER_PRIORITY")),
		PolicySnapshot:       os.Getenv("ANVILKIT_POLICY_SNAPSHOT"),
		CapabilitySnapshot:   os.Getenv("ANVILKIT_CAPABILITY_SNAPSHOT"),
		ArtifactPolicy:       env("ANVILKIT_ARTIFACT_POLICY", "baseline"),
		EgressAllowlist:      csv(os.Getenv("ANVILKIT_EGRESS_ALLOWLIST")),
		SigningKey:           secret("ANVILKIT_SIGNING_KEY_REF", "ANVILKIT_SIGNING_KEY"),
		EncryptionKey:        secret("ANVILKIT_ENCRYPTION_KEY_REF", "ANVILKIT_ENCRYPTION_KEY"),
		RecoveryRegister:     endpoint("ANVILKIT_RECOVERY_REGISTER"),
		ReceiptJournal:       endpoint("ANVILKIT_RECEIPT_JOURNAL"),
		AuthoritativeTime:    endpoint("ANVILKIT_AUTHORITATIVE_TIME"),
		ProtectedAudit:       endpoint("ANVILKIT_PROTECTED_AUDIT"),
		OTelEndpoint:         os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"),
	}

	var err error
	if cfg.ProviderEnabled, err = boolean("ANVILKIT_PROVIDER_ENABLED", false); err != nil {
		return Config{}, err
	}
	if cfg.WorkflowPoolSize, err = integer("ANVILKIT_WORKFLOW_POOL_SIZE", 16); err != nil {
		return Config{}, err
	}
	if cfg.ControlPoolSize, err = integer("ANVILKIT_CONTROL_POOL_SIZE", 16); err != nil {
		return Config{}, err
	}
	if cfg.EventsPoolSize, err = integer("ANVILKIT_EVENTS_POOL_SIZE", 8); err != nil {
		return Config{}, err
	}
	if cfg.ArtifactsPoolSize, err = integer("ANVILKIT_ARTIFACTS_POOL_SIZE", 4); err != nil {
		return Config{}, err
	}
	if cfg.EvaluationPoolSize, err = integer("ANVILKIT_EVALUATION_POOL_SIZE", 4); err != nil {
		return Config{}, err
	}
	if cfg.BudgetUnits, err = integer64("ANVILKIT_BUDGET_UNITS", 1000); err != nil {
		return Config{}, err
	}
	if cfg.BudgetHeadroomMicros, err = integer64("ANVILKIT_BUDGET_HEADROOM_MICROS", 1_000_000); err != nil {
		return Config{}, err
	}
	if cfg.BudgetReviewBasisPoints, err = integer("ANVILKIT_BUDGET_REVIEW_BASIS_POINTS", 8000); err != nil {
		return Config{}, err
	}
	if cfg.TurnLimit, err = integer("ANVILKIT_TURN_LIMIT", 20); err != nil {
		return Config{}, err
	}
	if cfg.CircuitFailures, err = integer("ANVILKIT_CIRCUIT_FAILURES", 5); err != nil {
		return Config{}, err
	}
	if cfg.OTelSampleRatio, err = decimal("ANVILKIT_OTEL_SAMPLE_RATIO", 0.1); err != nil {
		return Config{}, err
	}
	if cfg.RunTimeout, err = duration("ANVILKIT_RUN_TIMEOUT", 30*time.Minute); err != nil {
		return Config{}, err
	}
	if cfg.DwellDeadline, err = duration("ANVILKIT_DWELL_DEADLINE", 15*time.Minute); err != nil {
		return Config{}, err
	}
	if cfg.InputRequestTTL, err = duration("ANVILKIT_INPUT_REQUEST_TTL", 15*time.Minute); err != nil {
		return Config{}, err
	}
	if cfg.ApprovalRequestTTL, err = duration("ANVILKIT_APPROVAL_REQUEST_TTL", 15*time.Minute); err != nil {
		return Config{}, err
	}
	if cfg.MaximumClockSkew, err = duration("ANVILKIT_MAXIMUM_CLOCK_SKEW", 5*time.Second); err != nil {
		return Config{}, err
	}
	if cfg.AuthRevalidation, err = duration("ANVILKIT_AUTH_REVALIDATION", 15*time.Second); err != nil {
		return Config{}, err
	}
	if cfg.FeatureGates, err = parseFeatureGates(os.Getenv("ANVILKIT_FEATURE_GATES")); err != nil {
		return Config{}, err
	}
	if cfg.Limits, err = loadLimits(); err != nil {
		return Config{}, err
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) Validate() error {
	if c.ServiceName != "agent-service" {
		return problem.InvalidConfiguration("ANVILKIT_SERVICE_NAME", "must be agent-service")
	}
	switch c.Environment {
	case EnvironmentDevelopment, EnvironmentTest, EnvironmentStaging, EnvironmentProduction:
	default:
		return problem.InvalidConfiguration("ANVILKIT_ENVIRONMENT", "must be development, test, staging, or production")
	}
	if c.HTTPAddress == "" {
		return problem.InvalidConfiguration("ANVILKIT_HTTP_ADDRESS", "must not be empty")
	}
	if c.MigrationMode != "validate" && c.MigrationMode != "apply" {
		return problem.InvalidConfiguration("ANVILKIT_MIGRATION_MODE", "must be validate or apply")
	}
	for field, size := range map[string]int{"ANVILKIT_CONTROL_POOL_SIZE": c.ControlPoolSize, "ANVILKIT_WORKFLOW_POOL_SIZE": c.WorkflowPoolSize, "ANVILKIT_EVENTS_POOL_SIZE": c.EventsPoolSize, "ANVILKIT_ARTIFACTS_POOL_SIZE": c.ArtifactsPoolSize, "ANVILKIT_EVALUATION_POOL_SIZE": c.EvaluationPoolSize} {
		if size < 1 || size > 256 {
			return problem.InvalidConfiguration(field, "must be between 1 and 256")
		}
	}
	if c.ProviderEnabled && len(c.ProviderPriority) == 0 {
		return problem.InvalidConfiguration("ANVILKIT_PROVIDER_PRIORITY", "must be non-empty when providers are enabled")
	}
	if c.FeatureGates["candidate-mutations"] {
		if c.Environment == EnvironmentProduction {
			return problem.InvalidConfiguration("ANVILKIT_FEATURE_GATES", "candidate mutations are forbidden in production until the interaction contract is finalized")
		}
		for name, value := range map[string]string{"ANVILKIT_AUTH_TRUST_SNAPSHOT": c.AuthTrustSnapshot, "ANVILKIT_AUTH_ISSUERS": strings.Join(c.AuthIssuers, ","), "ANVILKIT_CONTROL_DATABASE_URL": c.ControlDatabase, "ANVILKIT_EVENTS_DATABASE_URL": c.EventsDatabase, "ANVILKIT_RUN_AUTHORITY_FILE": c.RunAuthorityFile} {
			if value == "" {
				return problem.InvalidConfiguration(name, "is required when candidate mutations are enabled")
			}
		}
	}
	if c.Environment == EnvironmentProduction {
		if strings.Contains(strings.ToLower(c.WorkerImplementation), "fake") || strings.Contains(strings.ToLower(c.WorkerImplementation), "mock") {
			return problem.InvalidConfiguration("ANVILKIT_WORKER_IMPLEMENTATION", "fake and mock workers are forbidden in production")
		}
		for name, value := range map[string]string{"ANVILKIT_MODEL_IMPLEMENTATION": c.ModelImplementation, "ANVILKIT_TOOL_IMPLEMENTATION": c.ToolImplementation, "ANVILKIT_DOMAIN_IMPLEMENTATION": c.DomainImplementation} {
			lowered := strings.ToLower(value)
			if strings.Contains(lowered, "fake") || strings.Contains(lowered, "mock") || strings.Contains(lowered, "controlled") {
				return problem.InvalidConfiguration(name, "controlled, fake, and mock implementations are forbidden in production")
			}
		}
		for _, provider := range c.ProviderPriority {
			if strings.Contains(strings.ToLower(provider), "fake") || strings.Contains(strings.ToLower(provider), "mock") {
				return problem.InvalidConfiguration("ANVILKIT_PROVIDER_PRIORITY", "fake and mock providers are forbidden in production")
			}
		}
		for name, target := range map[string]string{"ANVILKIT_AUTH_TRUST_SNAPSHOT": c.AuthTrustSnapshot, "ANVILKIT_AUTH_ISSUERS": strings.Join(c.AuthIssuers, ","), "ANVILKIT_MIGRATION_DATABASE_URL": c.MigrationDatabase, "ANVILKIT_CONTROL_DATABASE_URL": c.ControlDatabase, "ANVILKIT_WORKFLOW_DATABASE_URL": c.WorkflowDatabase, "ANVILKIT_EVENTS_DATABASE_URL": c.EventsDatabase, "ANVILKIT_ARTIFACTS_DATABASE_URL": c.ArtifactsDatabase, "ANVILKIT_EVALUATION_DATABASE_URL": c.EvaluationDatabase, "ANVILKIT_RECEIPT_JOURNAL_URL": c.ReceiptJournal.URL, "ANVILKIT_RECOVERY_REGISTER_URL": c.RecoveryRegister.URL, "ANVILKIT_AUTHORITATIVE_TIME_URL": c.AuthoritativeTime.URL, "ANVILKIT_PROTECTED_AUDIT_URL": c.ProtectedAudit.URL, "ANVILKIT_POLICY_SNAPSHOT": c.PolicySnapshot, "ANVILKIT_CAPABILITY_SNAPSHOT": c.CapabilitySnapshot} {
			if target == "" {
				return problem.InvalidConfiguration(name, "is required in production")
			}
		}
		for name, target := range map[string]Endpoint{
			"ANVILKIT_PAGIX": c.Pagix, "ANVILKIT_CONTRACT_RUNTIME": c.ContractRuntime,
			"ANVILKIT_OBJECT_STORE": c.ObjectStore, "ANVILKIT_RECOVERY_REGISTER": c.RecoveryRegister,
			"ANVILKIT_RECEIPT_JOURNAL": c.ReceiptJournal, "ANVILKIT_AUTHORITATIVE_TIME": c.AuthoritativeTime,
			"ANVILKIT_PROTECTED_AUDIT": c.ProtectedAudit,
		} {
			if productionStandIn(target) {
				return problem.InvalidConfiguration(name, "fake, mock, loopback, and local-development endpoints are forbidden in production")
			}
		}
		if !c.SigningKey.Present() {
			return problem.InvalidConfiguration("ANVILKIT_SIGNING_KEY", "a secret reference is required in production")
		}
	}
	if c.OTelSampleRatio < 0 || c.OTelSampleRatio > 1 {
		return problem.InvalidConfiguration("ANVILKIT_OTEL_SAMPLE_RATIO", "must be between 0 and 1")
	}
	if c.Limits.Tools < 3 || c.Limits.Tools > 7 {
		return problem.InvalidConfiguration("ANVILKIT_TOOL_LIMIT", "must be between 3 and 7")
	}
	if c.InputRequestTTL <= 0 || c.ApprovalRequestTTL <= 0 {
		return problem.InvalidConfiguration("ANVILKIT_INPUT_REQUEST_TTL", "interrupt deadlines must be positive")
	}
	if c.RunTimeout <= 0 || c.DwellDeadline <= 0 || c.MaximumClockSkew < 0 || c.AuthRevalidation <= 0 {
		return problem.InvalidConfiguration("duration", "timeouts must be positive and clock skew must not be negative")
	}
	if c.BudgetUnits < 1 || c.BudgetHeadroomMicros < 1 || c.BudgetReviewBasisPoints < 1 || c.BudgetReviewBasisPoints > 10_000 || c.TurnLimit < 1 || c.CircuitFailures < 1 {
		return problem.InvalidConfiguration("limits", "budget, turn, and circuit-breaker limits must be positive")
	}
	for field, value := range map[string]string{
		"ANVILKIT_PAGIX_URL":              c.Pagix.URL,
		"ANVILKIT_CONTRACT_RUNTIME_URL":   c.ContractRuntime.URL,
		"ANVILKIT_OBJECT_STORE_URL":       c.ObjectStore.URL,
		"ANVILKIT_RECOVERY_REGISTER_URL":  c.RecoveryRegister.URL,
		"ANVILKIT_RECEIPT_JOURNAL_URL":    c.ReceiptJournal.URL,
		"ANVILKIT_AUTHORITATIVE_TIME_URL": c.AuthoritativeTime.URL,
		"ANVILKIT_PROTECTED_AUDIT_URL":    c.ProtectedAudit.URL,
	} {
		if !validURL(value) {
			return problem.InvalidConfiguration(field, "must be an absolute URL")
		}
	}
	return nil
}

func loadLimits() (Limits, error) {
	values := Limits{}
	var err error
	if values.HTTPBodyBytes, err = integer64("ANVILKIT_HTTP_BODY_BYTES", 1<<20); err != nil {
		return Limits{}, err
	}
	if values.SSEConnections, err = integer("ANVILKIT_SSE_CONNECTIONS", 1000); err != nil {
		return Limits{}, err
	}
	if values.SSEHeartbeat, err = duration("ANVILKIT_SSE_HEARTBEAT", 15*time.Second); err != nil {
		return Limits{}, err
	}
	if values.ContextTokens, err = integer("ANVILKIT_CONTEXT_TOKENS", 32000); err != nil {
		return Limits{}, err
	}
	if values.Tools, err = integer("ANVILKIT_TOOL_LIMIT", 5); err != nil {
		return Limits{}, err
	}
	if values.RepairAttempts, err = integer("ANVILKIT_REPAIR_ATTEMPTS", 2); err != nil {
		return Limits{}, err
	}
	if values.RetryAttempts, err = integer("ANVILKIT_RETRY_ATTEMPTS", 3); err != nil {
		return Limits{}, err
	}
	if values.EventBytes, err = integer("ANVILKIT_EVENT_BYTES", 65536); err != nil {
		return Limits{}, err
	}
	if values.ArtifactBytes, err = integer64("ANVILKIT_ARTIFACT_BYTES", 100<<20); err != nil {
		return Limits{}, err
	}
	if values.ConcurrentRuns, err = integer("ANVILKIT_CONCURRENT_RUNS", 500); err != nil {
		return Limits{}, err
	}
	if values.WorkspaceConcurrency, err = integer("ANVILKIT_WORKSPACE_CONCURRENCY", 20); err != nil {
		return Limits{}, err
	}
	if values.ChildDepth, err = integer("ANVILKIT_CHILD_DEPTH", 4); err != nil {
		return Limits{}, err
	}
	if values.ChildFanout, err = integer("ANVILKIT_CHILD_FANOUT", 16); err != nil {
		return Limits{}, err
	}
	return values, nil
}

func endpoint(prefix string) Endpoint {
	return Endpoint{URL: os.Getenv(prefix + "_URL"), TrustRef: os.Getenv(prefix + "_TRUST_REF")}
}
func secret(nameKey, valueKey string) SecretRef {
	return SecretRef{Name: os.Getenv(nameKey), value: os.Getenv(valueKey)}
}
func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
func csv(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	values := strings.Split(value, ",")
	for i := range values {
		values[i] = strings.TrimSpace(values[i])
	}
	return values
}
func boolean(key string, fallback bool) (bool, error) {
	value := os.Getenv(key)
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, problem.InvalidConfiguration(key, "must be a boolean")
	}
	return parsed, nil
}
func integer(key string, fallback int) (int, error) {
	value := os.Getenv(key)
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, problem.InvalidConfiguration(key, "must be an integer")
	}
	return parsed, nil
}
func integer64(key string, fallback int64) (int64, error) {
	value := os.Getenv(key)
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, problem.InvalidConfiguration(key, "must be an integer")
	}
	return parsed, nil
}
func decimal(key string, fallback float64) (float64, error) {
	value := os.Getenv(key)
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return 0, problem.InvalidConfiguration(key, "must be a decimal")
	}
	return parsed, nil
}
func duration(key string, fallback time.Duration) (time.Duration, error) {
	value := os.Getenv(key)
	if value == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0, problem.InvalidConfiguration(key, "must be a duration")
	}
	return parsed, nil
}
func parseFeatureGates(value string) (map[string]bool, error) {
	result := map[string]bool{}
	for _, item := range csv(value) {
		pair := strings.SplitN(item, "=", 2)
		if len(pair) != 2 {
			return nil, problem.InvalidConfiguration("ANVILKIT_FEATURE_GATES", "must use name=true or name=false entries")
		}
		enabled, err := strconv.ParseBool(pair[1])
		if err != nil || pair[0] == "" {
			return nil, problem.InvalidConfiguration("ANVILKIT_FEATURE_GATES", "must use name=true or name=false entries")
		}
		result[pair[0]] = enabled
	}
	return result, nil
}

func (c Config) String() string {
	return fmt.Sprintf("service=%s version=%s environment=%s", c.ServiceName, c.ServiceVersion, c.Environment)
}

func validURL(value string) bool {
	if value == "" {
		return true
	}
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme != ""
}

func productionStandIn(endpoint Endpoint) bool {
	trust := strings.ToLower(endpoint.TrustRef)
	if strings.Contains(trust, "fake") || strings.Contains(trust, "mock") || strings.Contains(trust, "local-dev") {
		return true
	}
	if endpoint.URL == "" {
		return false
	}
	parsed, err := url.Parse(endpoint.URL)
	if err != nil {
		return true
	}
	host := strings.ToLower(parsed.Hostname())
	target := host + strings.ToLower(parsed.EscapedPath())
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") || strings.Contains(target, "fake") || strings.Contains(target, "mock") {
		return true
	}
	address := net.ParseIP(host)
	return address != nil && (address.IsLoopback() || address.IsUnspecified())
}
