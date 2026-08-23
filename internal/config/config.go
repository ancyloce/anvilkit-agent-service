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
	"github.com/ancyloce/anvilkit-agent-service/internal/workflow"
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
	ServiceName                   string
	ServiceVersion                string
	Environment                   Environment
	HTTPAddress                   string
	MigrationMode                 string
	MigrationDatabase             string
	ContractRoot                  string
	DefinitionTrustRoot           string
	DefinitionAttestation         string
	AuthTrustSnapshot             string
	AuthIssuers                   []string
	AuthAudience                  string
	AuthRevalidation              time.Duration
	RunAuthorityFile              string
	ControlDatabase               string
	ControlPoolSize               int
	WorkflowDatabase              string
	WorkflowPoolSize              int
	EventsDatabase                string
	EventsPoolSize                int
	ArtifactsDatabase             string
	ArtifactsPoolSize             int
	EvaluationDatabase            string
	EvaluationPoolSize            int
	ExecutorID                    string
	Pagix                         Endpoint
	ContractRuntime               Endpoint
	ObjectStore                   Endpoint
	QueueName                     string
	DLQName                       string
	WorkerImplementation          string
	ModelImplementation           string
	ToolImplementation            string
	DomainImplementation          string
	ContractRuntimeImplementation string
	ContractRuntimeAttempts       int
	ContractRuntimeBackoff        time.Duration
	ControlledModelScript         []string
	InputRequestTTL               time.Duration
	ApprovalRequestTTL            time.Duration
	ApplyAuthorizationTTL         time.Duration
	ArtifactPendingTTL            time.Duration
	ArtifactGrantTTL              time.Duration
	EventRetention                time.Duration
	SSEWriteTimeout               time.Duration
	// StreamCursorSpool is the instance's durable directory for stream
	// disconnect records the authoritative cursor store refused. It must be a
	// volume that survives a restart: a record held there is the only account
	// of what a disconnected client received until the reconciler places it.
	StreamCursorSpool       string
	ProviderEnabled         bool
	ProviderPriority        []string
	PolicySnapshot          string
	CapabilitySnapshot      string
	ArtifactPolicy          string
	BudgetUnits             int64 // per-child reservation upper bound in currency micros
	BudgetHeadroomMicros    int64
	BudgetReviewBasisPoints int
	// BudgetMaxReservedMicros bounds the total unreleased reservation
	// exposure the Platform budget controller may hold per root run scope.
	BudgetMaxReservedMicros int64
	// DomainReconcileLimit bounds how many durable uncertain reconciliations
	// one submitted governed effect may accumulate before it escalates to
	// operator resolution; the retry base and cap shape the bounded backoff
	// between reconciliations. It is validated against
	// workflow.MaximumDomainReconciliations, so a configured window can never
	// outrun the commit loop that has to reach it: a run is released at the
	// submit boundary only after a durable escalation, and configuration
	// cannot put that escalation beyond the loop's reach.
	DomainReconcileLimit int
	DomainRetryBase      time.Duration
	DomainRetryCap       time.Duration
	RunTimeout           time.Duration
	TurnLimit            int
	DwellDeadline        time.Duration
	CircuitFailures      int
	EgressAllowlist      []string
	// EgressMaximumBytes and EgressTimeout bound one outbound exchange, and
	// MemoryAdmissionBytes bounds the untrusted content one tool may place in
	// a run's carried memory.
	EgressMaximumBytes   int64
	EgressTimeout        time.Duration
	MemoryAdmissionBytes int
	SigningKey           SecretRef
	EncryptionKey        SecretRef
	RecoveryRegister     Endpoint
	ReceiptJournal       Endpoint
	AuthoritativeTime    Endpoint
	MaximumClockSkew     time.Duration
	// AuthoritativeTimeTrustRoot is the operator-distributed trust root the
	// time authority's signed statements are authenticated against. It is
	// separate from the endpoint on purpose: material that authenticates a
	// source must not be fetched from that source.
	AuthoritativeTimeTrustRoot string
	// ProtectedAudit is the endpoint the service appends its security
	// decisions to. It is the only protected-audit credential the running
	// process is given, and it connects as a login that holds append and read
	// and nothing else.
	//
	// The credential that establishes the chain, its barriers, and that grant
	// is deliberately absent from this surface. It belongs to the one-shot
	// provisioner in cmd/protected-audit-provisioner, which exits: a
	// long-running process configured with an administrative credential owns
	// the account of its own security decisions for as long as it runs,
	// whether it ever uses the credential or not.
	ProtectedAudit  Endpoint
	OTelEndpoint    string
	OTelSampleRatio float64
	FeatureGates    map[string]bool
	Limits          Limits
}

// ProtectedAuditProvisioning is the whole configuration of the one-shot
// protected-audit provisioner, and it is a separate surface from the service's
// own on purpose: the two are meant to be delivered to different workloads,
// and a shared configuration type is a shared configuration in practice.
//
// It names the runtime login as a role rather than as a connection string, so
// the provisioner holds no credential the service connects with, exactly as
// the service holds none the provisioner administers with.
type ProtectedAuditProvisioning struct {
	Environment  Environment
	AdminURL     string
	RuntimeLogin string
}

// LoadProtectedAuditProvisioning reads the provisioner's configuration.
func LoadProtectedAuditProvisioning() (ProtectedAuditProvisioning, error) {
	value := ProtectedAuditProvisioning{
		Environment:  Environment(env("ANVILKIT_ENVIRONMENT", "development")),
		AdminURL:     os.Getenv("ANVILKIT_PROTECTED_AUDIT_ADMIN_URL"),
		RuntimeLogin: os.Getenv("ANVILKIT_PROTECTED_AUDIT_RUNTIME_LOGIN"),
	}
	switch value.Environment {
	case EnvironmentDevelopment, EnvironmentTest, EnvironmentStaging, EnvironmentProduction:
	default:
		return ProtectedAuditProvisioning{}, problem.InvalidConfiguration("ANVILKIT_ENVIRONMENT", "must be development, test, staging, or production")
	}
	if value.AdminURL == "" || !validURL(value.AdminURL) {
		return ProtectedAuditProvisioning{}, problem.InvalidConfiguration("ANVILKIT_PROTECTED_AUDIT_ADMIN_URL", "must be the absolute URL of the administratively credentialed audit endpoint")
	}
	if value.RuntimeLogin == "" || len(value.RuntimeLogin) > 63 {
		return ProtectedAuditProvisioning{}, problem.InvalidConfiguration("ANVILKIT_PROTECTED_AUDIT_RUNTIME_LOGIN", "must name the login role the service connects as")
	}
	return value, nil
}

// RequiresSeparateLogins reports whether the provisioner must prove the
// administering login is neither a superuser nor an owner of what it
// established, beyond the two identities being different at all.
//
// That the identities differ is not a question this answers: EnsureSchema
// refuses to grant the runtime role to the login administering the audit in
// every environment, so there is no configuration in which the service runs
// as the credential that owns its own audit. What is asked here is the
// stronger standing proof, and it is asked of every deployed environment
// rather than of production alone — a staging deployment whose runtime login
// is a superuser is confined by no grant either.
func (p ProtectedAuditProvisioning) RequiresSeparateLogins() bool {
	switch p.Environment {
	case EnvironmentDevelopment, EnvironmentTest:
		return false
	default:
		return true
	}
}

// Load reads the complete typed configuration surface. No other package may
// read process environment directly; cmd/boundarycheck enforces that rule.
func Load() (Config, error) {
	cfg := Config{
		ServiceName:                   env("ANVILKIT_SERVICE_NAME", "agent-service"),
		ServiceVersion:                env("ANVILKIT_SERVICE_VERSION", "dev"),
		Environment:                   Environment(env("ANVILKIT_ENVIRONMENT", "development")),
		HTTPAddress:                   env("ANVILKIT_HTTP_ADDRESS", ":8080"),
		MigrationMode:                 env("ANVILKIT_MIGRATION_MODE", "validate"),
		MigrationDatabase:             os.Getenv("ANVILKIT_MIGRATION_DATABASE_URL"),
		ContractRoot:                  env("ANVILKIT_CONTRACT_ROOT", "."),
		DefinitionTrustRoot:           env("ANVILKIT_DEFINITION_TRUST_ROOT", ""),
		DefinitionAttestation:         env("ANVILKIT_DEFINITION_ATTESTATION", ""),
		AuthTrustSnapshot:             os.Getenv("ANVILKIT_AUTH_TRUST_SNAPSHOT"),
		StreamCursorSpool:             os.Getenv("ANVILKIT_STREAM_CURSOR_SPOOL"),
		AuthIssuers:                   csv(os.Getenv("ANVILKIT_AUTH_ISSUERS")),
		AuthAudience:                  env("ANVILKIT_AUTH_AUDIENCE", "urn:anvilkit:audience:agent-service"),
		RunAuthorityFile:              os.Getenv("ANVILKIT_RUN_AUTHORITY_FILE"),
		ControlDatabase:               os.Getenv("ANVILKIT_CONTROL_DATABASE_URL"),
		WorkflowDatabase:              os.Getenv("ANVILKIT_WORKFLOW_DATABASE_URL"),
		EventsDatabase:                os.Getenv("ANVILKIT_EVENTS_DATABASE_URL"),
		ArtifactsDatabase:             os.Getenv("ANVILKIT_ARTIFACTS_DATABASE_URL"),
		EvaluationDatabase:            os.Getenv("ANVILKIT_EVALUATION_DATABASE_URL"),
		ExecutorID:                    env("ANVILKIT_EXECUTOR_ID", "local-1"),
		Pagix:                         endpoint("ANVILKIT_PAGIX"),
		ContractRuntime:               endpoint("ANVILKIT_CONTRACT_RUNTIME"),
		ObjectStore:                   endpoint("ANVILKIT_OBJECT_STORE"),
		QueueName:                     env("ANVILKIT_QUEUE_NAME", "agent-tasks"),
		DLQName:                       env("ANVILKIT_DLQ_NAME", "agent-tasks-dlq"),
		WorkerImplementation:          os.Getenv("ANVILKIT_WORKER_IMPLEMENTATION"),
		ModelImplementation:           os.Getenv("ANVILKIT_MODEL_IMPLEMENTATION"),
		ToolImplementation:            os.Getenv("ANVILKIT_TOOL_IMPLEMENTATION"),
		DomainImplementation:          os.Getenv("ANVILKIT_DOMAIN_IMPLEMENTATION"),
		ContractRuntimeImplementation: os.Getenv("ANVILKIT_CONTRACT_RUNTIME_IMPLEMENTATION"),
		ControlledModelScript:         csv(env("ANVILKIT_CONTROLLED_MODEL_SCRIPT", "final")),
		ProviderPriority:              csv(os.Getenv("ANVILKIT_PROVIDER_PRIORITY")),
		PolicySnapshot:                os.Getenv("ANVILKIT_POLICY_SNAPSHOT"),
		CapabilitySnapshot:            os.Getenv("ANVILKIT_CAPABILITY_SNAPSHOT"),
		ArtifactPolicy:                env("ANVILKIT_ARTIFACT_POLICY", "baseline"),
		EgressAllowlist:               csv(os.Getenv("ANVILKIT_EGRESS_ALLOWLIST")),
		SigningKey:                    secret("ANVILKIT_SIGNING_KEY_REF", "ANVILKIT_SIGNING_KEY"),
		EncryptionKey:                 secret("ANVILKIT_ENCRYPTION_KEY_REF", "ANVILKIT_ENCRYPTION_KEY"),
		RecoveryRegister:              endpoint("ANVILKIT_RECOVERY_REGISTER"),
		ReceiptJournal:                endpoint("ANVILKIT_RECEIPT_JOURNAL"),
		AuthoritativeTime:             endpoint("ANVILKIT_AUTHORITATIVE_TIME"),
		AuthoritativeTimeTrustRoot:    env("ANVILKIT_AUTHORITATIVE_TIME_TRUST_ROOT", ""),
		ProtectedAudit:                endpoint("ANVILKIT_PROTECTED_AUDIT"),
		OTelEndpoint:                  os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"),
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
	if cfg.BudgetMaxReservedMicros, err = integer64("ANVILKIT_BUDGET_MAX_RESERVED_MICROS", 10_000_000_000); err != nil {
		return Config{}, err
	}
	if cfg.DomainReconcileLimit, err = integer("ANVILKIT_DOMAIN_RECONCILE_LIMIT", 8); err != nil {
		return Config{}, err
	}
	if cfg.DomainRetryBase, err = duration("ANVILKIT_DOMAIN_RETRY_BASE", 10*time.Second); err != nil {
		return Config{}, err
	}
	if cfg.DomainRetryCap, err = duration("ANVILKIT_DOMAIN_RETRY_CAP", 5*time.Minute); err != nil {
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
	if cfg.ApplyAuthorizationTTL, err = duration("ANVILKIT_APPLY_AUTHORIZATION_TTL", 2*time.Minute); err != nil {
		return Config{}, err
	}
	if cfg.EgressTimeout, err = duration("ANVILKIT_EGRESS_TIMEOUT", 5*time.Second); err != nil {
		return Config{}, err
	}
	if cfg.EgressMaximumBytes, err = integer64("ANVILKIT_EGRESS_MAXIMUM_BYTES", 1<<20); err != nil {
		return Config{}, err
	}
	if cfg.MemoryAdmissionBytes, err = integer("ANVILKIT_MEMORY_ADMISSION_BYTES", 64*1024); err != nil {
		return Config{}, err
	}
	if cfg.ArtifactPendingTTL, err = duration("ANVILKIT_ARTIFACT_PENDING_TTL", time.Hour); err != nil {
		return Config{}, err
	}
	if cfg.ArtifactGrantTTL, err = duration("ANVILKIT_ARTIFACT_GRANT_TTL", 5*time.Minute); err != nil {
		return Config{}, err
	}
	if cfg.EventRetention, err = duration("ANVILKIT_EVENT_RETENTION", 720*time.Hour); err != nil {
		return Config{}, err
	}
	if cfg.SSEWriteTimeout, err = duration("ANVILKIT_SSE_WRITE_TIMEOUT", 10*time.Second); err != nil {
		return Config{}, err
	}
	if cfg.ContractRuntimeAttempts, err = integer("ANVILKIT_CONTRACT_RUNTIME_ATTEMPTS", 3); err != nil {
		return Config{}, err
	}
	if cfg.ContractRuntimeBackoff, err = duration("ANVILKIT_CONTRACT_RUNTIME_BACKOFF", time.Second); err != nil {
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
	if err := refuseAdministrativeAuditCredential(); err != nil {
		return Config{}, err
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// refuseAdministrativeAuditCredential stops the service from starting in a
// workload that was handed the credential which owns the protected audit.
//
// The service is meant to hold one audit credential and it is the narrow one.
// Holding the administrative credential is not a thing that has to be used to
// matter: a long-running process configured with a login that owns the audit
// table can drop its barriers and rewrite its own record of every security
// decision for as long as it runs, so the separation is only real if the
// credential is absent from this workload rather than merely unused by it.
//
// It is checked here because this package is the only one permitted to read
// process environment, and refusing at load is what makes the misconfiguration
// a startup failure rather than a property nobody can observe.
func refuseAdministrativeAuditCredential() error {
	for _, name := range []string{"ANVILKIT_PROTECTED_AUDIT_ADMIN_URL", "ANVILKIT_PROTECTED_AUDIT_RUNTIME_LOGIN"} {
		if _, present := os.LookupEnv(name); present {
			return problem.InvalidConfiguration(name, "belongs to the one-shot protected-audit provisioner and must not be delivered to the Agent Service workload")
		}
	}
	return nil
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
	// The governed AgentRun mutation surface is part of the production API and
	// carries no feature gate: authentication, authorization, concurrency,
	// idempotency, and canonical schema validation each fail closed on their
	// own, and composition refuses to serve the API at all without its
	// authentication trust material and durable stores.
	if c.Environment == EnvironmentProduction {
		if strings.Contains(strings.ToLower(c.WorkerImplementation), "fake") || strings.Contains(strings.ToLower(c.WorkerImplementation), "mock") {
			return problem.InvalidConfiguration("ANVILKIT_WORKER_IMPLEMENTATION", "fake and mock workers are forbidden in production")
		}
		for name, value := range map[string]string{"ANVILKIT_MODEL_IMPLEMENTATION": c.ModelImplementation, "ANVILKIT_TOOL_IMPLEMENTATION": c.ToolImplementation, "ANVILKIT_DOMAIN_IMPLEMENTATION": c.DomainImplementation, "ANVILKIT_CONTRACT_RUNTIME_IMPLEMENTATION": c.ContractRuntimeImplementation} {
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
		for name, target := range map[string]string{"ANVILKIT_AUTH_TRUST_SNAPSHOT": c.AuthTrustSnapshot, "ANVILKIT_AUTH_ISSUERS": strings.Join(c.AuthIssuers, ","), "ANVILKIT_MIGRATION_DATABASE_URL": c.MigrationDatabase, "ANVILKIT_CONTROL_DATABASE_URL": c.ControlDatabase, "ANVILKIT_WORKFLOW_DATABASE_URL": c.WorkflowDatabase, "ANVILKIT_EVENTS_DATABASE_URL": c.EventsDatabase, "ANVILKIT_ARTIFACTS_DATABASE_URL": c.ArtifactsDatabase, "ANVILKIT_EVALUATION_DATABASE_URL": c.EvaluationDatabase, "ANVILKIT_RECEIPT_JOURNAL_URL": c.ReceiptJournal.URL, "ANVILKIT_RECOVERY_REGISTER_URL": c.RecoveryRegister.URL, "ANVILKIT_AUTHORITATIVE_TIME_URL": c.AuthoritativeTime.URL, "ANVILKIT_AUTHORITATIVE_TIME_TRUST_REF": c.AuthoritativeTime.TrustRef, "ANVILKIT_AUTHORITATIVE_TIME_TRUST_ROOT": c.AuthoritativeTimeTrustRoot, "ANVILKIT_PROTECTED_AUDIT_URL": c.ProtectedAudit.URL, "ANVILKIT_POLICY_SNAPSHOT": c.PolicySnapshot, "ANVILKIT_CAPABILITY_SNAPSHOT": c.CapabilitySnapshot,
			// The approved Agent definition catalog must be authenticated
			// against an operator-distributed trust root in production. The
			// repository ships no signing key, so production cannot fall back
			// to trusting its own copy of the catalog.
			"ANVILKIT_DEFINITION_TRUST_ROOT": c.DefinitionTrustRoot, "ANVILKIT_DEFINITION_ATTESTATION": c.DefinitionAttestation} {
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
	// A deployment that serves agent runs runs tools, and a tool that reaches
	// outside does so under this policy. An empty allowlist is a deployment
	// with no destination any tool may reach, which is a valid and closed
	// posture; what is refused is a policy whose bounds make no sense.
	if c.EgressMaximumBytes < 1 || c.EgressMaximumBytes > 1<<30 {
		return problem.InvalidConfiguration("ANVILKIT_EGRESS_MAXIMUM_BYTES", "the bounded egress response size must be between one byte and one gibibyte")
	}
	if c.EgressTimeout <= 0 || c.EgressTimeout > 30*time.Second {
		return problem.InvalidConfiguration("ANVILKIT_EGRESS_TIMEOUT", "the bounded egress exchange must be positive and at most thirty seconds")
	}
	if c.MemoryAdmissionBytes < 1 || c.MemoryAdmissionBytes > 1<<20 {
		return problem.InvalidConfiguration("ANVILKIT_MEMORY_ADMISSION_BYTES", "the untrusted memory admission bound must be between one byte and one mebibyte")
	}
	if c.Limits.Tools < 3 || c.Limits.Tools > 7 {
		return problem.InvalidConfiguration("ANVILKIT_TOOL_LIMIT", "must be between 3 and 7")
	}
	if c.InputRequestTTL <= 0 || c.ApprovalRequestTTL <= 0 {
		return problem.InvalidConfiguration("ANVILKIT_INPUT_REQUEST_TTL", "interrupt deadlines must be positive")
	}
	if c.ApplyAuthorizationTTL <= 0 || c.ApplyAuthorizationTTL > 5*time.Minute {
		return problem.InvalidConfiguration("ANVILKIT_APPLY_AUTHORIZATION_TTL", "apply authorization expiry must be positive and at most five minutes")
	}
	if c.ArtifactPendingTTL <= 0 {
		return problem.InvalidConfiguration("ANVILKIT_ARTIFACT_PENDING_TTL", "artifact pending expiry must be positive")
	}
	if c.ArtifactGrantTTL <= 0 || c.ArtifactGrantTTL > 15*time.Minute {
		return problem.InvalidConfiguration("ANVILKIT_ARTIFACT_GRANT_TTL", "artifact grant expiry must be positive and at most fifteen minutes")
	}
	if c.ContractRuntimeAttempts < 1 || c.ContractRuntimeAttempts > 5 {
		return problem.InvalidConfiguration("ANVILKIT_CONTRACT_RUNTIME_ATTEMPTS", "contract runtime attempts must be between 1 and 5")
	}
	if c.ContractRuntimeBackoff < 0 || c.ContractRuntimeBackoff > 30*time.Second {
		return problem.InvalidConfiguration("ANVILKIT_CONTRACT_RUNTIME_BACKOFF", "contract runtime backoff must be between 0 and 30 seconds")
	}
	if c.EventRetention < time.Hour {
		return problem.InvalidConfiguration("ANVILKIT_EVENT_RETENTION", "the public cursor retention window must be at least one hour")
	}
	if c.SSEWriteTimeout <= 0 || c.SSEWriteTimeout > time.Minute {
		return problem.InvalidConfiguration("ANVILKIT_SSE_WRITE_TIMEOUT", "the event stream write deadline must be positive and at most one minute")
	}
	// The authenticated agent API is what serves event streams, so wherever it
	// is composed the durable holding area for disconnect records must be
	// declared. Every stream records what its client received before the
	// connection ends; a deployment with nowhere durable to put that record
	// when the store refuses it is a deployment that would lose it.
	if c.AuthTrustSnapshot != "" && strings.TrimSpace(c.StreamCursorSpool) == "" {
		return problem.InvalidConfiguration("ANVILKIT_STREAM_CURSOR_SPOOL", "a durable stream-cursor spool directory is required wherever event streams are served")
	}
	if len(c.ControlledModelScript) < 1 || len(c.ControlledModelScript) > 16 {
		return problem.InvalidConfiguration("ANVILKIT_CONTROLLED_MODEL_SCRIPT", "the controlled model script must carry between 1 and 16 steps")
	}
	for _, step := range c.ControlledModelScript {
		if step != "final" && step != "need-input" && step != "tool-echo" {
			return problem.InvalidConfiguration("ANVILKIT_CONTROLLED_MODEL_SCRIPT", "controlled model script steps must be final, need-input, or tool-echo")
		}
	}
	if c.RunTimeout <= 0 || c.DwellDeadline <= 0 || c.MaximumClockSkew < 0 || c.AuthRevalidation <= 0 {
		return problem.InvalidConfiguration("duration", "timeouts must be positive and clock skew must not be negative")
	}
	if c.BudgetMaxReservedMicros < 1 || c.DomainReconcileLimit < 1 || c.DomainRetryBase <= 0 || c.DomainRetryCap < c.DomainRetryBase {
		return fmt.Errorf("budget controller exposure bound and domain reconciliation window must be positive and ordered")
	}
	if c.DomainReconcileLimit > workflow.MaximumDomainReconciliations {
		return problem.InvalidConfiguration("ANVILKIT_DOMAIN_RECONCILE_LIMIT", fmt.Sprintf("the domain reconciliation window must not exceed %d", workflow.MaximumDomainReconciliations))
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
