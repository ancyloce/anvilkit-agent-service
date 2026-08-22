package events

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/auth"
	"github.com/ancyloce/anvilkit-agent-service/internal/authority"
	"github.com/ancyloce/anvilkit-agent-service/internal/canonical"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"github.com/ancyloce/anvilkit-agent-service/internal/runs"
)

// AgentEvidenceSchemaURI pins the canonical AgentEvidence contract every
// stored internal evidence document is validated against.
const AgentEvidenceSchemaURI = "anvilkit://schema/agent-evidence?digest=sha256:e4251dd073a86fa271d85551c9dfd4f8d046c38704e4f32a70e03f764fd7e378"

// ContractValidator proves one rendered document satisfies its pinned
// canonical contract before the caller performs a durable or outward side
// effect. The repository contract guard satisfies it; the boundary is bound
// by the caller so this package stays free of trust-boundary vocabulary.
type ContractValidator interface {
	Require(ctx context.Context, schemaURI string, raw []byte) error
}

// Evidence is one internal high-fidelity execution fact (ADR-020 §1). It is
// never a public event: it carries its own independent per-run sequence,
// explicit data classification and retention category, and reaches consumers
// only through the access-audited evidence store. Payload facts are bounded
// strings — digests and identifiers, never prompts, responses, tool payloads,
// credentials, or stacks.
type Evidence struct {
	WorkspaceID string
	ProjectID   string
	RunID       string
	// EvidenceID is the producer-derived idempotency identity: replaying the
	// same durable operation appends nothing new.
	EvidenceID     string
	Type           string
	OccurredAt     time.Time
	Producer       EvidenceProducer
	Classification string
	Retention      string
	TurnID         string
	WorkflowID     string
	PublicEventID  string
	Traceparent    string
	Payload        map[string]string
}

type EvidenceProducer struct {
	Component         string
	DefinitionDigest  string
	PolicyDigest      string
	ContractBOMDigest string
}

// RecordedEvidence is one stored evidence row with its allocated sequence,
// its recording time, the derived disclosure deadline, and the integrity
// digest the store verified before disclosing it.
type RecordedEvidence struct {
	Evidence
	Sequence   uint64
	RecordedAt time.Time
	// ExpiresAt is derived from RecordedAt and the retention category, never
	// stored, so it always reflects the governed window in force.
	ExpiresAt time.Time
	Digest    string
	// Identity is the stable digest over the producer-owned fact alone. It is
	// what makes an append idempotent across replays that would otherwise be
	// stored under a different sequence and recording time.
	Identity string
}

// EvidenceRecorder appends one evidence fact, allocating the run's next
// independent evidenceSequence. Appending is idempotent by EvidenceID.
type EvidenceRecorder interface {
	AppendEvidence(context.Context, Evidence) (uint64, error)
}

// MaximumEvidencePage bounds how many records one evidence read discloses.
// Reads are bounded in every store, so a caller can never accidentally pull a
// run's entire internal history in one unbounded query.
const MaximumEvidencePage = 1000

// ValidateEvidenceRun reports whether a run identity is one an evidence read
// may name. Both stores apply it, so neither can be looser than the other.
func ValidateEvidenceRun(runID string) error {
	if !opaqueIdentity(runID) {
		return fmt.Errorf("evidence reads require a bounded run identity")
	}
	return nil
}

// BoundedEvidencePage resolves a requested page size to the bounded one every
// store applies: a non-positive or oversized request becomes the maximum.
func BoundedEvidencePage(limit int) int {
	if limit <= 0 || limit > MaximumEvidencePage {
		return MaximumEvidencePage
	}
	return limit
}

// EvidenceLookup answers what is already recorded under one evidence
// identity. It exists so a producer replaying a durable operation can
// converge on the fact that was recorded instead of stamping a second account
// of it: a fact happened once, so its occurrence time was decided once, and
// the store is where that decision lives.
//
// It is not an evidence read: it discloses no payload to a caller that did
// not produce the fact, only the identity, sequence, and times the producer
// needs to converge.
type EvidenceLookup interface {
	RecordedEvidence(ctx context.Context, scope Scope, evidenceID string) (RecordedEvidence, bool, error)
}

// EvidenceReader reads a run's evidence in sequence order under one proven
// accessor authority. There is no scope parameter by design: the tenant an
// evidence read reaches is the tenant the accessor is authorized for, so a
// cross-tenant read is not a shape this interface can express.
type EvidenceReader interface {
	ReadEvidence(ctx context.Context, authority EvidenceAuthority, runID string, limit int) ([]RecordedEvidence, error)
}

// EvidenceAuthority is the proven authority behind one evidence read: the
// tenant scope the accessor is authorized for, their identity, the purpose
// the read is audited under, and the highest data classification current
// authority clears them for. Every field is unexported and every value comes
// from MintEvidenceAuthority, so a caller cannot manufacture a clearance it
// was never granted and the zero value authorizes nothing.
type EvidenceAuthority struct {
	scope     Scope
	accessor  string
	purpose   string
	clearance string
	// resolve re-reads the same authority from its live sources. A store
	// calls it immediately before disclosing anything, so a subject, scope,
	// role, clearance, or activation that changed after minting is observed
	// on this read rather than the next one.
	resolve func(context.Context) (EvidenceAuthority, error)
}

// Scope, Accessor, Purpose, and Clearance report the minted authority. They
// are read-only projections: nothing outside this package can set them.
func (a EvidenceAuthority) Scope() Scope      { return a.scope }
func (a EvidenceAuthority) Accessor() string  { return a.accessor }
func (a EvidenceAuthority) Purpose() string   { return a.purpose }
func (a EvidenceAuthority) Clearance() string { return a.clearance }

// EvidenceAccessAuthorizer verifies one caller's request authority for the
// evidence-read operation and returns the tenant scope it is bound to. The
// service's auth validator satisfies it; it is an interface here so this
// package depends on the verification rather than on a construction path.
type EvidenceAccessAuthorizer interface {
	Authorize(context.Context, auth.Claims, auth.Operation) (runs.Scope, error)
}

// MintEvidenceAuthority resolves the authority behind one evidence read.
//
// Nothing about the read is asserted by the caller except the purpose it is
// audited under: the tenant scope and the accessor identity come from the
// verified request authority, and the clearance comes from the data
// classifications the scope's current authority grants that actor. That is
// what makes a forged clearance impossible rather than merely rejected — an
// unminted authority carries no resolver and discloses nothing.
func MintEvidenceAuthority(ctx context.Context, authorizer EvidenceAccessAuthorizer, source authority.Source, claims auth.Claims, purpose string) (EvidenceAuthority, error) {
	return resolveEvidenceAuthority(ctx, authorizer, source, claims, purpose)
}

func resolveEvidenceAuthority(ctx context.Context, authorizer EvidenceAccessAuthorizer, source authority.Source, claims auth.Claims, purpose string) (EvidenceAuthority, error) {
	if authorizer == nil || source == nil {
		return EvidenceAuthority{}, fmt.Errorf("evidence access requires a request authorizer and the current-authority source")
	}
	if purpose == "" || len(purpose) > 256 {
		return EvidenceAuthority{}, fmt.Errorf("evidence reads require a bounded declared purpose")
	}
	scope, err := authorizer.Authorize(ctx, claims, auth.OpReadEvidence)
	if err != nil {
		return EvidenceAuthority{}, err
	}
	current, err := source.Current(ctx, authority.Scope{WorkspaceID: scope.WorkspaceID, ProjectID: scope.ProjectID, ActorID: scope.ActorID})
	if err != nil {
		return EvidenceAuthority{}, err
	}
	if !current.Active() {
		return EvidenceAuthority{}, evidenceAccessDenied("current authority no longer permits evidence access")
	}
	if current.ActorRole == "" {
		return EvidenceAuthority{}, evidenceAccessDenied("the scope admits no role for this actor")
	}
	// The clearance is the accessor's own, read from the scope's subject
	// register. It is deliberately not the scope's dispatch grants: those are
	// shared by every actor in the workspace, so a clearance held there would
	// disclose evidence to all of them at once.
	clearance := current.ActorGrants.Clearance()
	if clearance == "" {
		return EvidenceAuthority{}, evidenceAccessDenied("current authority grants this actor no evidence data classification")
	}
	value := EvidenceAuthority{
		scope:     Scope{WorkspaceID: scope.WorkspaceID, ProjectID: scope.ProjectID},
		accessor:  scope.ActorID,
		purpose:   purpose,
		clearance: clearance,
		resolve: func(ctx context.Context) (EvidenceAuthority, error) {
			return resolveEvidenceAuthority(ctx, authorizer, source, claims, purpose)
		},
	}
	if err := value.Validate(); err != nil {
		return EvidenceAuthority{}, err
	}
	return value, nil
}

// Revalidated re-reads the authority from its live sources and returns the
// authority in force now. A store calls it before disclosing any evidence
// bytes, so a revoked subject, a deactivated scope, a withdrawn role, or a
// reduced clearance takes effect on this read. An authority whose scope or
// accessor identity moved underneath it is refused outright rather than
// silently repointed at another tenant.
func (a EvidenceAuthority) Revalidated(ctx context.Context) (EvidenceAuthority, error) {
	if a.resolve == nil {
		return EvidenceAuthority{}, evidenceAccessDenied("evidence reads require a minted access authority")
	}
	current, err := a.resolve(ctx)
	if err != nil {
		return EvidenceAuthority{}, err
	}
	if current.scope != a.scope || current.accessor != a.accessor {
		return EvidenceAuthority{}, evidenceAccessDenied("the accessor's authority no longer covers the scope this read was minted for")
	}
	return current, nil
}

func evidenceAccessDenied(detail string) problem.Details {
	value := problem.New(problem.CodeAuthorizationDenied, "")
	value.Detail = detail
	return value
}

// classificationRank orders the registered data classifications, lowest
// first. A read discloses a record only when the accessor's clearance reaches
// at least the record's classification; an unregistered value ranks zero and
// therefore never passes.
//
// It defers to the one governed ranking the whole runtime reads rather than
// keeping a second copy: a clearance ordered one way here and another way
// where custody is decided would be two different rules wearing one name.
func classificationRank(classification string) int {
	return authority.ClassificationRank(classification)
}

func (a EvidenceAuthority) Validate() error {
	if err := a.scope.Validate(); err != nil {
		return fmt.Errorf("evidence reads require the accessor's authorized tenant scope: %w", err)
	}
	if a.accessor == "" || len(a.accessor) > 128 {
		return fmt.Errorf("evidence reads require a bounded accessor identity")
	}
	if a.purpose == "" || len(a.purpose) > 256 {
		return fmt.Errorf("evidence reads require a bounded declared purpose")
	}
	if classificationRank(a.clearance) == 0 {
		return fmt.Errorf("evidence read clearance %q is not a registered data classification", a.clearance)
	}
	return nil
}

// Permits reports whether the authority's clearance reaches one record's data
// classification. An unregistered classification never passes.
func (a EvidenceAuthority) Permits(classification string) bool {
	recorded := classificationRank(classification)
	return recorded != 0 && classificationRank(a.clearance) >= recorded
}

// PermittedClassifications lists every data classification this authority may
// see. A store filters on it rather than discarding rows after reading them,
// so a bounded read returns as many disclosable records as it was asked for
// instead of however many happened to survive the clearance check.
func (a EvidenceAuthority) PermittedClassifications() []string {
	var permitted []string
	for _, classification := range []string{"public", "internal", "confidential", "restricted"} {
		if a.Permits(classification) {
			permitted = append(permitted, classification)
		}
	}
	return permitted
}

// RetentionWindow is the repository-owned disclosure lifetime of one
// retention category. It is governance, not a deployment knob: operational
// facts age out quickly, audit facts survive a full review cycle, and
// security facts outlive both. Recorded evidence is never rewritten or
// deleted — the window bounds disclosure, so the integrity digest keeps
// attesting the record it was computed over.
func RetentionWindow(category string) (time.Duration, error) {
	switch category {
	case RetentionOperational:
		return 30 * 24 * time.Hour, nil
	case RetentionAudit:
		return 365 * 24 * time.Hour, nil
	case RetentionSecurity:
		return 10 * 365 * 24 * time.Hour, nil
	default:
		return 0, fmt.Errorf("evidence retention category %q is not registered", category)
	}
}

// The registered retention categories.
const (
	RetentionOperational = "operational"
	RetentionAudit       = "audit"
	RetentionSecurity    = "security"
)

// RetentionCategories lists every registered retention category. A store that
// derives disclosure deadlines per category reads this list, so adding a
// category cannot leave a store silently filtering on an incomplete set.
func RetentionCategories() []string {
	return []string{RetentionOperational, RetentionAudit, RetentionSecurity}
}

// DisclosureDeadline is when one recorded fact stops being disclosable. It is
// derived from the recording time and the governed window rather than stored,
// so a deadline can never drift away from the governance that defines it.
func DisclosureDeadline(recordedAt time.Time, category string) (time.Time, error) {
	window, err := RetentionWindow(category)
	if err != nil {
		return time.Time{}, err
	}
	return recordedAt.Add(window), nil
}

// RetentionCutoffs maps each registered retention category to the earliest
// recording time still disclosable at the given moment.
func RetentionCutoffs(now time.Time) (map[string]time.Time, error) {
	cutoffs := make(map[string]time.Time, len(RetentionCategories()))
	for _, category := range RetentionCategories() {
		window, err := RetentionWindow(category)
		if err != nil {
			return nil, err
		}
		cutoffs[category] = now.Add(-window)
	}
	return cutoffs, nil
}

// evidenceTimeLayout is the canonical millisecond-precision UTC timestamp the
// evidence contract requires.
const evidenceTimeLayout = "2006-01-02T15:04:05.000Z"

const evidenceTypePattern = `^(agent|model|tool|validation|artifact|approval|commit|domain|recovery)\.[a-z0-9][a-z0-9.-]*$`

const traceparentPattern = `^[0-9a-f]{2}-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$`
const digestPattern = `^sha256:[0-9a-f]{64}$`

// opaqueIdentity reports whether value is a bounded opaque identifier the
// canonical contracts accept wherever they reference one.
func opaqueIdentity(value string) bool {
	return matches(opaqueIdentityPattern, value)
}

const opaqueIdentityPattern = `^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`

// matches reports whether value satisfies one of this package's fixed
// patterns. The patterns are constants, so a compilation failure here is a
// programmer error rather than an input error.
func matches(pattern, value string) bool {
	matched, err := regexp.MatchString(pattern, value)
	return err == nil && matched
}

// ValidateEvidence enforces the internal evidence contract before anything is
// stored: namespaced type, registered classification and retention, complete
// producer material, correlation that the canonical contract accepts, bounded
// payload, and the same prohibited-content denylist the public envelope uses.
func ValidateEvidence(value Evidence) error {
	if !opaqueIdentity(value.WorkspaceID) || !opaqueIdentity(value.ProjectID) || !opaqueIdentity(value.RunID) || !opaqueIdentity(value.EvidenceID) {
		return fmt.Errorf("evidence requires bounded workspace, project, run, and evidence identities")
	}
	for _, correlation := range []string{value.TurnID, value.WorkflowID, value.PublicEventID} {
		if correlation != "" && !opaqueIdentity(correlation) {
			return fmt.Errorf("evidence correlation identity %q is not a bounded opaque identifier", correlation)
		}
	}
	// The public registry is checked first so the separation it enforces is a
	// reachable, testable rule rather than one the namespace pattern happens
	// to shadow: widening either list can never quietly let a public type
	// become an evidence type.
	if PublicEventType(value.Type) {
		return fmt.Errorf("evidence type %q is a public event type", value.Type)
	}
	if !matches(evidenceTypePattern, value.Type) || len(value.Type) > 128 {
		return fmt.Errorf("evidence type %q is not in a registered internal namespace", value.Type)
	}
	if classificationRank(value.Classification) == 0 {
		return fmt.Errorf("evidence data classification %q is not registered", value.Classification)
	}
	if _, err := RetentionWindow(value.Retention); err != nil {
		return err
	}
	if value.OccurredAt.IsZero() {
		return fmt.Errorf("evidence requires its occurrence time")
	}
	if value.Producer.Component == "" || len(value.Producer.Component) > 128 {
		return fmt.Errorf("evidence requires a bounded producing component")
	}
	// Producer material is what makes a fact attributable: policy and
	// contract-bill-of-materials digests are always present, and a definition
	// digest is present whenever an Agent definition was already resolved.
	if !matches(digestPattern, value.Producer.PolicyDigest) || !matches(digestPattern, value.Producer.ContractBOMDigest) {
		return fmt.Errorf("evidence requires the producer's policy and contract bill-of-materials digests")
	}
	if value.Producer.DefinitionDigest != "" && !matches(digestPattern, value.Producer.DefinitionDigest) {
		return fmt.Errorf("evidence producer definition digest is malformed")
	}
	if !matches(traceparentPattern, value.Traceparent) {
		return fmt.Errorf("evidence requires a well-formed trace context")
	}
	if len(value.Payload) > 16 {
		return fmt.Errorf("evidence payload exceeds the bounded fact set")
	}
	for key, field := range value.Payload {
		if key == "" || len(key) > 64 || len(field) > 1024 {
			return fmt.Errorf("evidence payload facts must be bounded strings")
		}
		if prohibitedContent(key + " " + field) {
			return fmt.Errorf("evidence payload carries prohibited content")
		}
	}
	return nil
}

// evidenceDocument renders the producer-owned part of one evidence fact:
// everything the producer decided and nothing the store allocates. Both the
// canonical document and the stable identity digest are built from it, so the
// identity always covers exactly the content that is recorded.
func evidenceDocument(value Evidence) map[string]any {
	document := map[string]any{
		"kind":               "AgentEvidence",
		"evidenceId":         value.EvidenceID,
		"runId":              value.RunID,
		"workspaceId":        value.WorkspaceID,
		"projectId":          value.ProjectID,
		"evidenceType":       value.Type,
		"occurredAt":         value.OccurredAt.UTC().Format(evidenceTimeLayout),
		"producer":           producerDocument(value.Producer),
		"dataClassification": value.Classification,
		"retentionCategory":  value.Retention,
		"traceContext":       map[string]string{"traceparent": value.Traceparent},
	}
	if value.TurnID != "" {
		document["turnId"] = value.TurnID
	}
	if value.WorkflowID != "" {
		document["workflowId"] = value.WorkflowID
	}
	if value.PublicEventID != "" {
		document["publicEventId"] = value.PublicEventID
	}
	if len(value.Payload) != 0 {
		document["payload"] = value.Payload
	}
	return document
}

// RenderEvidence renders the canonical AgentEvidence document for one stored
// row. The sequence and recording time come from the store, never from the
// producer.
func RenderEvidence(value Evidence, sequence uint64, recordedAt time.Time) ([]byte, error) {
	document := evidenceDocument(value)
	document["evidenceSequence"] = sequence
	document["recordedAt"] = recordedAt.UTC().Format(evidenceTimeLayout)
	rendered, err := json.Marshal(document)
	if err != nil {
		return nil, fmt.Errorf("render evidence: %w", err)
	}
	return rendered, nil
}

// EvidenceIdentity is the stable digest that binds one evidence append to the
// tenant, run, evidence identity, type, classification, retention, and
// canonical content its producer decided — and to nothing the store allocates.
//
// That is what makes idempotency decidable: a durable-operation replay of the
// same fact yields the same identity even though it would be stored under a
// different sequence and recording time, while the same EvidenceID carrying
// different content or naming a different run yields a different one and is
// refused as a conflict instead of silently answering with someone else's
// sequence.
func EvidenceIdentity(value Evidence) (string, error) {
	rendered, err := json.Marshal(evidenceDocument(value))
	if err != nil {
		return "", fmt.Errorf("render evidence identity: %w", err)
	}
	digest, err := canonical.Digest(rendered)
	if err != nil {
		return "", fmt.Errorf("digest evidence identity: %w", err)
	}
	return digest, nil
}

// EvidenceConflict is the typed conflict every store raises when an
// EvidenceID is reused for a fact that is not byte-identical to the one
// already recorded under it. Recorded evidence is immutable, so the only
// correct answer is to refuse the second fact rather than to return the first
// one's sequence for it.
func EvidenceConflict(evidenceID string) problem.Details {
	value := problem.New(problem.CodeIdempotencyConflict, "")
	value.Detail = "evidence identity " + evidenceID + " is already recorded with different content"
	return value
}

// EvidenceDigest is the integrity attestation over one rendered evidence
// document. It is taken over the canonical serialization, so the attestation
// survives any storage encoding that reorders or reformats the document and
// still fails the moment the content itself differs.
func EvidenceDigest(rendered []byte) (string, error) {
	digest, err := canonical.Digest(rendered)
	if err != nil {
		return "", fmt.Errorf("digest evidence: %w", err)
	}
	return digest, nil
}

// DecodeEvidence reconstructs one stored fact from its canonical document,
// including the sequence, recording time, and full causal and trace
// correlation. Everything it returns comes from the document the integrity
// digest attests — never from a row column — so a caller can re-decide
// scope, classification, and ordering against what was actually signed.
func DecodeEvidence(rendered []byte) (RecordedEvidence, error) {
	var document struct {
		EvidenceID     string            `json:"evidenceId"`
		RunID          string            `json:"runId"`
		WorkspaceID    string            `json:"workspaceId"`
		ProjectID      string            `json:"projectId"`
		EvidenceType   string            `json:"evidenceType"`
		EvidenceSeq    uint64            `json:"evidenceSequence"`
		RecordedAt     string            `json:"recordedAt"`
		OccurredAt     string            `json:"occurredAt"`
		Classification string            `json:"dataClassification"`
		Retention      string            `json:"retentionCategory"`
		TurnID         string            `json:"turnId"`
		WorkflowID     string            `json:"workflowId"`
		PublicEventID  string            `json:"publicEventId"`
		Payload        map[string]string `json:"payload"`
		ProducerBody   struct {
			Component         string `json:"component"`
			DefinitionDigest  string `json:"definitionDigest"`
			PolicyDigest      string `json:"policyDigest"`
			ContractBOMDigest string `json:"contractBomDigest"`
		} `json:"producer"`
		TraceContext struct {
			Traceparent string `json:"traceparent"`
		} `json:"traceContext"`
	}
	if err := json.Unmarshal(rendered, &document); err != nil {
		return RecordedEvidence{}, fmt.Errorf("decode evidence: %w", err)
	}
	occurredAt, err := time.Parse(evidenceTimeLayout, document.OccurredAt)
	if err != nil {
		return RecordedEvidence{}, fmt.Errorf("decode evidence occurrence time: %w", err)
	}
	recordedAt, err := time.Parse(evidenceTimeLayout, document.RecordedAt)
	if err != nil {
		return RecordedEvidence{}, fmt.Errorf("decode evidence recording time: %w", err)
	}
	return RecordedEvidence{
		Evidence: Evidence{
			WorkspaceID:    document.WorkspaceID,
			ProjectID:      document.ProjectID,
			RunID:          document.RunID,
			EvidenceID:     document.EvidenceID,
			Type:           document.EvidenceType,
			OccurredAt:     occurredAt,
			Producer:       EvidenceProducer{Component: document.ProducerBody.Component, DefinitionDigest: document.ProducerBody.DefinitionDigest, PolicyDigest: document.ProducerBody.PolicyDigest, ContractBOMDigest: document.ProducerBody.ContractBOMDigest},
			Classification: document.Classification,
			Retention:      document.Retention,
			TurnID:         document.TurnID,
			WorkflowID:     document.WorkflowID,
			PublicEventID:  document.PublicEventID,
			Traceparent:    document.TraceContext.Traceparent,
			Payload:        document.Payload,
		},
		Sequence:   document.EvidenceSeq,
		RecordedAt: recordedAt,
	}, nil
}

func producerDocument(producer EvidenceProducer) map[string]string {
	document := map[string]string{
		"component":         producer.Component,
		"policyDigest":      producer.PolicyDigest,
		"contractBomDigest": producer.ContractBOMDigest,
	}
	if producer.DefinitionDigest != "" {
		document["definitionDigest"] = producer.DefinitionDigest
	}
	return document
}

// prohibitedContent reports whether text carries any of the categories no
// outward or recorded shape may ever contain. One denylist serves the public
// envelope, the internal evidence payload, and the provisional delta payload,
// so the three can never drift apart.
func prohibitedContent(text string) bool {
	lowered := strings.ToLower(text)
	for _, prohibited := range ProhibitedContentCategories() {
		if strings.Contains(lowered, prohibited) {
			return true
		}
	}
	return false
}

// ProhibitedContentCategories lists the content categories no outward or
// recorded shape may ever carry, in lower case.
func ProhibitedContentCategories() []string {
	return []string{"prompt", "puckdata", "canvas", "pageir", "componentsource", "imagebytes", "signedurl", "continuation", "secret"}
}

// MemoryEvidence is the in-memory evidence store for tests. It enforces the
// same validation, idempotency, authorization, retention, integrity, and
// audited-read semantics as the durable store, so a test that passes against
// it is testing the real contract.
type MemoryEvidence struct {
	lock      sync.Mutex
	records   map[string][]RecordedEvidence
	byID      map[string]RecordedEvidence
	validator ContractValidator
	now       func() time.Time
	Reads     []string
}

// NewMemoryEvidence builds the controlled evidence store. A nil validator
// skips contract proof for callers that only exercise sequencing; production
// composition always uses the durable store.
func NewMemoryEvidence(options ...func(*MemoryEvidence)) *MemoryEvidence {
	store := &MemoryEvidence{records: map[string][]RecordedEvidence{}, byID: map[string]RecordedEvidence{}, now: func() time.Time { return time.Now().UTC() }}
	for _, option := range options {
		option(store)
	}
	return store
}

// WithEvidenceContracts proves every appended document against the canonical
// evidence contract. WithEvidenceClock fixes the store's recording time.
func WithEvidenceContracts(validator ContractValidator) func(*MemoryEvidence) {
	return func(store *MemoryEvidence) { store.validator = validator }
}

func WithEvidenceClock(now func() time.Time) func(*MemoryEvidence) {
	return func(store *MemoryEvidence) { store.now = now }
}

func evidenceRunKey(workspaceID, projectID, runID string) string {
	return workspaceID + "\x00" + projectID + "\x00" + runID
}

func (m *MemoryEvidence) AppendEvidence(ctx context.Context, value Evidence) (uint64, error) {
	if err := ValidateEvidence(value); err != nil {
		return 0, err
	}
	identity, err := EvidenceIdentity(value)
	if err != nil {
		return 0, err
	}
	m.lock.Lock()
	defer m.lock.Unlock()
	key := value.WorkspaceID + "\x00" + value.ProjectID + "\x00" + value.EvidenceID
	// Idempotency is decided on the stable identity, never on the identifier
	// alone: an identical replay answers with the original sequence, and the
	// same identifier carrying a different fact is a conflict.
	if recorded, present := m.byID[key]; present {
		if recorded.Identity != identity {
			return 0, EvidenceConflict(value.EvidenceID)
		}
		return recorded.Sequence, nil
	}
	runKey := evidenceRunKey(value.WorkspaceID, value.ProjectID, value.RunID)
	sequence := uint64(len(m.records[runKey]) + 1)
	// Recorded at exactly the precision the canonical document attests, so
	// the stored time and the attested time can never disagree.
	recordedAt := m.now().UTC().Truncate(time.Millisecond)
	rendered, err := RenderEvidence(value, sequence, recordedAt)
	if err != nil {
		return 0, err
	}
	if m.validator != nil {
		if err := m.validator.Require(ctx, AgentEvidenceSchemaURI, rendered); err != nil {
			return 0, fmt.Errorf("validate evidence against its canonical contract: %w", err)
		}
	}
	digest, err := EvidenceDigest(rendered)
	if err != nil {
		return 0, err
	}
	deadline, err := DisclosureDeadline(recordedAt, value.Retention)
	if err != nil {
		return 0, err
	}
	record := RecordedEvidence{Evidence: value, Sequence: sequence, RecordedAt: recordedAt, ExpiresAt: deadline, Digest: digest, Identity: identity}
	m.records[runKey] = append(m.records[runKey], record)
	m.byID[key] = record
	return sequence, nil
}

func (m *MemoryEvidence) RecordedEvidence(_ context.Context, scope Scope, evidenceID string) (RecordedEvidence, bool, error) {
	if err := scope.Validate(); err != nil {
		return RecordedEvidence{}, false, err
	}
	m.lock.Lock()
	defer m.lock.Unlock()
	record, present := m.byID[scope.WorkspaceID+"\x00"+scope.ProjectID+"\x00"+evidenceID]
	return record, present, nil
}

func (m *MemoryEvidence) ReadEvidence(ctx context.Context, accessor EvidenceAuthority, runID string, limit int) ([]RecordedEvidence, error) {
	// The authority in force now is what decides the read: a clearance minted
	// earlier is evidence of a past decision, never permission for this one.
	current, err := accessor.Revalidated(ctx)
	if err != nil {
		return nil, err
	}
	if err := current.Validate(); err != nil {
		return nil, err
	}
	if err := ValidateEvidenceRun(runID); err != nil {
		return nil, err
	}
	limit = BoundedEvidencePage(limit)
	m.lock.Lock()
	defer m.lock.Unlock()
	// The audit lands before any bytes are returned, exactly as it does in the
	// durable store: an evidence read without its audit record is not a mode.
	m.Reads = append(m.Reads, current.Accessor()+":"+current.Purpose())
	now := m.now().UTC()
	var disclosed []RecordedEvidence
	for _, record := range m.records[evidenceRunKey(current.Scope().WorkspaceID, current.Scope().ProjectID, runID)] {
		if !current.Permits(record.Classification) || !now.Before(record.ExpiresAt) {
			continue
		}
		if len(disclosed) == limit {
			break
		}
		disclosed = append(disclosed, record)
	}
	return disclosed, nil
}
