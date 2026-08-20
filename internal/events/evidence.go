package events

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
)

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

// RecordedEvidence is one stored evidence row with its allocated sequence.
type RecordedEvidence struct {
	Evidence
	Sequence   uint64
	RecordedAt time.Time
}

// EvidenceRecorder appends one evidence fact, allocating the run's next
// independent evidenceSequence. Appending is idempotent by EvidenceID.
type EvidenceRecorder interface {
	AppendEvidence(context.Context, Evidence) (uint64, error)
}

// EvidenceReader reads a run's evidence in sequence order. Every read is
// access-audited with the accessor identity and declared purpose.
type EvidenceReader interface {
	ReadEvidence(ctx context.Context, scope Scope, runID, accessor, purpose string, limit int) ([]RecordedEvidence, error)
}

const evidenceTypePattern = `^(agent|model|tool|validation|artifact|approval|commit|domain|recovery)\.[a-z0-9][a-z0-9.-]*$`

// ValidateEvidence enforces the internal evidence contract before anything is
// stored: namespaced type, registered classification and retention, bounded
// payload, and the same prohibited-content denylist the public envelope uses.
func ValidateEvidence(value Evidence) error {
	if value.WorkspaceID == "" || value.ProjectID == "" || value.RunID == "" || value.EvidenceID == "" || len(value.EvidenceID) > 128 {
		return fmt.Errorf("evidence requires bounded workspace, project, run, and evidence identities")
	}
	if matched, err := regexp.MatchString(evidenceTypePattern, value.Type); err != nil || !matched || len(value.Type) > 128 {
		return fmt.Errorf("evidence type %q is not in a registered internal namespace", value.Type)
	}
	switch value.Classification {
	case "public", "internal", "confidential", "restricted":
	default:
		return fmt.Errorf("evidence data classification %q is not registered", value.Classification)
	}
	switch value.Retention {
	case "operational", "audit", "security":
	default:
		return fmt.Errorf("evidence retention category %q is not registered", value.Retention)
	}
	if value.OccurredAt.IsZero() {
		return fmt.Errorf("evidence requires its occurrence time")
	}
	if value.Producer.Component == "" || len(value.Producer.Component) > 128 {
		return fmt.Errorf("evidence requires a bounded producing component")
	}
	if len(value.Payload) > 16 {
		return fmt.Errorf("evidence payload exceeds the bounded fact set")
	}
	for key, field := range value.Payload {
		if key == "" || len(key) > 64 || len(field) > 1024 {
			return fmt.Errorf("evidence payload facts must be bounded strings")
		}
		lowered := strings.ToLower(key + " " + field)
		for _, prohibited := range []string{"prompt", "puckdata", "canvas", "pageir", "componentsource", "imagebytes", "signedurl", "continuation", "secret"} {
			if strings.Contains(lowered, prohibited) {
				return fmt.Errorf("evidence payload carries prohibited content")
			}
		}
	}
	return nil
}

// RenderEvidence renders the canonical AgentEvidence document for one stored
// row. The sequence and recording time come from the store, never from the
// producer.
func RenderEvidence(value Evidence, sequence uint64, recordedAt time.Time) ([]byte, error) {
	document := map[string]any{
		"kind":               "AgentEvidence",
		"evidenceId":         value.EvidenceID,
		"runId":              value.RunID,
		"workspaceId":        value.WorkspaceID,
		"projectId":          value.ProjectID,
		"evidenceType":       value.Type,
		"evidenceSequence":   sequence,
		"recordedAt":         recordedAt.UTC().Format("2006-01-02T15:04:05.000Z"),
		"occurredAt":         value.OccurredAt.UTC().Format("2006-01-02T15:04:05.000Z"),
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
	rendered, err := json.Marshal(document)
	if err != nil {
		return nil, fmt.Errorf("render evidence: %w", err)
	}
	return rendered, nil
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

// MemoryEvidence is the in-memory evidence store for tests. It enforces the
// same validation, idempotency, and audited-read semantics as the durable
// store.
type MemoryEvidence struct {
	lock    sync.Mutex
	records map[string][]RecordedEvidence
	byID    map[string]uint64
	Reads   []string
}

func NewMemoryEvidence() *MemoryEvidence {
	return &MemoryEvidence{records: map[string][]RecordedEvidence{}, byID: map[string]uint64{}}
}

func evidenceRunKey(workspaceID, projectID, runID string) string {
	return workspaceID + "\x00" + projectID + "\x00" + runID
}

func (m *MemoryEvidence) AppendEvidence(_ context.Context, value Evidence) (uint64, error) {
	if err := ValidateEvidence(value); err != nil {
		return 0, err
	}
	m.lock.Lock()
	defer m.lock.Unlock()
	identity := value.WorkspaceID + "\x00" + value.ProjectID + "\x00" + value.EvidenceID
	if sequence, recorded := m.byID[identity]; recorded {
		return sequence, nil
	}
	key := evidenceRunKey(value.WorkspaceID, value.ProjectID, value.RunID)
	sequence := uint64(len(m.records[key]) + 1)
	m.records[key] = append(m.records[key], RecordedEvidence{Evidence: value, Sequence: sequence, RecordedAt: time.Now().UTC()})
	m.byID[identity] = sequence
	return sequence, nil
}

func (m *MemoryEvidence) ReadEvidence(_ context.Context, scope Scope, runID, accessor, purpose string, limit int) ([]RecordedEvidence, error) {
	if accessor == "" || purpose == "" {
		return nil, fmt.Errorf("evidence reads require an accessor identity and a declared purpose")
	}
	m.lock.Lock()
	defer m.lock.Unlock()
	m.Reads = append(m.Reads, accessor+":"+purpose)
	records := m.records[evidenceRunKey(scope.WorkspaceID, scope.ProjectID, runID)]
	if limit > 0 && limit < len(records) {
		records = records[:limit]
	}
	return append([]RecordedEvidence(nil), records...), nil
}
