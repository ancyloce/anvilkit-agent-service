package events

import (
	"fmt"
	"strconv"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/canonical"
)

// This file owns the one deterministic path from an internal execution fact to
// a public projection (ADR-020 §2). Every production writer builds its source
// AgentEvidence here, so the evidence identity, the internal namespace, and
// the public event a projection carries are decided by one rule rather than
// per call site — which is what makes the provenance stamped on a durable
// event reproducible on replay.

// ProjectionEvidenceType maps one public lifecycle event to the internal
// evidence namespace the fact behind it is recorded under. It is total over
// the closed public registry and defined nowhere else, so a new public type
// cannot be projected until its internal namespace is decided here.
func ProjectionEvidenceType(publicType string) (string, error) {
	switch publicType {
	case TypeRunCreated:
		return "agent.run-created", nil
	case TypeStateChanged:
		return "agent.run-state-changed", nil
	case TypeInputRequested:
		return "agent.input-requested", nil
	case TypeApprovalRequested:
		return "approval.requested", nil
	case TypeArtifactAvailable:
		return "artifact.available", nil
	case TypeProblemRecorded:
		return "agent.problem-recorded", nil
	default:
		return "", fmt.Errorf("public event projection: %q is not a registered public event type", publicType)
	}
}

// ProjectionEvidenceID is the deterministic identity of the evidence one
// public event is projected from. It is derived from the public event
// identity, which is itself allocated from the run's durable sequence, so a
// replayed durable operation converges on the same evidence record instead of
// appending a second account of the same fact.
func ProjectionEvidenceID(eventID string) (string, error) {
	identity := "projection." + eventID
	if !opaqueIdentity(identity) {
		return "", fmt.Errorf("public event projection: %q does not yield a bounded evidence identity", eventID)
	}
	return identity, nil
}

// ProjectionCorrelation is the run-local correlation a projection's evidence
// carries: the durable workflow it happened under and the turn, when the
// producing boundary knows one.
type ProjectionCorrelation struct {
	WorkflowID string
	TurnID     string
}

// ProjectionEvidence builds the authoritative internal record one public event
// is projected from, and binds the two together: the evidence names the public
// event it produced, and the projection names the evidence it came from.
//
// The evidence payload restates the projected public facts rather than
// widening them. Evidence may carry more than a public event does, but a
// projection's own record is exactly the fact that was projected — anything
// richer belongs to the producing boundary that knows it, recorded as its own
// evidence.
func ProjectionEvidence(projection Projection, producer EvidenceProducer, correlation ProjectionCorrelation) (Evidence, Projection, error) {
	evidenceType, err := ProjectionEvidenceType(projection.Type)
	if err != nil {
		return Evidence{}, Projection{}, err
	}
	identity, err := ProjectionEvidenceID(projection.EventID)
	if err != nil {
		return Evidence{}, Projection{}, err
	}
	payload := map[string]string{
		"publicEventType":     projection.Type,
		"publicEventSequence": strconv.FormatUint(projection.Sequence, 10),
	}
	for key, value := range projection.Payload {
		payload[key] = value
	}
	if projection.Artifact != nil {
		payload["artifactId"] = projection.Artifact.ArtifactID
		payload["artifactDigest"] = projection.Artifact.Digest
		payload["artifactMediaType"] = projection.Artifact.MediaType
		payload["artifactSizeBytes"] = strconv.FormatInt(projection.Artifact.SizeBytes, 10)
	}
	value := Evidence{
		WorkspaceID:    projection.WorkspaceID,
		ProjectID:      projection.ProjectID,
		RunID:          projection.RunID,
		EvidenceID:     identity,
		Type:           evidenceType,
		OccurredAt:     projection.OccurredAt,
		Producer:       producer,
		Classification: "internal",
		// Public lifecycle facts are the record an audit reconstructs a run
		// from, so they outlive operational detail.
		Retention:     RetentionAudit,
		TurnID:        correlation.TurnID,
		WorkflowID:    correlation.WorkflowID,
		PublicEventID: projection.EventID,
		Traceparent:   projection.Traceparent,
		Payload:       payload,
	}
	if err := ValidateEvidence(value); err != nil {
		return Evidence{}, Projection{}, fmt.Errorf("validate projection evidence: %w", err)
	}
	projection.evidenceID = identity
	return value, projection, nil
}

// ProjectionProducer derives the producing component's attributable material
// from the run's pinned governance documents. The digests are taken over the
// canonical form of the documents themselves, so the attribution names the
// exact material in force rather than a label about it.
func ProjectionProducer(component string, definition, contractBOM, policy []byte) (EvidenceProducer, error) {
	bomDigest, err := canonical.Digest(contractBOM)
	if err != nil {
		return EvidenceProducer{}, fmt.Errorf("digest contract bill of materials: %w", err)
	}
	policyDigest, err := canonical.Digest(policy)
	if err != nil {
		return EvidenceProducer{}, fmt.Errorf("digest policy: %w", err)
	}
	producer := EvidenceProducer{Component: component, PolicyDigest: policyDigest, ContractBOMDigest: bomDigest}
	// A definition digest is present whenever the run already resolved one; a
	// child run created before resolution legitimately has none.
	if len(definition) != 0 {
		definitionDigest, err := canonical.Digest(definition)
		if err != nil {
			return EvidenceProducer{}, fmt.Errorf("digest definition: %w", err)
		}
		producer.DefinitionDigest = definitionDigest
	}
	return producer, nil
}

// ProjectionOccurrence normalizes an occurrence time to the millisecond
// precision the canonical contracts attest, so the evidence document and the
// public event it produced never disagree about when the fact happened.
func ProjectionOccurrence(value time.Time) time.Time {
	return value.UTC().Truncate(time.Millisecond)
}
