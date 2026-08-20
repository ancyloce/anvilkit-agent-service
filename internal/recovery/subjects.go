package recovery

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// OperationalSubject is one indexed operational recovery subject: the
// procedure operators follow, the automated exercise that proves it, and the
// reviewers accountable for signing it off. The service owns this index so
// the invariant is machine-verifiable from the repository alone; the
// operational runbook document is written against it.
type OperationalSubject struct {
	Index     int      `json:"index"`
	Title     string   `json:"title"`
	Exercise  string   `json:"exercise"`
	Reviewers []string `json:"reviewers"`
}

// ReviewPosture records who must review the operational procedures and which
// gates their sign-off is still waiting on.
type ReviewPosture struct {
	Reviewer     string `json:"reviewer"`
	Scope        string `json:"scope"`
	PendingGates string `json:"pendingGates"`
}

// OperationalIndex is the complete tracked index: the deploy and rollback
// procedure, every numbered subject, and the review posture.
type OperationalIndex struct {
	DeployAndRollback string               `json:"deployAndRollback"`
	Subjects          []OperationalSubject `json:"subjects"`
	Review            []ReviewPosture      `json:"review"`
}

// RequiredOperationalSubjects is the number of indexed subjects the
// operational procedures must cover. It is fixed by the recovery design and
// changing it is a design change, not a test change.
const RequiredOperationalSubjects = 14

const (
	reviewerPlatformSRE = "Platform SRE"
	reviewerSecurity    = "Security"
)

// OperationalProcedures returns the tracked operational index.
func OperationalProcedures() OperationalIndex {
	return OperationalIndex{
		DeployAndRollback: "Deploy and rollback",
		Subjects: []OperationalSubject{
			{1, "Database point-in-time restore and mandatory order", "TestMandatoryThirteenStepOrderAndProbes", []string{reviewerPlatformSRE}},
			{2, "Logical-RPO-0 acknowledgement reconstruction", "TestRestoreRebuildsLostAcknowledgements", []string{reviewerPlatformSRE, reviewerSecurity}},
			{3, "Recovery-epoch rotation and register disaster procedure", "TestConditionalIncrementIsSerializedAndFailsClosed", []string{reviewerPlatformSRE, reviewerSecurity}},
			{4, "Queue and DLQ replay", "TestQueueFailureInjectionAndDeadLetterReplay", []string{reviewerPlatformSRE}},
			{5, "Transactional outbox rebuild and inbox deduplication", "TestOutboxRebuildAndInboxDeduplication", []string{reviewerPlatformSRE}},
			{6, "Apply authorization and authoritative-effect reconciliation", "TestDomainCommitUncertaintyReconciliation", []string{reviewerPlatformSRE, reviewerSecurity}},
			{7, "All-attempt usage and budget-reservation reconciliation", "TestAllAttemptUsageAndBudgetReconciliation", []string{reviewerPlatformSRE}},
			{8, "Artifact reconciliation and signed-grant revocation", "TestArtifactLifecycleAccessQuarantineAndRevocation", []string{reviewerPlatformSRE, reviewerSecurity}},
			{9, "Workspace deletion and current-authority reconciliation", "TestAuthorityFreshnessMatrix", []string{reviewerPlatformSRE, reviewerSecurity}},
			{10, "Provider disablement and propagation verification", "TestModelRegistryEligibilityAndDisablement", []string{reviewerPlatformSRE}},
			{11, "Signing-key and trust revocation and rollover", "TestSigningOverlapAndEmergencyRevocation", []string{reviewerPlatformSRE, reviewerSecurity}},
			{12, "Protected-audit outage or tamper response", "TestProtectedSinkOutageAndTamperDetection", []string{reviewerPlatformSRE, reviewerSecurity}},
			{13, "Authoritative-time skew or rollback response", "TestSkewBoundaryRollbackAndOutage", []string{reviewerPlatformSRE, reviewerSecurity}},
			{14, "Overload shedding and stuck-run diagnosis", "TestNoisyNeighbourAndQueueCapShedding", []string{reviewerPlatformSRE}},
		},
		Review: []ReviewPosture{
			{reviewerPlatformSRE, "All subjects, production products and topology, drills and paging", "Pending Gates F/G/H"},
			{reviewerSecurity, "Epoch and register, authority and deletion, key, audit, time, adversarial response", "Pending Gates F/G"},
		},
	}
}

// Validate proves the operational index is complete and well formed: every
// indexed subject present exactly once in order, each with the exercise that
// proves it and at least one accountable reviewer, and every reviewer
// carrying an explicit outstanding-gate posture.
func (i OperationalIndex) Validate() error {
	if i.DeployAndRollback == "" {
		return fmt.Errorf("operational index: the deploy and rollback procedure is missing")
	}
	if len(i.Subjects) != RequiredOperationalSubjects {
		return fmt.Errorf("operational index: %d subjects, want %d", len(i.Subjects), RequiredOperationalSubjects)
	}
	titles := make(map[string]struct{}, len(i.Subjects))
	exercises := make(map[string]struct{}, len(i.Subjects))
	for position, subject := range i.Subjects {
		if subject.Index != position+1 {
			return fmt.Errorf("operational index: subject at position %d carries index %d", position+1, subject.Index)
		}
		if subject.Title == "" || subject.Exercise == "" {
			return fmt.Errorf("operational index: subject %d has no title or no exercise", subject.Index)
		}
		if len(subject.Reviewers) == 0 {
			return fmt.Errorf("operational index: subject %d has no accountable reviewer", subject.Index)
		}
		for _, reviewer := range subject.Reviewers {
			if reviewer != reviewerPlatformSRE && reviewer != reviewerSecurity {
				return fmt.Errorf("operational index: subject %d names unknown reviewer %q", subject.Index, reviewer)
			}
		}
		if _, duplicate := titles[subject.Title]; duplicate {
			return fmt.Errorf("operational index: duplicate subject title %q", subject.Title)
		}
		if _, duplicate := exercises[subject.Exercise]; duplicate {
			return fmt.Errorf("operational index: duplicate exercise %q", subject.Exercise)
		}
		titles[subject.Title], exercises[subject.Exercise] = struct{}{}, struct{}{}
	}
	if len(i.Review) != 2 {
		return fmt.Errorf("operational index: the review posture must name both accountable reviewers")
	}
	seen := map[string]struct{}{}
	for _, posture := range i.Review {
		if posture.Reviewer != reviewerPlatformSRE && posture.Reviewer != reviewerSecurity {
			return fmt.Errorf("operational index: unknown reviewer %q", posture.Reviewer)
		}
		if posture.Scope == "" || posture.PendingGates == "" {
			return fmt.Errorf("operational index: reviewer %q has no scope or no outstanding-gate posture", posture.Reviewer)
		}
		if _, duplicate := seen[posture.Reviewer]; duplicate {
			return fmt.Errorf("operational index: duplicate reviewer %q", posture.Reviewer)
		}
		seen[posture.Reviewer] = struct{}{}
	}
	return nil
}

// ParseOperationalIndex strictly decodes a tracked operational index.
func ParseOperationalIndex(raw []byte) (OperationalIndex, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var index OperationalIndex
	if err := decoder.Decode(&index); err != nil {
		return OperationalIndex{}, fmt.Errorf("operational index: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return OperationalIndex{}, fmt.Errorf("operational index: document must contain exactly one JSON value")
	}
	return index, nil
}
