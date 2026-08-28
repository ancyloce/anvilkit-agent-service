package execution

import "github.com/ancyloce/anvilkit-agent-service/internal/eligibility"

// The eligibility vocabulary lives in its own leaf package so that packages
// this one depends on — the runtime transport among them — can declare where
// they may be composed. These aliases keep one vocabulary: a second Eligibility
// type would let an implementation declare production fitness in a currency the
// composition root does not check.
type (
	Eligibility           = eligibility.Eligibility
	ProductionEligibility = eligibility.ProductionEligibility
)

const (
	UndeclaredEligibility = eligibility.UndeclaredEligibility
	ControlledOnly        = eligibility.ControlledOnly
	ProductionEligible    = eligibility.ProductionEligible
)

// EligibilityOf reads what an implementation declares about itself.
func EligibilityOf(candidate any) Eligibility { return eligibility.EligibilityOf(candidate) }

func (*ControlledModelStack) Eligibility() Eligibility      { return ControlledOnly }
func (*ControlledToolExecutor) Eligibility() Eligibility    { return ControlledOnly }
func (*ControlledDomainPort) Eligibility() Eligibility      { return ControlledOnly }
func (*ControlledContractRuntime) Eligibility() Eligibility { return ControlledOnly }
func (*ControlledCommitAuthority) Eligibility() Eligibility { return ControlledOnly }
func (*ControlledArtifactPort) Eligibility() Eligibility    { return ControlledOnly }
func (*ScriptedAdapter) Eligibility() Eligibility           { return ControlledOnly }

// Eligibility of the fenced dispatch path is the eligibility of the worker it
// dispatches to. The scheduler, leases, fences, and usage accounting around
// that worker are production machinery, but they do not make the thing that
// executes real: a production-shaped wrapper over a controlled worker is still
// a controlled worker, and this is where that would otherwise be lost.
func (e *ScheduledToolExecutor) Eligibility() Eligibility {
	return EligibilityOf(e.worker)
}
