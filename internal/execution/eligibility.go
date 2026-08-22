package execution

// Eligibility is an implementation's own statement about where it may be
// composed. It exists because the alternative — inferring the answer from an
// implementation's name — is only ever as good as the naming convention, and a
// convention is not a control. A controlled fake that happened to be named
// without the expected word would have passed a name test; it cannot pass this
// one, because it has to say what it is.
type Eligibility uint8

const (
	// UndeclaredEligibility is the zero value, and the reason this is a
	// declaration rather than a flag: an implementation that says nothing
	// about itself is refused in production. Adding a new port or a new
	// implementation therefore fails closed by default, without anyone having
	// to remember to add it to a list.
	UndeclaredEligibility Eligibility = iota
	// ControlledOnly names an implementation that exists to make behaviour
	// reproducible — a scripted provider, a fake domain owner, a worker that
	// executes nothing. It talks to no real dependency and must never be
	// composed in production, whatever it is called.
	ControlledOnly
	// ProductionEligible names an implementation that talks to the real
	// dependency it stands for.
	ProductionEligible
)

// ProductionEligibility is implemented by anything selected into the
// composition root through a port that production must be able to trust.
type ProductionEligibility interface {
	Eligibility() Eligibility
}

// EligibilityOf reads what an implementation declares about itself. Anything
// that declares nothing is undeclared, which production refuses.
func EligibilityOf(candidate any) Eligibility {
	declared, ok := candidate.(ProductionEligibility)
	if !ok {
		return UndeclaredEligibility
	}
	return declared.Eligibility()
}

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
