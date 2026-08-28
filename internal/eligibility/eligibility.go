// Package eligibility carries an implementation's own statement about where it
// may be composed.
//
// It is a leaf package on purpose. The statement has to be readable by every
// package the composition root selects an implementation from — including the
// ones the execution package itself depends on — and a declaration that could
// only be made by packages sitting above the pipeline would be unavailable
// exactly where a new transport or adapter is written.
package eligibility

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
