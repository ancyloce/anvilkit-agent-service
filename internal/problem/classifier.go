package problem

import (
	"errors"
	"fmt"
)

type Family string

const (
	FamilyProvider       Family = "provider"
	FamilyContract       Family = "contract"
	FamilyPolicy         Family = "policy"
	FamilyWorker         Family = "worker"
	FamilyArtifact       Family = "artifact"
	FamilyConflict       Family = "conflict"
	FamilyDomain         Family = "domain"
	FamilyTelemetry      Family = "telemetry"
	FamilyInfrastructure Family = "infrastructure"
	FamilyAuthentication Family = "authentication"
	FamilyAuthorization  Family = "authorization"
)

type Failure struct {
	Family Family
	Err    error
}

func (f Failure) Error() string { return fmt.Sprintf("%s failure: %v", f.Family, f.Err) }
func (f Failure) Unwrap() error { return f.Err }

type Action string

const (
	ActionAck   Action = "ack"
	ActionRetry Action = "retry"
	ActionDLQ   Action = "dlq"
)

type Classification struct {
	Problem Details
	Action  Action
}

func Classify(err error, traceID string) Classification {
	var failure Failure
	if !errors.As(err, &failure) {
		return Classification{Problem: New(CodeInternal, traceID), Action: ActionDLQ}
	}
	code, action := CodeInternal, ActionDLQ
	switch failure.Family {
	case FamilyProvider:
		code, action = CodeProviderUnavailable, ActionRetry
	case FamilyContract:
		code, action = CodeContractInvalid, ActionAck
	case FamilyPolicy:
		code, action = CodePolicyDenied, ActionAck
	case FamilyWorker:
		code, action = CodeWorkerFailed, ActionDLQ
	case FamilyArtifact:
		code, action = CodeArtifactInvalid, ActionAck
	case FamilyConflict:
		code, action = CodeVersionConflict, ActionAck
	case FamilyDomain:
		code, action = CodeDomainRejected, ActionAck
	case FamilyTelemetry:
		code, action = CodeTelemetryDegraded, ActionAck
	case FamilyInfrastructure:
		code, action = CodeInfrastructureUnavailable, ActionRetry
	case FamilyAuthentication:
		code, action = CodeAuthenticationInvalid, ActionAck
	case FamilyAuthorization:
		code, action = CodeAuthorizationDenied, ActionAck
	}
	return Classification{Problem: New(code, traceID), Action: action}
}
