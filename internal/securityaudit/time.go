// Package securityaudit provides authoritative time and independently protected audit ports.
package securityaudit

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
)

type TimeSource interface {
	Now(context.Context) (time.Time, error)
}
type LocalClock interface{ Now() time.Time }

type AuthoritativeClock struct {
	lock    sync.Mutex
	source  TimeSource
	local   LocalClock
	maxSkew time.Duration
	last    time.Time
}

// FailClosedClock adapts authoritative time to time.Time-only ports. A
// source, skew, or rollback failure becomes the zero value, which
// authority-issuing consumers reject.
//
// It also keeps the last failure, because the zero value alone loses the one
// thing a caller needs: whether waiting would help. An unreachable time
// authority and a tampered answer both stop the decision, but the first is a
// dependency the caller should be told to retry against and the second is
// never retryable at all. Reporting both as a denial told an operator riding
// out a brief outage that their authority was stale.
type FailClosedClock struct {
	Authority *AuthoritativeClock
	last      *atomic.Pointer[error]
}

// NewFailClosedClock builds the adapter with somewhere to keep the last
// failure. A zero-valued FailClosedClock still answers correctly; it simply
// cannot say why it refused.
func NewFailClosedClock(authority *AuthoritativeClock) FailClosedClock {
	return FailClosedClock{Authority: authority, last: &atomic.Pointer[error]{}}
}

func (c FailClosedClock) Now() time.Time {
	if c.Authority == nil {
		return time.Time{}
	}
	value, err := c.Authority.Now(context.Background())
	if err != nil {
		c.record(err)
		return time.Time{}
	}
	c.record(nil)
	return value
}

func (c FailClosedClock) record(err error) {
	if c.last == nil {
		return
	}
	if err == nil {
		c.last.Store(nil)
		return
	}
	c.last.Store(&err)
}

// LastFailure answers why the clock last refused, or nil if it did not. A
// caller that saw the zero instant reads this to decide what to tell its own
// caller: a retryable dependency failure, or a refusal that will not change.
func (c FailClosedClock) LastFailure() error {
	if c.last == nil {
		return nil
	}
	if held := c.last.Load(); held != nil {
		return *held
	}
	return nil
}

// Refusal renders the governed problem this clock's last zero instant stands
// for, or nil when it last answered. It is what lets a boundary that only sees
// a zero instant tell its caller whether to wait or to stop.
func (c FailClosedClock) Refusal() error {
	if c.LastFailure() == nil {
		return nil
	}
	return TimeRefusal(c)
}

// TimeRefusal renders the governed problem a zero instant stands for. It
// prefers what the clock actually reported; with nothing recorded it answers
// as an unavailable dependency, because an unexplained absence of time is a
// failure to establish it rather than a proven attack on it.
func TimeRefusal(clock FailClosedClock) error {
	if details, governed := GovernedTimeFailure(clock.LastFailure()); governed {
		return details
	}
	details := problem.New(problem.CodeInfrastructureUnavailable, "")
	details.Detail = "the approved time authority could not be established"
	return details
}

func NewAuthoritativeClock(source TimeSource, local LocalClock, maximumSkew time.Duration) (*AuthoritativeClock, error) {
	if source == nil || local == nil || maximumSkew < 0 {
		return nil, fmt.Errorf("authoritative time source, local clock, and non-negative skew are required")
	}
	return &AuthoritativeClock{source: source, local: local, maxSkew: maximumSkew}, nil
}

func (c *AuthoritativeClock) Now(ctx context.Context) (time.Time, error) {
	authoritative, err := c.source.Now(ctx)
	if err != nil {
		// The source already says which kind of failure this is, and that
		// distinction survives to the caller untouched: wrapping it in a
		// generic message here is what used to make an outage and a forged
		// answer indistinguishable further up.
		if _, governed := GovernedTimeFailure(err); governed {
			return time.Time{}, err
		}
		return time.Time{}, TimeUnavailable{Err: err}
	}
	authoritative = authoritative.UTC()
	local := c.local.Now().UTC()
	if authoritative.IsZero() || local.IsZero() {
		return time.Time{}, TimeUntrusted{Err: fmt.Errorf("authoritative time: the answered instant is empty")}
	}
	skew := authoritative.Sub(local)
	if skew < 0 {
		skew = -skew
	}
	if skew > c.maxSkew {
		// A signed answer this far from the host's own clock is not a
		// dependency problem. Something is wrong with the time itself, and
		// asking again will not settle it.
		return time.Time{}, TimeUntrusted{Err: fmt.Errorf("authoritative time: the answered instant is %s from local time, beyond the permitted skew", skew)}
	}
	c.lock.Lock()
	defer c.lock.Unlock()
	if !c.last.IsZero() && authoritative.Before(c.last) {
		return time.Time{}, TimeUntrusted{Err: fmt.Errorf("authoritative time: the authority answered earlier than it already had")}
	}
	c.last = authoritative
	return authoritative, nil
}

// ValidateWindow is used before issuing or extending time-sensitive authority.
func (c *AuthoritativeClock) ValidateWindow(ctx context.Context, notBefore, expires time.Time) error {
	now, err := c.Now(ctx)
	if err != nil {
		return err
	}
	if notBefore.IsZero() || expires.IsZero() || !expires.After(notBefore) || now.Before(notBefore.Add(-c.maxSkew)) || !now.Before(expires) {
		return problem.New(problem.CodeAuthorityStale, "")
	}
	return nil
}
