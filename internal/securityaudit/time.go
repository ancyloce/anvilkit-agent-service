// Package securityaudit provides authoritative time and independently protected audit ports.
package securityaudit

import (
	"context"
	"fmt"
	"sync"
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
// source/skew/rollback failure becomes the zero value, which authority-issuing
// consumers reject.
type FailClosedClock struct{ Authority *AuthoritativeClock }

func (c FailClosedClock) Now() time.Time {
	if c.Authority == nil {
		return time.Time{}
	}
	value, err := c.Authority.Now(context.Background())
	if err != nil {
		return time.Time{}
	}
	return value
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
		return time.Time{}, fmt.Errorf("authoritative time unavailable: %w", err)
	}
	authoritative = authoritative.UTC()
	local := c.local.Now().UTC()
	skew := authoritative.Sub(local)
	if skew < 0 {
		skew = -skew
	}
	if skew > c.maxSkew {
		return time.Time{}, problem.New(problem.CodeAuthorityStale, "")
	}
	c.lock.Lock()
	defer c.lock.Unlock()
	if !c.last.IsZero() && authoritative.Before(c.last) {
		return time.Time{}, problem.New(problem.CodeAuthorityStale, "")
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
	if expires.IsZero() || !expires.After(notBefore) || now.Before(notBefore.Add(-c.maxSkew)) || !now.Before(expires.Add(c.maxSkew)) {
		return problem.New(problem.CodeAuthorityStale, "")
	}
	return nil
}
