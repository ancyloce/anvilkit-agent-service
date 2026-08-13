package persistence

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Pools struct{ Control, Authority, Events, Workflow, Artifacts, Evaluation *pgxpool.Pool }

type PoolConfig struct {
	URL     string
	Role    string
	Maximum int32
}

func OpenPool(ctx context.Context, input PoolConfig) (*pgxpool.Pool, error) {
	if input.URL == "" {
		return nil, fmt.Errorf("open pool: database URL is required")
	}
	if input.Maximum < 1 || input.Maximum > 256 {
		return nil, fmt.Errorf("open pool: maximum must be between 1 and 256")
	}
	parsed, err := pgxpool.ParseConfig(input.URL)
	if err != nil {
		return nil, fmt.Errorf("parse pool configuration: %w", err)
	}
	parsed.MaxConns = input.Maximum
	if input.Role != "" {
		parsed.ConnConfig.RuntimeParams["role"] = input.Role
	}
	pool, err := pgxpool.NewWithConfig(ctx, parsed)
	if err != nil {
		return nil, fmt.Errorf("open bounded pool: %w", err)
	}
	return pool, nil
}

func (p Pools) Close() {
	for _, pool := range []*pgxpool.Pool{p.Control, p.Authority, p.Events, p.Workflow, p.Artifacts, p.Evaluation} {
		if pool != nil {
			pool.Close()
		}
	}
}
