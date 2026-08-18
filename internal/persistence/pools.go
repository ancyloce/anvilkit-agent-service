package persistence

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Pools struct{ Control, Authority, Events, Workflow, Artifacts, Evaluation *pgxpool.Pool }

type PoolConfig struct {
	URL     string
	Role    string
	Maximum int32
}

type DatabaseTarget struct {
	Name string
	URL  string
}

// ValidateColocated requires schema-specific pool URLs to resolve to the same
// Platform Postgres database. The authority stores span the control, events,
// workflow, and artifact schemas in a single transaction, so accepting a split
// database topology would route writes to whichever URL backed the authority
// pool and leave the other configured databases silently unused.
func ValidateColocated(targets ...DatabaseTarget) error {
	var baselineName string
	var baseline databaseIdentity
	for _, target := range targets {
		if target.URL == "" {
			continue
		}
		parsed, err := pgxpool.ParseConfig(target.URL)
		if err != nil {
			return fmt.Errorf("parse %s database configuration: %w", target.Name, err)
		}
		identity := identityOf(parsed)
		if baselineName == "" {
			baselineName, baseline = target.Name, identity
			continue
		}
		if identity != baseline {
			return fmt.Errorf("%s and %s must target the same Platform Postgres database; authority transactions span schema-specific pools", baselineName, target.Name)
		}
	}
	return nil
}

type databaseIdentity struct {
	hosts    string
	database string
}

func identityOf(config *pgxpool.Config) databaseIdentity {
	hosts := []string{databaseEndpoint(config.ConnConfig.Host, config.ConnConfig.Port)}
	for _, fallback := range config.ConnConfig.Fallbacks {
		hosts = append(hosts, databaseEndpoint(fallback.Host, fallback.Port))
	}
	return databaseIdentity{hosts: strings.Join(hosts, ","), database: config.ConnConfig.Database}
}

func databaseEndpoint(host string, port uint16) string {
	if !strings.HasPrefix(host, "/") {
		host = strings.ToLower(host)
	}
	return host + ":" + strconv.FormatUint(uint64(port), 10)
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
