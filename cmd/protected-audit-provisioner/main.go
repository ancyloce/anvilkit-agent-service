// Command protected-audit-provisioner establishes the Agent Service's
// protected audit and then exits.
//
// It exists so the running service does not have to. Establishing the audit
// needs a credential that owns the table, its triggers, and the grants on it;
// appending to the audit needs a credential that can do neither. Those were
// once the same startup path in one process, which meant the service was
// configured with an administrative credential for its whole lifetime — and a
// process that holds the standing to drop the append-only trigger owns the
// account of its own security decisions, whether it ever exercises that
// standing or not. Every barrier below it was decoration.
//
// So provisioning is a separate workload with a separate credential and a
// bounded lifetime: an init container, a Job, or an operator step run before
// the service starts. It takes the runtime login as a role name rather than a
// connection string, so it holds nothing the service connects with. The
// service, in turn, refuses to start against an audit this command has not
// established.
//
// Running it again is safe: the schema, barriers, and grant converge, and the
// proofs are taken again on what is actually there.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ancyloce/anvilkit-agent-service/internal/config"
	securityauditpg "github.com/ancyloce/anvilkit-agent-service/internal/securityaudit/postgres"
)

// provisioningDeadline bounds the whole run. Provisioning is a handful of
// statements against one database; a run that is still going after this is
// waiting on something that is not going to answer.
const provisioningDeadline = 2 * time.Minute

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("protected audit provisioned")
}

func run() error {
	settings, err := config.LoadProtectedAuditProvisioning()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, provisioningDeadline)
	defer cancel()

	admin, err := pgxpool.New(ctx, settings.AdminURL)
	if err != nil {
		return fmt.Errorf("open protected audit administration pool: %w", err)
	}
	// The administrative connection is closed with this command's process.
	// Nothing that outlives it ever holds this credential.
	defer admin.Close()
	return securityauditpg.Provision(ctx, admin, settings.RuntimeLogin, settings.RequiresSeparateLogins())
}
