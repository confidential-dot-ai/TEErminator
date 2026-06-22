package cmd

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/confidential-dot-ai/TEErminator/internal/config"
	"github.com/confidential-dot-ai/TEErminator/internal/proxy"
	"github.com/spf13/cobra"
)

// defaultReattestInterval is how long a verified verdict is reused for a
// long-lived session before the next request re-attests.
const defaultReattestInterval = time.Minute

// StartOptions configures the start command when TEErminator's subcommands are
// embedded into another CLI. The zero value is valid and matches the behaviour
// of the standalone binary. It deliberately uses only standard-library types so
// external callers can construct it without importing TEErminator's internal
// packages.
type StartOptions struct {
	// ReattestInterval overrides how long a verified verdict is reused before
	// the next request re-attests. Zero (or negative) selects the default of
	// one minute.
	ReattestInterval time.Duration
	// Out receives the human-readable status lines printed while the daemon
	// runs. Nil selects os.Stdout.
	Out io.Writer
}

func newStartCmd(name string, opts StartOptions) *cobra.Command {
	reattest := opts.ReattestInterval
	if reattest <= 0 {
		reattest = defaultReattestInterval
	}
	out := opts.Out
	if out == nil {
		out = os.Stdout
	}

	return &cobra.Command{
		Use:   "start",
		Short: "Start the verifying proxy daemon",
		Long:  `Start the verifying proxy daemon, binding local ports and forwarding traffic to configured remote TEE endpoints and only accepting attested responses.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}

			if len(cfg.Remotes) == 0 {
				return fmt.Errorf("no remotes configured; add one with `%s remote add`", name)
			}

			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			tunnels := make([]*proxy.Tunnel, 0, len(cfg.Remotes))
			for _, r := range cfg.Remotes {
				t, err := proxy.StartWithOptions(ctx, r.Local, r.Remote, proxy.Options{
					// Each tunnel enforces its own remote's attestation method, so the
					// daemon can front several attested backends at once with different
					// methods per backend.
					Remote: r,
					// Re-attest at most once per interval on a long-lived session; the
					// TLS channel carries the guarantee between checks.
					ReattestInterval: reattest,
					// Operator-added CAs (`certs add`) become upstream trust anchors,
					// so a backend served by a private CA (e.g. a c8s mesh CA) verifies.
					ExtraCAs: cfg.Certs,
				})
				if err != nil {
					// Stop already-started tunnels before returning.
					for _, running := range tunnels {
						_ = running.Stop()
					}
					return fmt.Errorf("starting proxy for %s -> %s: %w", r.Local, r.Remote, err)
				}
				tunnels = append(tunnels, t)
				fmt.Fprintf(out, "Listening on %s -> %s\n", r.Local, r.Remote)
			}

			fmt.Fprintln(out, "verifying proxy running. Press Ctrl+C to stop.")
			<-ctx.Done()

			fmt.Fprintln(out, "\nShutting down...")
			for _, t := range tunnels {
				if err := t.Stop(); err != nil {
					fmt.Fprintf(os.Stderr, "error stopping tunnel: %v\n", err)
				}
			}
			return nil
		},
	}
}
