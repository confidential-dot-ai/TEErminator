package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/lunal-dev/TEErminator/internal/config"
	"github.com/lunal-dev/TEErminator/internal/proxy"
	"github.com/spf13/cobra"
)

// reattestInterval is how long a verified verdict is reused for a long-lived
// session before the next request re-attests.
const reattestInterval = time.Minute

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the TEErminator proxy daemon",
	Long:  `Start the TEErminator proxy daemon, binding local ports and forwarding traffic to configured remote TEE endpoints.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load()
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}

		if len(cfg.Remotes) == 0 {
			return fmt.Errorf("no remotes configured; add one with `teerminator remote add`")
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
				// Re-attest at most once per minute on a long-lived session; the
				// TLS channel carries the guarantee between checks.
				ReattestInterval: reattestInterval,
			})
			if err != nil {
				// Stop already-started tunnels before returning.
				for _, running := range tunnels {
					_ = running.Stop()
				}
				return fmt.Errorf("starting proxy for %s -> %s: %w", r.Local, r.Remote, err)
			}
			tunnels = append(tunnels, t)
			fmt.Printf("Listening on %s -> %s\n", r.Local, r.Remote)
		}

		fmt.Println("TEErminator running. Press Ctrl+C to stop.")
		<-ctx.Done()

		fmt.Println("\nShutting down...")
		for _, t := range tunnels {
			if err := t.Stop(); err != nil {
				fmt.Fprintf(os.Stderr, "error stopping tunnel: %v\n", err)
			}
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(startCmd)
}
