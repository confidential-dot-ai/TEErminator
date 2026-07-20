package cmd

import (
	"context"
	"fmt"
	"os"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/confidential-dot-ai/TEErminator/internal/config"
	"github.com/confidential-dot-ai/TEErminator/internal/proxy"
	"github.com/spf13/cobra"
)

func newStatusCmd() *cobra.Command {
	var timeout time.Duration

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Check the live trust status of all configured remotes",
		Long: `Check the live trust status of all configured remotes.

Each remote is verified right now, over the same upstream TLS trust the proxy
uses: remotes with --mode attest run the full session attestation (Verified /
Failed), remotes without an attestation mode are probed for reachability
(Untrusted / Failed), and remotes whose mode the proxy cannot enforce yet are
reported Failed. The results are persisted, so 'remote ls' shows the last
checked status.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}
			if len(cfg.Remotes) == 0 {
				fmt.Println("No remotes configured.")
				return nil
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
			defer cancel()

			results := make([]proxy.CheckResult, len(cfg.Remotes))
			var wg sync.WaitGroup
			for i := range cfg.Remotes {
				wg.Add(1)
				go func() {
					defer wg.Done()
					results[i] = proxy.CheckRemote(ctx, cfg.Remotes[i], cfg.Certs)
				}()
			}
			wg.Wait()

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "Local\tRemote\tAuth\tMode\tStatus")
			for i, r := range cfg.Remotes {
				mode := string(r.Mode)
				if r.Mode == config.AttestNone {
					mode = "None"
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", r.Local, r.Remote, r.Auth, mode, results[i].Status)
				cfg.Remotes[i].Status = results[i].Status
			}
			if err := w.Flush(); err != nil {
				return err
			}

			details := false
			for i, r := range cfg.Remotes {
				if results[i].Detail == "" {
					continue
				}
				if !details {
					fmt.Println()
					details = true
				}
				fmt.Printf("%s: %s\n", r.Local, results[i].Detail)
			}

			if err := cfg.Save(); err != nil {
				return fmt.Errorf("saving checked statuses: %w", err)
			}
			return nil
		},
	}

	cmd.Flags().DurationVar(&timeout, "timeout", 10*time.Second, "overall timeout for the checks (they run concurrently)")
	return cmd
}
