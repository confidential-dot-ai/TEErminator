package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/lunal-dev/TEErminator/internal/config"
	"github.com/lunal-dev/TEErminator/internal/proxy"
	"github.com/spf13/cobra"
)

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

		tunnels := make([]*proxy.Tunnel, 0, len(cfg.Remotes))
		for _, r := range cfg.Remotes {
			t, err := proxy.Start(r.Local, r.Remote, r.Token)
			if err != nil {
				// Stop already-started tunnels before returning
				for _, running := range tunnels {
					running.Stop()
				}
				return fmt.Errorf("starting proxy for %s -> %s: %w", r.Local, r.Remote, err)
			}
			tunnels = append(tunnels, t)
			fmt.Printf("Listening on %s -> %s\n", r.Local, r.Remote)
		}

		fmt.Println("TEErminator running. Press Ctrl+C to stop.")

		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig

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
