package cmd

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/confidential-dot-ai/TEErminator/internal/config"
	"github.com/spf13/cobra"
)

// newRemoteCmd builds the `remote` command group and its subcommands. name is
// the invocation prefix used in help-text examples.
func newRemoteCmd(name string) *cobra.Command {
	remoteCmd := &cobra.Command{
		Use:   "remote",
		Short: "Manage remote TEE proxy endpoints",
	}
	remoteCmd.AddCommand(newRemoteAddCmd(name))
	remoteCmd.AddCommand(newRemoteAuthCmd())
	remoteCmd.AddCommand(newRemoteRmCmd())
	remoteCmd.AddCommand(newRemoteLsCmd())
	return remoteCmd
}

func newRemoteAddCmd(name string) *cobra.Command {
	var (
		mode         string
		measurements []string
		discoveryURL string
		serverName   string
	)

	cmd := &cobra.Command{
		Use:   "add <local-addr> <remote-url>",
		Short: "Add a new remote TEE proxy endpoint",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			localAddr := args[0]
			remoteURL := args[1]

			if !config.ValidAttestMode(mode) {
				return fmt.Errorf("invalid --mode %q (want one of: attest, cds-cert, or empty)", mode)
			}

			cfg, err := config.Load()
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}

			r := config.Remote{
				Local:        localAddr,
				Remote:       remoteURL,
				Auth:         config.AuthNone,
				Status:       config.StatusUnknown,
				Mode:         config.AttestMode(mode),
				Measurements: measurements,
				DiscoveryURL: discoveryURL,
				ServerName:   serverName,
			}
			if err := cfg.AddRemote(r); err != nil {
				return err
			}
			if err := cfg.Save(); err != nil {
				return fmt.Errorf("saving config: %w", err)
			}

			if r.Mode != config.AttestNone {
				fmt.Printf("Added %s -> %s (attestation: %s)\n", localAddr, remoteURL, r.Mode)
			} else {
				fmt.Printf("Added %s -> %s\n", localAddr, remoteURL)
			}
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVar(&mode, "mode", "", "attestation mode: attest (Flow B, session-scoped endpoint attestation), cds-cert (Flow C), or empty to disable")
	f.StringSliceVar(&measurements, "measurements", nil, "accepted launch-digest allowlist (hex), comma-separated")
	f.StringVar(&discoveryURL, "discovery-url", "", "discovery base URL, reserved for Flow C (Flow B always uses the remote's origin)")
	f.StringVar(&serverName, "server-name", "", fmt.Sprintf("TLS server name (SNI) to validate the upstream certificate against, when the <remote-url> host has no matching SAN — e.g. an LB reached by IP whose cert only has an internal DNS SAN. Pair with `%s certs add <ca.pem>` to trust the issuing CA", name))
	return cmd
}

func newRemoteAuthCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "auth <local-addr|index> <token-file|-  for stdin>",
		Short: "Set a bearer token for a remote endpoint",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			key := args[0]
			tokenSrc := args[1]

			var token string
			if tokenSrc == "-" {
				data, err := io.ReadAll(bufio.NewReader(os.Stdin))
				if err != nil {
					return fmt.Errorf("reading token from stdin: %w", err)
				}
				token = strings.TrimRight(string(data), "\r\n")
			} else {
				data, err := os.ReadFile(tokenSrc)
				if err != nil {
					return fmt.Errorf("reading token file: %w", err)
				}
				token = strings.TrimRight(string(data), "\r\n")
			}

			cfg, err := config.Load()
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}

			r := cfg.FindByKey(key)
			if r == nil {
				return fmt.Errorf("no remote found for %q; add it first with `remote add` or check `remote ls`", key)
			}

			r.Auth = config.AuthToken
			r.Token = token

			if err := cfg.Save(); err != nil {
				return fmt.Errorf("saving config: %w", err)
			}

			fmt.Printf("Token set for %s\n", r.Local)
			return nil
		},
	}
}

func newRemoteRmCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rm <local-addr|index>",
		Short: "Remove a remote TEE proxy endpoint",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			key := args[0]

			cfg, err := config.Load()
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}

			r := cfg.FindByKey(key)
			if r == nil {
				return fmt.Errorf("no remote found for %q", key)
			}
			local := r.Local
			if !cfg.RemoveRemote(local) {
				return fmt.Errorf("no remote found for %q", key)
			}
			if err := cfg.Save(); err != nil {
				return fmt.Errorf("saving config: %w", err)
			}

			fmt.Printf("Removed remote %s\n", local)
			return nil
		},
	}
}

func newRemoteLsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "List configured remote TEE proxy endpoints",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}
			if len(cfg.Remotes) == 0 {
				fmt.Println("No remotes configured.")
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "#\tLocal\tRemote\tAuth\tStatus")
			for i, r := range cfg.Remotes {
				fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\n", i+1, r.Local, r.Remote, r.Auth, r.Status)
			}
			return w.Flush()
		},
	}
}
