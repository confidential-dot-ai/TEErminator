package cmd

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/lunal-dev/TEErminator/internal/config"
	"github.com/spf13/cobra"
)

var remoteCmd = &cobra.Command{
	Use:   "remote",
	Short: "Manage remote TEE proxy endpoints",
}

var remoteAddCmd = &cobra.Command{
	Use:   "add <local-addr> <remote-url>",
	Short: "Add a new remote TEE proxy endpoint",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		localAddr := args[0]
		remoteURL := args[1]

		cfg, err := config.Load()
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}

		r := config.Remote{
			Local:  localAddr,
			Remote: remoteURL,
			Auth:   config.AuthNone,
			Status: config.StatusUnknown,
		}
		if err := cfg.AddRemote(r); err != nil {
			return err
		}
		if err := cfg.Save(); err != nil {
			return fmt.Errorf("saving config: %w", err)
		}

		fmt.Printf("Added %s -> %s\n", localAddr, remoteURL)
		return nil
	},
}

var remoteAuthCmd = &cobra.Command{
	Use:   "auth <local-addr> <token-file|-  for stdin>",
	Short: "Set a bearer token for a remote endpoint",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		localAddr := args[0]
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

		r := cfg.FindByLocal(localAddr)
		if r == nil {
			return fmt.Errorf("no remote found for local address %q; add it first with `remote add`", localAddr)
		}

		r.Auth = config.AuthToken
		r.Token = token

		if err := cfg.Save(); err != nil {
			return fmt.Errorf("saving config: %w", err)
		}

		fmt.Printf("Token set for %s\n", localAddr)
		return nil
	},
}

func init() {
	remoteCmd.AddCommand(remoteAddCmd)
	remoteCmd.AddCommand(remoteAuthCmd)
	rootCmd.AddCommand(remoteCmd)
}
