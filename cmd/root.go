package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "teerminator",
	Short: "Localhost proxy for verifying and enforcing TEE-attestation from remote hosts",
	Long: `TEErminator is a localhost daemon that lets you connect to remote TEE APIs
verified through attested TLS headers or dedicated session-scoped attestation.`,
}

// SetupCommands registers all subcommands with the root command.
func SetupCommands() {
	remoteCmd.AddCommand(remoteAddCmd)
	remoteCmd.AddCommand(remoteAuthCmd)
	remoteCmd.AddCommand(remoteRmCmd)
	remoteCmd.AddCommand(remoteLsCmd)
	rootCmd.AddCommand(remoteCmd)

	certsCmd.AddCommand(certsAddCmd)
	certsCmd.AddCommand(certsRmCmd)
	rootCmd.AddCommand(certsCmd)

	rootCmd.AddCommand(statusCmd)
}

// Execute runs the root command.
func Execute() {
	SetupCommands()
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
