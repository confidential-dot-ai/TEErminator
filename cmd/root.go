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

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
