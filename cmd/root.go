package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// DefaultName is the invocation name used by the standalone TEErminator binary.
const DefaultName = "teerminator"

// newRootCmd builds the root command for the standalone TEErminator binary.
func newRootCmd() *cobra.Command {
	return &cobra.Command{
		Use:   DefaultName,
		Short: "Localhost proxy for verifying and enforcing TEE-attestation from remote hosts",
		Long: `TEErminator is a localhost daemon that lets you connect to remote TEE APIs
verified through attested TLS headers or dedicated session-scoped attestation.`,
	}
}

// SetupCommands builds TEErminator's subcommands and registers them on root.
//
// It is the entry point for embedding TEErminator into another CLI: pass your
// own (sub)command as root to mount `start`, `remote`, `certs` and `status`
// under it. name is the invocation prefix used in help-text examples (e.g.
// "teerminator" for the standalone binary, or "mytool teerminator" when nested
// under another CLI). opts configures the start command; the zero value is
// valid.
func SetupCommands(root *cobra.Command, name string, opts StartOptions) {
	root.AddCommand(newStartCmd(name, opts))
	root.AddCommand(newRemoteCmd(name))
	root.AddCommand(newCertsCmd())
	root.AddCommand(newStatusCmd())
}

// Execute runs the standalone TEErminator binary.
func Execute() {
	root := newRootCmd()
	SetupCommands(root, DefaultName, StartOptions{})
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
