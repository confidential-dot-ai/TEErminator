package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/lunal-dev/TEErminator/internal/config"
	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show all configured remote proxies and their trust status",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load()
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "Local\tRemote\tAuth\tStatus")
		for _, r := range cfg.Remotes {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", r.Local, r.Remote, r.Auth, r.Status)
		}
		return w.Flush()
	},
}
