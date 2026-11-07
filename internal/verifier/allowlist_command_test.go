package verifier_test

import (
	"context"
	"io"
	"testing"

	"github.com/confidential-dot-ai/TEErminator/cmd"
	"github.com/confidential-dot-ai/TEErminator/internal/verifier"
	"github.com/spf13/cobra"
)

func TestAllowlistFetchCommandRepin(t *testing.T) {
	verifier.RunAllowlistCommandTests(t, func(ctx context.Context, args ...string) error {
		root := &cobra.Command{Use: cmd.DefaultName}
		cmd.SetupCommands(root, cmd.DefaultName, cmd.StartOptions{})
		root.SetOut(io.Discard)
		root.SetErr(io.Discard)
		root.SetArgs(args)
		return root.ExecuteContext(ctx)
	})
}
