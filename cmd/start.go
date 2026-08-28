package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/confidential-dot-ai/TEErminator/internal/config"
	"github.com/confidential-dot-ai/TEErminator/internal/proxy"
	"github.com/spf13/cobra"
)

// defaultReattestInterval is how long a verified verdict is reused for a
// long-lived session before the next request re-attests.
const defaultReattestInterval = time.Minute

// configPollInterval is how often the running daemon checks the config file
// for changes made by `remote add`/`remote rm`/`certs add` in another
// terminal. SIGHUP forces an immediate reload.
const configPollInterval = 2 * time.Second

// StartOptions configures the start command when TEErminator's subcommands are
// embedded into another CLI. The zero value is valid and matches the behaviour
// of the standalone binary. It deliberately uses only standard-library types so
// external callers can construct it without importing TEErminator's internal
// packages.
type StartOptions struct {
	// ReattestInterval overrides how long a verified verdict is reused before
	// the next request re-attests. Zero (or negative) selects the default of
	// one minute.
	ReattestInterval time.Duration
	// Out receives the human-readable status lines printed while the daemon
	// runs. Nil selects os.Stdout.
	Out io.Writer
}

func newStartCmd(name string, opts StartOptions) *cobra.Command {
	reattest := opts.ReattestInterval
	if reattest <= 0 {
		reattest = defaultReattestInterval
	}
	out := opts.Out
	if out == nil {
		out = os.Stdout
	}

	return &cobra.Command{
		Use:   "start",
		Short: "Start the verifying proxy daemon",
		Long:  `Start the verifying proxy daemon, binding local ports and forwarding traffic to configured remote TEE endpoints and only accepting attested responses.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}

			if len(cfg.Remotes) == 0 {
				return fmt.Errorf("no remotes configured; add one with `%s remote add`", name)
			}

			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			d := &daemon{
				reattest: reattest,
				out:      out,
				tunnels:  make(map[string]runningTunnel),
			}
			// The initial reconcile is strict: a remote that cannot start
			// (e.g. its port is taken) aborts startup, as before. Later
			// reloads only log, so a bad edit never kills a running daemon.
			if err := d.reconcile(ctx, cfg, true); err != nil {
				d.stopAll()
				return err
			}

			hup := make(chan os.Signal, 1)
			signal.Notify(hup, syscall.SIGHUP)
			defer signal.Stop(hup)

			fmt.Fprintln(out, "verifying proxy running. Press Ctrl+C to stop.")
			d.watch(ctx, hup)

			fmt.Fprintln(out, "\nShutting down...")
			d.stopAll()
			return nil
		},
	}
}

// daemon owns the running tunnels and keeps them matching the config file.
type daemon struct {
	reattest time.Duration
	out      io.Writer
	tunnels  map[string]runningTunnel // keyed by the remote's local address
}

// runningTunnel pairs a tunnel with the policy snapshot it was started under,
// so a reload can tell an unchanged remote from an edited one.
type runningTunnel struct {
	key    string
	remote string
	tunnel *proxy.Tunnel
}

// tunnelKey snapshots everything a tunnel's behaviour depends on: the remote's
// full policy and the trust store the tunnel's TLS config and CA pins were
// built from. A reload restarts a tunnel exactly when its key changes.
func tunnelKey(r config.Remote, certs []config.Cert) string {
	remoteJSON, _ := json.Marshal(r)    // struct of strings and numbers; never fails
	certsJSON, _ := json.Marshal(certs) // ditto
	return string(remoteJSON) + "\x00" + string(certsJSON)
}

// watch blocks until ctx is done, reloading the config whenever the file
// changes on disk (polled) or a SIGHUP arrives.
func (d *daemon) watch(ctx context.Context, hup <-chan os.Signal) {
	path, err := config.Path()
	if err != nil {
		fmt.Fprintf(os.Stderr, "config reload disabled: %v\n", err)
		<-ctx.Done()
		return
	}
	last := fileStamp(path)

	ticker := time.NewTicker(configPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-hup:
			last = fileStamp(path)
			d.reload(ctx)
		case <-ticker.C:
			stamp := fileStamp(path)
			if stamp == last {
				continue
			}
			last = stamp
			d.reload(ctx)
		}
	}
}

// fileStamp summarizes a file's mtime and size for cheap change detection.
func fileStamp(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%d/%d", info.ModTime().UnixNano(), info.Size())
}

// reload re-reads the config and reconciles the tunnels against it, logging
// instead of failing so the daemon survives a bad edit.
func (d *daemon) reload(ctx context.Context) {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "config changed but could not be reloaded: %v\n", err)
		return
	}
	if err := d.reconcile(ctx, cfg, false); err != nil {
		fmt.Fprintf(os.Stderr, "config reload: %v\n", err)
	}
}

// reconcile makes the running tunnels match cfg: it stops tunnels whose
// remote is gone or whose policy (or the trust store) changed, and starts
// tunnels for remotes not yet running. When strict is set the first tunnel
// that fails to start aborts with its error; otherwise failures are logged
// and the remaining remotes still start.
func (d *daemon) reconcile(ctx context.Context, cfg *config.Config, strict bool) error {
	desired := make(map[string]string, len(cfg.Remotes))
	for _, r := range cfg.Remotes {
		desired[r.Local] = tunnelKey(r, cfg.Certs)
	}

	for local, rt := range d.tunnels {
		if key, ok := desired[local]; ok && key == rt.key {
			continue
		}
		if err := rt.tunnel.Stop(); err != nil {
			fmt.Fprintf(os.Stderr, "error stopping tunnel %s: %v\n", local, err)
		}
		delete(d.tunnels, local)
		fmt.Fprintf(d.out, "Stopped %s -> %s\n", local, rt.remote)
	}

	for _, r := range cfg.Remotes {
		if _, ok := d.tunnels[r.Local]; ok {
			continue
		}
		t, err := proxy.StartWithOptions(ctx, r.Local, r.Remote, proxy.Options{
			// Each tunnel enforces its own remote's attestation method, so the
			// daemon can front several attested backends at once with different
			// methods per backend.
			Remote: r,
			// Re-attest at most once per interval on a long-lived session; the
			// TLS channel carries the guarantee between checks.
			ReattestInterval: d.reattest,
			// Operator-added CAs (`certs add`) become upstream trust anchors,
			// so a backend served by a private CA (e.g. a c8s mesh CA) verifies.
			ExtraCAs: cfg.Certs,
		})
		if err != nil {
			err = fmt.Errorf("starting proxy for %s -> %s: %w", r.Local, r.Remote, err)
			if strict {
				return err
			}
			fmt.Fprintf(os.Stderr, "%v\n", err)
			continue
		}
		d.tunnels[r.Local] = runningTunnel{key: desired[r.Local], remote: r.Remote, tunnel: t}
		fmt.Fprintf(d.out, "Listening on %s -> %s\n", r.Local, r.Remote)
	}
	return nil
}

// stopAll stops every running tunnel.
func (d *daemon) stopAll() {
	for local, rt := range d.tunnels {
		if err := rt.tunnel.Stop(); err != nil {
			fmt.Fprintf(os.Stderr, "error stopping tunnel: %v\n", err)
		}
		delete(d.tunnels, local)
	}
}
