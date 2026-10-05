package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/confidential-dot-ai/TEErminator/internal/config"
	"github.com/confidential-dot-ai/TEErminator/internal/proxy"
	"github.com/spf13/cobra"
)

// newAllowlistCmd builds the `allowlist` command group. name is the invocation
// prefix used in help-text examples.
func newAllowlistCmd(name string) *cobra.Command {
	allowlistCmd := &cobra.Command{
		Use:   "allowlist",
		Short: "Fetch a cluster's workload allowlist and check it against what it attested",
	}
	allowlistCmd.AddCommand(newAllowlistFetchCmd(name))
	return allowlistCmd
}

func newAllowlistFetchCmd(name string) *cobra.Command {
	var (
		output   string
		boundDir string
		force    bool
		pin      bool
		timeout  time.Duration
	)

	cmd := &cobra.Command{
		Use:   "fetch <local-addr|index>",
		Short: "Fetch a remote's allowlist document, checked against its attested stamp",
		Long: fmt.Sprintf(`Fetch a remote's allowlist document and write it only if the cluster's own
attestation names it.

The remote is attested exactly as 'status' attests it (--mode attest-lb only),
the matched-workload stamp is read off the chain-verified mesh leaf, GET
/allowlist is fetched over a connection pinned to the attested serving leaf, and
the response is written only when SHA-256 over the bytes AS RECEIVED equals the
digest the stamp names and the stamped workload resolves in the document. The
bytes are written verbatim: the digest is over those exact bytes, so re-encoding
them — even through a JSON round trip that preserves meaning — produces a file
that no longer matches the stamp. A document that fails the check is never
written, not even partially.

What this proves, and what it does not: the hardware evidence binds the mesh
leaf into the attest-lb transcript, the mesh CA's signature over that leaf
vouches for the stamp inside it, and the stamp names the allowlist digest. The
document is therefore CA-VOUCHED — the snapshot the attested front door's
workload match was decided under — not hardware-committed, and not proof of
what the cluster enforces right now.

A digest mismatch is ordinary, not an alarm: the stamp names the snapshot the
match was decided under, so an allowlist edited between the leaf's issuance and
the fetch legitimately differs. The fetch re-attests once by itself; if it still
mismatches, both digests are printed with the version counters that tell churn
apart from a substituted document.

Pass --pin to store the written file as the remote's --allowlist pin, which is
the bootstrap this command exists for: fetch the document the cluster attested,
then have every later handshake check the stamp against it.

With --bound-dir instead of --output, fetch every policy in the router's
attested rollout bound (c8s router.attest.pinnedAllowlist) into
<dir>/<hex>.json, each kept only when it hashes to its attested digest. With
--pin, their digests are added to the remote's --pin-policy set once reviewed.

  $ %s allowlist fetch 127.0.0.1:8080 -o ./allowlist.json --pin
  $ %s allowlist fetch 127.0.0.1:8080 --bound-dir ./policies`, name, name),
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}
			r := cfg.FindByKey(args[0])
			if r == nil {
				return fmt.Errorf("no remote found for %q; add it first with `remote add` or check `remote ls`", args[0])
			}

			if boundDir != "" {
				return fetchBound(cmd.Context(), cfg, r, boundDir, pin, timeout)
			}

			// Decided before any network round trip: an operator who cannot
			// write the result should not have to attest to find that out.
			out, err := resolveOutputPath(output, r, force)
			if err != nil {
				return err
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
			defer cancel()

			res, err := proxy.FetchAllowlist(ctx, *r, cfg.Certs)
			if err != nil {
				return err
			}
			// Only now, after the check passed, does anything touch the disk.
			if err := writeAllowlistFile(out, res.Document.Raw); err != nil {
				return err
			}
			printFetchSummary(out, res)

			if !pin {
				return nil
			}
			stored, err := validateWorkloadFlags(r.WorkloadName, out)
			if err != nil {
				return err
			}
			r.AllowlistPath = stored
			if err := cfg.Save(); err != nil {
				return fmt.Errorf("saving config: %w", err)
			}
			fmt.Printf("Pinned %s as the allowlist for %s: every attest-lb handshake now requires the stamp to name this file's exact bytes.\n", stored, r.Local)
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVarP(&output, "output", "o", "", "file to write the checked allowlist document to (required); written verbatim, and only if the check passes")
	f.BoolVar(&force, "force", false, "overwrite an existing output file (refused by default, and named explicitly when that file is the remote's current --allowlist pin)")
	f.StringVar(&boundDir, "bound-dir", "", "directory to write every policy in the attested rollout bound to, instead of --output")
	f.BoolVar(&pin, "pin", false, "after a successful fetch, store the written file as the remote's --allowlist pin (with --bound-dir: add the fetched digests to its --pin-policy set)")
	f.DurationVar(&timeout, "timeout", 30*time.Second, "overall timeout for the attestation and the fetch")
	cmd.MarkFlagsOneRequired("output", "bound-dir")
	cmd.MarkFlagsMutuallyExclusive("output", "bound-dir")
	return cmd
}

// fetchBound writes every attested bound policy to dir and, with pin, adds the
// digests to the remote's pinned policies.
func fetchBound(ctx context.Context, cfg *config.Config, r *config.Remote, dir string, pin bool, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	v, policies, err := proxy.FetchBoundPolicies(ctx, *r, cfg.Certs)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating %s: %w", dir, err)
	}
	written := map[string]bool{}
	for _, digest := range v.AllowlistBound {
		if written[digest] {
			continue
		}
		written[digest] = true
		path := filepath.Join(dir, strings.TrimPrefix(digest, "sha256:")+".json")
		if err := writeAllowlistFile(path, policies[digest]); err != nil {
			return err
		}
		fmt.Printf("Wrote %s (%s)\n", path, digest)
	}
	fmt.Printf("  attested measurement %s, trust %s (%s); the router's attestation commits this bound\n", v.Measurement, v.TrustMode, v.Profile)
	if !pin {
		return nil
	}
	for _, digest := range v.AllowlistBound {
		if !slices.Contains(r.PinnedPolicies, digest) {
			r.PinnedPolicies = append(r.PinnedPolicies, digest)
		}
	}
	if err := cfg.Save(); err != nil {
		return fmt.Errorf("saving config: %w", err)
	}
	fmt.Printf("Pinned %d policies for %s: every attest-lb handshake now requires the attested bound to stay within them.\n", len(r.PinnedPolicies), r.Local)
	return nil
}

// resolveOutputPath decides whether the fetched document may be written to
// path, and returns it absolute. An existing file is never overwritten without
// --force; when it is the remote's current --allowlist pin, the refusal says so
// — replacing that file changes the policy every later handshake is checked
// against.
func resolveOutputPath(path string, r *config.Remote, force bool) (string, error) {
	if path == "" {
		return "", fmt.Errorf("--output is required: the fetched allowlist is written to a file, never to stdout, so its exact bytes survive the shell")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolving --output path: %w", err)
	}
	_, statErr := os.Lstat(abs)
	switch {
	case errors.Is(statErr, os.ErrNotExist):
		return abs, nil
	case statErr != nil:
		return "", fmt.Errorf("checking --output path: %w", statErr)
	case force:
		return abs, nil
	case r.AllowlistPath != "" && filepath.Clean(r.AllowlistPath) == abs:
		return "", fmt.Errorf("%s is the allowlist %s currently pins: replacing it changes the document every attest-lb handshake is checked against. Fetch to a new path and re-pin with --pin, or pass --force to replace it in place", abs, r.Local)
	default:
		return "", fmt.Errorf("%s already exists; pass --force to overwrite it", abs)
	}
}

// writeAllowlistFile writes raw to path verbatim and atomically: the temporary
// file lives in the destination directory so the rename cannot cross a
// filesystem, and it is removed on any failure — a fetch that does not complete
// leaves neither a partial file nor a temporary one behind. raw goes to disk
// unchanged; it is the byte string the stamp's digest was checked over.
func writeAllowlistFile(path string, raw []byte) (err error) {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".allowlist-*.json.tmp")
	if err != nil {
		return fmt.Errorf("creating a temporary file in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()
	if _, err = tmp.Write(raw); err != nil {
		return fmt.Errorf("writing %s: %w", tmpName, err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("closing %s: %w", tmpName, err)
	}
	if err = os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("renaming %s to %s: %w", tmpName, path, err)
	}
	return nil
}

// printFetchSummary reports what was written and on what basis, including the
// guarantee's shape — a reader of this output must not come away thinking the
// hardware attested the allowlist.
func printFetchSummary(out string, res *proxy.AllowlistFetch) {
	doc := res.Document
	v := res.Verdict
	if res.Reattested {
		fmt.Println("Note: the first fetch raced an allowlist change; re-attested once, and the freshly issued leaf names the document below.")
	}
	fmt.Printf("Wrote %d bytes to %s\n", len(doc.Raw), out)
	fmt.Printf("  workload %s, allowlist version %s (stamped), digest sha256:%x\n", doc.Workload, doc.StampedVersion, doc.Digest)
	fmt.Printf("  attested measurement %s, trust %s (%s)\n", v.Measurement, v.TrustMode, v.Profile)
	if doc.ServedVersion != "" && doc.ServedVersion != doc.StampedVersion {
		fmt.Printf("  note: the cluster served version %s while the leaf stamps version %s; the bytes match the stamped digest, which is what the check rests on (the served counter is transport metadata, outside the digest).\n",
			doc.ServedVersion, doc.StampedVersion)
	}
	if v.Warning != "" {
		fmt.Printf("  WARNING: %s\n", v.Warning)
	}
	if v.StaticAllowlistDigest != "" {
		fmt.Printf("  sealed: the mesh CA seals digest sha256:%s as its one lifetime policy (CA launch %s verified under the remote's measurement policy), and the stamp was decided under it.\n",
			v.StaticAllowlistDigest, v.SealedCALaunch)
		return
	}
	fmt.Println("  This document is CA-vouched, not hardware-attested: the evidence binds the mesh leaf, the mesh CA vouches for the stamp in it, and the stamp names this digest.")
}
