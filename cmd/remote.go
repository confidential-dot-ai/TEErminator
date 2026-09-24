package cmd

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/confidential-dot-ai/TEErminator/internal/config"
	"github.com/confidential-dot-ai/TEErminator/internal/verifier"
	"github.com/spf13/cobra"
)

// defaultC8sServerName is the internal DNS SAN a stock c8s TLS LoadBalancer
// serves. Remotes added by raw IP without --server-name default to it, since
// an IP-reached c8s LB is the common case and its cert carries no IP SAN.
const defaultC8sServerName = "c8s-tls-lb.c8s-system.svc"

// defaultServerName returns the ServerName to store for a remote: the explicit
// override when given, otherwise defaultC8sServerName when remoteURL's host is
// a raw IP (whose cert can't be expected to match the dial address). The bool
// reports whether the default was applied.
func defaultServerName(remoteURL, explicit string) (string, bool) {
	if explicit != "" {
		return explicit, false
	}
	u, err := url.Parse(remoteURL)
	if err != nil || net.ParseIP(u.Hostname()) == nil {
		return "", false
	}
	return defaultC8sServerName, true
}

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

var policyDigestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// validatePolicyDigests checks --pin-policy values are sha256:<64 lowercase hex>.
func validatePolicyDigests(digests []string) error {
	for _, d := range digests {
		if !policyDigestRE.MatchString(d) {
			return fmt.Errorf("--pin-policy %q: want sha256:<64 lowercase hex>", d)
		}
	}
	return nil
}

// validateWorkloadFlags checks the --workload/--allowlist pins at add time:
// the name must satisfy the workload-name grammar, the allowlist file must
// exist and parse as a c8s.allowlist/v1 document, and when both are given the
// name must resolve in the document. It returns the allowlist path to store
// (absolute, so the daemon finds it regardless of working directory).
func validateWorkloadFlags(workload, allowlistPath string) (string, error) {
	if workload != "" && !verifier.ValidWorkloadName(workload) {
		return "", fmt.Errorf("invalid --workload %q: want 1..%d bytes matching [A-Za-z0-9][A-Za-z0-9._-]*", workload, verifier.MaxWorkloadNameLen)
	}
	if allowlistPath == "" {
		return "", nil
	}
	raw, err := os.ReadFile(allowlistPath)
	if err != nil {
		return "", fmt.Errorf("reading --allowlist: %w", err)
	}
	doc, err := verifier.ParsePinnedAllowlist(raw)
	if err != nil {
		return "", fmt.Errorf("--allowlist %s: %w", allowlistPath, err)
	}
	if workload != "" {
		if _, ok := doc.Workloads[workload]; !ok {
			return "", fmt.Errorf("--allowlist %s does not contain workload %q", allowlistPath, workload)
		}
	}
	abs, err := filepath.Abs(allowlistPath)
	if err != nil {
		return "", fmt.Errorf("resolving --allowlist path: %w", err)
	}
	return abs, nil
}

// validateImageManifestFlag checks --image-manifest at add time — the file must
// exist and parse as a complete mrtd+rtmr1+rtmr2 tuple — and returns the
// absolute path to store, so the daemon finds it regardless of working
// directory.
func validateImageManifestFlag(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	if _, err := verifier.LoadImageManifest(path); err != nil {
		return "", fmt.Errorf("--image-manifest: %w", err)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolving --image-manifest path: %w", err)
	}
	return abs, nil
}

// validatePinModes rejects a platform pin stored on a remote that can never
// enforce it. Only attest-lb verifies hardware evidence, so on any other mode
// these three are inert: the remote reads as configured, and the gap only
// surfaces much later — if ever — as traffic that was never measured.
func validatePinModes(mode config.AttestMode, imageManifest, expectedRTMR3, minTCB string) error {
	if mode == config.AttestEndpoint {
		return nil
	}
	for _, pin := range []struct{ flag, value string }{
		{"--image-manifest", imageManifest},
		{"--expected-rtmr3", expectedRTMR3},
		{"--min-tcb", minTCB},
	} {
		if pin.value != "" {
			return fmt.Errorf("%s requires --mode attest-lb: nothing verifies hardware measurements in mode %q, so the pin would be stored but never enforced", pin.flag, mode)
		}
	}
	return nil
}

// validateStaticAllowlistFlags checks the sealed-policy flags at add time:
// both need --mode attest-lb (nothing else commits a mesh CA to verify a seal
// on), and --init-data needs --static-allowlist and is 32 bytes of hex.
func validateStaticAllowlistFlags(mode config.AttestMode, staticAllowlist bool, initData string) error {
	if mode != config.AttestEndpoint {
		switch {
		case staticAllowlist:
			return fmt.Errorf("--static-allowlist requires --mode attest-lb: only the attest-lb handshake commits the mesh CA the seal is read off, so the pin would be stored but never enforced")
		case initData != "":
			return fmt.Errorf("--init-data requires --mode attest-lb and --static-allowlist: it pins the sealed mesh CA's evidence, which nothing verifies in mode %q", mode)
		}
	}
	_, err := verifier.ValidateStaticAllowlistPins(staticAllowlist, strings.TrimSpace(initData))
	return err
}

// validateRTMR3Flag validates the --expected-rtmr3 pin and returns the value to
// store. Surrounding whitespace is trimmed here, at the flag boundary only: a
// register pin is copy-pasted out of terminal output, so a trailing newline is
// a typing artefact rather than a different value. The manifest parser stays
// strict — there the exact file bytes are the reference.
func validateRTMR3Flag(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", nil
	}
	if _, err := verifier.ParseRegisterHex(s); err != nil {
		return "", fmt.Errorf("--expected-rtmr3 %w", err)
	}
	return s, nil
}

// parseMinTCBFlag parses --min-tcb's four comma-separated components
// (bootloader,tee,snp,microcode), each 0-255. Empty means no floor, and so does
// an all-zero floor: every component is >= 0, so it gates nothing, while a
// stored floor would reject all TDX evidence as a cross-platform pin.
func parseMinTCBFlag(s string) (*config.TCBFloor, error) {
	if s == "" {
		return nil, nil
	}
	parts := strings.Split(s, ",")
	if len(parts) != 4 {
		return nil, fmt.Errorf("invalid --min-tcb %q: want four comma-separated components <bootloader,tee,snp,microcode>", s)
	}
	vals := make([]uint8, 4)
	for i, p := range parts {
		n, err := strconv.ParseUint(strings.TrimSpace(p), 10, 8)
		if err != nil {
			return nil, fmt.Errorf("invalid --min-tcb component %q: want an integer 0-255", p)
		}
		vals[i] = uint8(n)
	}
	floor := config.TCBFloor{Bootloader: vals[0], TEE: vals[1], SNP: vals[2], Microcode: vals[3]}
	if floor == (config.TCBFloor{}) {
		return nil, nil
	}
	return &floor, nil
}

func newRemoteAddCmd(name string) *cobra.Command {
	var (
		mode            string
		measurements    []string
		discoveryURL    string
		serverName      string
		workload        string
		allowlistPath   string
		imageManifest   string
		expectedRTMR3   string
		minTCB          string
		staticAllowlist bool
		initData        string
		pinPolicies     []string
	)

	cmd := &cobra.Command{
		Use:   "add <local-addr> <remote-url>",
		Short: "Add a new remote TEE proxy endpoint",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			localAddr := args[0]
			remoteURL := args[1]

			attestMode, normalized, ok := config.ParseAttestMode(mode)
			if !ok {
				return fmt.Errorf("invalid --mode %q (want one of: attest-lb, cds-cert, or empty)", mode)
			}
			if normalized {
				fmt.Printf("Note: --mode attest is now attest-lb; storing mode %q.\n", attestMode)
			}

			if err := validatePinModes(attestMode, imageManifest, expectedRTMR3, minTCB); err != nil {
				return err
			}
			if err := validateStaticAllowlistFlags(attestMode, staticAllowlist, initData); err != nil {
				return err
			}
			// How the measurement pins relate to each other is one rule set,
			// shared with the verifier so a config the CLI refuses to write is
			// also a config the daemon refuses to run.
			if err := verifier.ValidatePinCombination(measurements, imageManifest, expectedRTMR3); err != nil {
				return err
			}

			allowlistStored, err := validateWorkloadFlags(workload, allowlistPath)
			if err != nil {
				return err
			}
			if err := validatePolicyDigests(pinPolicies); err != nil {
				return err
			}
			manifestStored, err := validateImageManifestFlag(imageManifest)
			if err != nil {
				return err
			}
			rtmr3Stored, err := validateRTMR3Flag(expectedRTMR3)
			if err != nil {
				return err
			}
			tcbFloor, err := parseMinTCBFlag(minTCB)
			if err != nil {
				return err
			}

			cfg, err := config.Load()
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}

			serverName, defaulted := defaultServerName(remoteURL, serverName)
			if defaulted {
				fmt.Printf("Note: %s is reached by IP and no --server-name was given; defaulting the TLS server name to %q (the standard c8s LB SAN). Pass --server-name (e.g. the IP itself, for a cert with an IP SAN) to override.\n",
					remoteURL, defaultC8sServerName)
			}

			r := config.Remote{
				Local:             localAddr,
				Remote:            remoteURL,
				Auth:              config.AuthNone,
				Status:            config.StatusUnknown,
				Mode:              attestMode,
				Measurements:      measurements,
				DiscoveryURL:      discoveryURL,
				ServerName:        serverName,
				WorkloadName:      workload,
				AllowlistPath:     allowlistStored,
				ImageManifestPath: manifestStored,
				ExpectedRTMR3:     rtmr3Stored,
				MinTCB:            tcbFloor,
				StaticAllowlist:   staticAllowlist,
				InitData:          strings.ToLower(strings.TrimSpace(initData)),
				PinnedPolicies:    pinPolicies,
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
	f.StringVar(&mode, "mode", "", "attestation mode: attest-lb (per-handshake attestation binding the exact serving leaf, over ordinary TLS), cds-cert (CDS-cert pinning, not yet implemented), or empty to disable")
	f.StringSliceVar(&measurements, "measurements", nil, "accepted launch-digest allowlist (hex), comma-separated; required for attest-lb unless --image-manifest is given (an empty measurement policy is a configuration error, and the two flags are mutually exclusive)")
	f.StringVar(&discoveryURL, "discovery-url", "", "discovery base URL, reserved for cds-cert (attest-lb always uses the remote's origin)")
	f.StringVar(&serverName, "server-name", "", fmt.Sprintf("TLS server name (SNI) to validate the upstream certificate against, when the <remote-url> host has no matching SAN — e.g. an LB reached by IP whose cert only has an internal DNS SAN. Defaults to %q when <remote-url> is an IP. Pair with `%s certs add <ca.pem>` to trust the issuing CA", defaultC8sServerName, name))
	f.StringVar(&workload, "workload", "", "workload name the committed mesh leaf's matched-workload stamp must carry (attest-lb)")
	f.StringVar(&allowlistPath, "allowlist", "", "path to a pinned canonical-allowlist JSON file; hashed exactly as read against the stamp's digest, and the stamped name must resolve in it (attest-lb)")
	f.StringVar(&imageManifest, "image-manifest", "", "build-artifact manifest of the expected TDX guest image (JSON object with mrtd, rtmr1, rtmr2, each 96 lowercase hex chars, published with the image build); all three registers are pinned exactly against this one manifest, so the guest kernel and rootfs are verified rather than only the firmware. Replaces --measurements rather than adding to it. TDX evidence only — with SNP evidence this is a policy error")
	f.StringVar(&expectedRTMR3, "expected-rtmr3", "", "expected TDX RTMR[3] as 96 lowercase hex chars — pins the runtime measurement register, i.e. the ordered operator-key/workload-event chain extended after boot. This is a deployment property, NOT a cluster identity, and cannot replace an image pin, so it requires --image-manifest. TDX evidence only — with SNP evidence this is a policy error")
	f.BoolVar(&staticAllowlist, "static-allowlist", false, "require the hardware-committed mesh CA to be sealed (c8s CDS --static-allowlist): it must carry the static-allowlist stamp and RA-TLS evidence over its own key that verifies under this remote's measurement policy, the sealed digest must equal the SHA-256 of the --allowlist file when one is pinned, and the mesh leaf's stamp must have been decided under it. Without --allowlist the seal is verified but compared to no reviewed document, which the verdict warns about (attest-lb)")
	f.StringSliceVar(&pinPolicies, "pin-policy", nil, "reviewed c8s allowlist policy digest(s) sha256:<hex>, comma-separated; every policy the router's attested rollout state says may run must be one of them, and CDS must fence open connections with an activation lease. Without it the bound is verified and reported only (attest-lb)")
	f.StringVar(&initData, "init-data", "", "hex SHA-256 of the CDS pod's kata init-data document, pinned against the sealed mesh CA evidence's init-data claim (pod-as-CVM deployments; requires --static-allowlist)")
	f.StringVar(&minTCB, "min-tcb", "", "minimum SNP TCB floor as four comma-separated components <bootloader,tee,snp,microcode> (each 0-255), enforced component-wise on the verified evidence. SNP evidence only — with TDX evidence this is a policy error")
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
