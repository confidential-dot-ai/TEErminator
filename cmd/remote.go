package cmd

import (
	"bufio"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/confidential-dot-ai/TEErminator/internal/config"
	"github.com/confidential-dot-ai/TEErminator/internal/routes"
	"github.com/confidential-dot-ai/TEErminator/internal/verifier"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
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
// these are inert: the remote reads as configured, and the gap only surfaces
// much later — if ever — as traffic that was never measured.
func validatePinModes(mode config.AttestMode, pins []pinFlag) error {
	if mode == config.AttestEndpoint {
		return nil
	}
	for _, pin := range pins {
		if pin.value != "" {
			return fmt.Errorf("%s requires --mode attest-lb: nothing verifies hardware measurements in mode %q, so the pin would be stored but never enforced", pin.flag, mode)
		}
	}
	return nil
}

// pinFlag is a pin flag and its value, empty when unset.
type pinFlag struct{ flag, value string }

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

// readOperatorKeys reads flag's PEM files and returns one PEM PUBLIC KEY
// block per key, the form route_operator_keys and trust_operator_keys store,
// so the daemon needs no file at run time.
func readOperatorKeys(flag string, paths []string) ([]string, error) {
	var out []string
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", flag, err)
		}
		keys, err := routes.ParsePublicKeys(raw)
		if err != nil {
			return nil, fmt.Errorf("%s %s: %w", flag, p, err)
		}
		for _, k := range keys {
			der, err := x509.MarshalPKIXPublicKey(k)
			if err != nil {
				return nil, fmt.Errorf("%s %s: %w", flag, p, err)
			}
			out = append(out, string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})))
		}
	}
	return out, nil
}

func newRemoteAddCmd(name string) *cobra.Command {
	var (
		mode          string
		measurements  []string
		discoveryURL  string
		serverName    string
		workload      string
		allowlistPath string
		imageManifest string
		expectedRTMR3 string
		minTCB        string
		tdxTCBStatus  []string
		routeDigests  []string
		routeKeyFiles []string
		routesFloor   string
		operatorPkey  string
		rtmrs         []string
		initData      string
		sandboxID     string
		pinPolicies   []string
		trustOperator bool
		trustKeyFiles []string
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

			if err := validatePinModes(attestMode, []pinFlag{
				{"--image-manifest", imageManifest},
				{"--expected-rtmr3", expectedRTMR3},
				{"--operator-pkey", operatorPkey},
				{"--rtmr", strings.Join(rtmrs, ",")},
				{"--init-data", initData},
				{"--sandbox-id", sandboxID},
				{"--min-tcb", minTCB},
				{"--tdx-tcb-status", strings.Join(tdxTCBStatus, ",")},
				{"--route-digest", strings.Join(routeDigests, ",")},
				{"--route-operator-key", strings.Join(routeKeyFiles, ",")},
				{"--routes-floor", routesFloor},
				{"--pin-policy", strings.Join(pinPolicies, ",")},
				{"--trust-operator", map[bool]string{true: "true"}[trustOperator]},
				{"--trust-operator-key", strings.Join(trustKeyFiles, ",")},
			}); err != nil {
				return err
			}
			if len(routeDigests) > 0 && len(routeKeyFiles) > 0 {
				return fmt.Errorf("--route-digest and --route-operator-key are mutually exclusive: each is a complete route check; pass one")
			}
			if err := verifier.ValidateRouteDigests(routeDigests); err != nil {
				return fmt.Errorf("--route-digest: %w", err)
			}
			routeOperatorKeys, err := readOperatorKeys("--route-operator-key", routeKeyFiles)
			if err != nil {
				return err
			}
			// The router routes by the Host header, and a manifest names no IP.
			if u, err := url.Parse(remoteURL); len(routeKeyFiles) > 0 && (err != nil || net.ParseIP(u.Hostname()) != nil) {
				return fmt.Errorf("--route-operator-key needs a <remote-url> with a DNS name the route manifest routes, not %q", remoteURL)
			}
			if _, err := verifier.ParseTDXTCBStatuses(tdxTCBStatus); err != nil {
				return fmt.Errorf("--tdx-tcb-status: %w", err)
			}
			trustOperatorKeys, err := readOperatorKeys("--trust-operator-key", trustKeyFiles)
			if err != nil {
				return err
			}
			// How the pins relate to each other is one rule set, shared with
			// the verifier so a config the CLI refuses to write is also a
			// config the daemon refuses to run.
			if err := verifier.ValidatePinCombination(config.Remote{
				Measurements: measurements, ImageManifestPath: imageManifest, ExpectedRTMR3: expectedRTMR3,
				OperatorPubkeyPath: operatorPkey, RTMRs: rtmrs, InitDataDigest: initData, SandboxID: sandboxID,
				RouteOperatorKeys: routeOperatorKeys, RouteFloor: routesFloor,
				PinnedPolicies: pinPolicies, TrustOperator: trustOperator, TrustOperatorKeys: trustOperatorKeys,
			}); err != nil {
				return err
			}
			operatorPkeyStored, err := validateOperatorPkeyFlag(operatorPkey)
			if err != nil {
				return err
			}
			pinPoliciesStored, err := validatePinPolicyFlags(pinPolicies)
			if err != nil {
				return err
			}

			allowlistStored, err := validateWorkloadFlags(workload, allowlistPath)
			if err != nil {
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
				Local:              localAddr,
				Remote:             remoteURL,
				Auth:               config.AuthNone,
				Status:             config.StatusUnknown,
				Mode:               attestMode,
				Measurements:       measurements,
				DiscoveryURL:       discoveryURL,
				ServerName:         serverName,
				WorkloadName:       workload,
				AllowlistPath:      allowlistStored,
				ImageManifestPath:  manifestStored,
				ExpectedRTMR3:      rtmr3Stored,
				MinTCB:             tcbFloor,
				TDXTCBStatus:       tdxTCBStatus,
				RouteDigests:       routeDigests,
				RouteOperatorKeys:  routeOperatorKeys,
				RouteFloor:         routesFloor,
				OperatorPubkeyPath: operatorPkeyStored,
				RTMRs:              rtmrs,
				InitDataDigest:     initData,
				SandboxID:          sandboxID,
				PinnedPolicies:     pinPoliciesStored,
				TrustOperator:      trustOperator,
				TrustOperatorKeys:  trustOperatorKeys,
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
	f.StringVar(&imageManifest, "image-manifest", "", "build-artifact manifest of the expected TDX guest image (mrtd, rtmr1, rtmr2, each 96 lowercase hex chars, nested under tdx as the confos build writes them or at the top level; published with the image build); all three registers are pinned exactly against this one manifest, so the guest kernel and rootfs are verified rather than only the firmware. Replaces --measurements rather than adding to it. TDX evidence only — with SNP evidence this is a policy error")
	f.StringVar(&expectedRTMR3, "expected-rtmr3", "", "expected TDX RTMR[3] as 96 lowercase hex chars: the bare operator-key seed, the register before the node measures any policy. A node that measures its allowlist policies is accepted when the policy list in its bundle replays from this seed to the quoted register. This is a deployment property, NOT a cluster identity, and cannot replace an image pin, so it requires --image-manifest. TDX evidence only — with SNP evidence this is a policy error")
	f.StringVar(&minTCB, "min-tcb", "", "minimum SNP TCB floor as four comma-separated components <bootloader,tee,snp,microcode> (each 0-255), enforced component-wise on the verified evidence. SNP evidence only — with TDX evidence this is a policy error")
	f.StringSliceVar(&tdxTCBStatus, "tdx-tcb-status", nil, "Intel TCB statuses accepted for TDX evidence, comma-separated: UpToDate, SWHardeningNeeded, ConfigurationNeeded, ConfigurationAndSWHardeningNeeded, OutOfDate, OutOfDateConfigurationNeeded. When set, every attestation fetches TCB info, QE identity and PCK CRLs from Intel PCS, refuses a revoked PCK chain, and requires the platform, TDX module and QE TCB statuses to be in this list. When unset, TDX evidence is verified offline (quote signature and PCK chain only). TDX evidence only — with SNP evidence this is a policy error")
	f.StringSliceVar(&routeDigests, "route-digest", nil, "accepted route digests (SHA-256 of the route manifest, 64 lowercase hex chars), comma-separated or repeated; the router must attest one of them. Pass the old and the new digest while routes change. Mutually exclusive with --route-operator-key. Requires --mode attest-lb. With neither, any attested digest is accepted and reported as unverified")
	f.StringArrayVar(&routeKeyFiles, "route-operator-key", nil, "PEM file of ECDSA operator public keys (P-256, P-384 or P-521), repeatable. With each attestation, fetch the router's published signed route manifest (/.well-known/c8s/routes), verify it under one of these keys, and require its digest to equal the attested one and its revision not to roll back. The router must enable route publication, and the manifest must route the <remote-url> host, so use a DNS name, not an IP. Mutually exclusive with --route-digest. Requires --mode attest-lb")
	f.StringVar(&routesFloor, "routes-floor", "", "with --route-operator-key: <revision>:<route digest hex> of the last signed route manifest accepted; each tunnel starts its rollback floor there, so a published manifest with a lower revision, or the same revision and another digest, fails")
	f.StringVar(&operatorPkey, "operator-pkey", "", "path to the operator PUBLIC key PEM (the exact file bytes the guest initrd hashed); pins RTMR[3] to its seed, SHA-384(0x00*48 || SHA-384(file bytes)), so the register need not be computed by hand. Mutually exclusive with --expected-rtmr3 and --rtmr 3=; requires --image-manifest. TDX evidence only")
	f.StringSliceVar(&rtmrs, "rtmr", nil, "TDX runtime register pins as <index>=<96 lowercase hex>, index 1, 2 or 3 (repeatable / comma-separated). RTMR[1] and RTMR[2] are the guest kernel and rootfs, so they exclude --image-manifest; pinning both beside --measurements counts as an image pin. RTMR[3] is another spelling of --expected-rtmr3 and requires --image-manifest. TDX evidence only")
	f.StringVar(&initData, "init-data", "", "expected init-data digest: SHA-256 hex of the init-data document; the evidence must commit exactly this digest (SNP HOST_DATA, TDX MR_CONFIG_ID, PCR[8] on Azure)")
	f.StringVar(&sandboxID, "sandbox-id", "", "CRI pod sandbox ID the committed mesh leaf must carry (OID 1.3.6.1.4.1.66378.1.4); CA-vouched, like --workload")
	f.StringSliceVar(&pinPolicies, "pin-policy", nil, "accepted allowlist policies (repeatable / comma-separated), each a sha256:<hex> digest or the path of an allowlist document hashed exactly as read (the bytes GET /allowlist serves): every policy in the node's replayed history, and the one the mesh leaf was issued under, must be one of these. Requires an RTMR[3] seed (--operator-pkey or --expected-rtmr3); excludes --trust-operator")
	f.BoolVar(&trustOperator, "trust-operator", false, "accept every policy in the node's replayed history, and the one the mesh leaf was issued under, only when CDS stores its document with a write token signed under --trust-operator-key: each one is fetched from /allowlist/objects/sha256/<hex>, re-hashed, and its token verified. Requires an RTMR[3] seed and --trust-operator-key; excludes --pin-policy")
	f.StringArrayVar(&trustKeyFiles, "trust-operator-key", nil, "PEM file of ECDSA operator public keys --trust-operator accepts signatures from (repeatable). Requires --trust-operator; --route-operator-key does not feed it")
	return cmd
}

// validateOperatorPkeyFlag checks --operator-pkey holds one P-256 PEM public
// key and returns the absolute path to store.
func validateOperatorPkeyFlag(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("reading --operator-pkey: %w", err)
	}
	if _, err := runtimemeasure.ParsePublicKeyPEM(raw); err != nil {
		return "", fmt.Errorf("--operator-pkey %s: %w", path, err)
	}
	return filepath.Abs(path)
}

// validatePinPolicyFlags resolves each --pin-policy entry once to catch a bad
// digest or document, and returns the entries to store: digests as given,
// files as absolute paths.
func validatePinPolicyFlags(entries []string) ([]string, error) {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if _, err := verifier.PinnedPolicyDigest(e); err != nil {
			return nil, fmt.Errorf("--pin-policy: %w", err)
		}
		if strings.HasPrefix(e, "sha256:") {
			out = append(out, e)
			continue
		}
		abs, err := filepath.Abs(e)
		if err != nil {
			return nil, fmt.Errorf("resolving --pin-policy path: %w", err)
		}
		out = append(out, abs)
	}
	return out, nil
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
