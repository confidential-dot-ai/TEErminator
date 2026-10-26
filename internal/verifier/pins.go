package verifier

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/confidential-dot-ai/TEErminator/internal/config"
	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
)

// platformPins are the resolved platform-complete measurement pins of one
// remote: the TDX image tuple (all three of MRTD, RTMR[1] and RTMR[2] compare
// exactly against the verified claims), RTMR[1]/[2] pinned by hand instead,
// the optional RTMR[3] seed (which only ever rides on top of an image tuple —
// see ValidatePinCombination), the init-data binding, the SNP TCB floor, and
// the accepted TDX TCB statuses. Any pin set against evidence from a platform
// it cannot apply to is a hard error.
type platformPins struct {
	image *ImagePins
	// rtmrs holds the by-hand RTMR[1] and RTMR[2] pins, keyed by index.
	rtmrs map[int][RegisterSize]byte
	rtmr3 *[RegisterSize]byte
	// initData is the expected init-data binding (SHA-256), nil when unpinned.
	initData []byte
	minTCB   *teetypes.SnpTcb
	// tdxTCBStatuses, when set, has the verifier fetch Intel collateral and
	// accept only these TCB statuses.
	tdxTCBStatuses []teetypes.TdxTcbStatus
}

// imagePinned reports whether the pins cover the whole TDX guest image:
// the manifest tuple, or RTMR[1] and RTMR[2] by hand beside the
// launch-digest allowlist.
func (p platformPins) imagePinned() bool {
	if p.image != nil {
		return true
	}
	_, kernel := p.rtmrs[1]
	_, rootfs := p.rtmrs[2]
	return kernel && rootfs
}

// ValidatePinCombination enforces the rules that relate a remote's pins to
// each other. They hold independently of any evidence or file, so both the
// `remote add` flags and the stored config go through this one
// implementation — a hand-edited config file must not reach a state the CLI
// refuses to write. c8s applies the same rules to `c8s verify`.
//
//   - An image manifest pins the launch digest exactly against its own MRTD,
//     and RTMR[1]/[2] with it, so neither a launch-digest allowlist nor a
//     by-hand RTMR[1]/[2] pin may sit beside it.
//   - Without a manifest, every allowlist entry is a SHA-384 launch digest,
//     and an attest-lb remote needs at least one.
//   - RTMR[3] records events extended into a guest whose image the untrusted
//     host selects, so its seed — expected_rtmr3, operator_pubkey_path or
//     rtmrs 3= — is named once and requires an image manifest.
//   - The policy history is judged by pinned_policies or trust_operator, not
//     both, and either needs the seed the history replays from.
func ValidatePinCombination(r config.Remote) error {
	if r.ImageManifestPath != "" && len(r.Measurements) > 0 {
		return errors.New("--measurements and --image-manifest are mutually exclusive: the manifest pins MRTD, RTMR[1] and RTMR[2] exactly against this one build, so a separate launch-digest allowlist could only admit an image it does not describe")
	}
	if r.ImageManifestPath == "" {
		if r.Mode == config.AttestEndpoint && len(r.Measurements) == 0 {
			return errors.New("--measurements or --image-manifest is required in mode attest-lb: an empty measurement policy pins nothing about what the front door runs")
		}
		if _, err := ValidateMeasurements(r.Measurements); err != nil {
			return err
		}
	}
	manual, err := refvalues.ParseRegisterPins(r.RTMRs)
	if err != nil {
		return fmt.Errorf("rtmrs: %w", err)
	}
	if (manual[1] != nil || manual[2] != nil) && r.ImageManifestPath != "" {
		return errors.New("--rtmr 1= and 2= cannot be combined with --image-manifest: the manifest already pins RTMR[1] and RTMR[2] together with the MRTD from the same build")
	}
	var seeds []string
	if r.ExpectedRTMR3 != "" {
		seeds = append(seeds, "--expected-rtmr3")
	}
	if r.OperatorPubkeyPath != "" {
		seeds = append(seeds, "--operator-pkey")
	}
	if manual[3] != nil {
		seeds = append(seeds, "--rtmr 3=")
	}
	if len(seeds) > 1 {
		return fmt.Errorf("%s all pin RTMR[3]: name the register once", strings.Join(seeds, " and "))
	}
	if len(seeds) == 1 && r.ImageManifestPath == "" {
		return fmt.Errorf("%s requires --image-manifest: RTMR[3] records events extended into a guest whose image the untrusted host selects, so pinning it without pinning the image proves nothing about what is running", seeds[0])
	}
	if len(r.PinnedPolicies) > 0 && r.TrustOperator {
		return errors.New("--pin-policy and --trust-operator are mutually exclusive: accept what the operator signed, or only what you pinned")
	}
	if len(r.TrustOperatorKeys) > 0 && !r.TrustOperator {
		return errors.New("--trust-operator-key requires --trust-operator")
	}
	if r.TrustOperator && len(r.TrustOperatorKeys) == 0 {
		return errors.New("--trust-operator requires --trust-operator-key: the operator public keys whose signatures it accepts")
	}
	if (len(r.PinnedPolicies) > 0 || r.TrustOperator) && len(seeds) == 0 {
		return errors.New("--pin-policy and --trust-operator require an RTMR[3] seed (--operator-pkey, --expected-rtmr3 or --rtmr 3=): the node's policy history counts only as far as it replays against RTMR[3] from that seed")
	}
	if r.RouteFloor != "" {
		if len(r.RouteOperatorKeys) == 0 {
			return errors.New("--routes-floor requires --route-operator-key: only a signed manifest carries a revision")
		}
		if _, _, err := ParseRouteFloor(r.RouteFloor); err != nil {
			return err
		}
	}
	if r.InitDataDigest != "" {
		if _, err := parseInitDataDigest(r.InitDataDigest); err != nil {
			return err
		}
	}
	if r.SandboxID != "" && !sandboxIDPattern.MatchString(r.SandboxID) {
		return fmt.Errorf("--sandbox-id %q must match %s", r.SandboxID, sandboxIDPattern)
	}
	return nil
}

// sandboxIDPattern is c8s's sandbox ID grammar (pkg/armtls ValidateSandboxID).
var sandboxIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// ParseRouteFloor parses a "<revision>:<64 lowercase hex>" route floor.
func ParseRouteFloor(s string) (uint64, [RouteDigestSize]byte, error) {
	rev, digest, ok := strings.Cut(s, ":")
	if !ok {
		return 0, [RouteDigestSize]byte{}, fmt.Errorf("--routes-floor %q: want <revision>:<route digest hex>", s)
	}
	n, err := strconv.ParseUint(rev, 10, 64)
	if err != nil {
		return 0, [RouteDigestSize]byte{}, fmt.Errorf("--routes-floor %q: revision: %w", s, err)
	}
	d, err := parseRouteDigest(digest)
	if err != nil {
		return 0, [RouteDigestSize]byte{}, fmt.Errorf("--routes-floor %q: %w", s, err)
	}
	return n, d, nil
}

// parseInitDataDigest parses the init_data_digest pin: SHA-256 as hex.
func parseInitDataDigest(s string) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != sha256.Size {
		return nil, fmt.Errorf("--init-data %q is not %d hex chars (SHA-256 of the init-data document)", s, 2*sha256.Size)
	}
	return b, nil
}

// operatorSeed reads the operator public-key PEM and derives the RTMR[3]
// seed from its exact bytes, as the guest initrd does.
func operatorSeed(path string) ([RegisterSize]byte, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return [RegisterSize]byte{}, fmt.Errorf("read operator_pubkey_path: %w", err)
	}
	if _, err := runtimemeasure.ParsePublicKeyPEM(pemBytes); err != nil {
		return [RegisterSize]byte{}, fmt.Errorf("operator_pubkey_path %s: %w", path, err)
	}
	return runtimemeasure.Seed(pemBytes), nil
}

// loadPlatformPins resolves a remote's platform pins; every failure is a
// configuration error.
func loadPlatformPins(r config.Remote) (platformPins, error) {
	var pins platformPins
	if err := ValidatePinCombination(r); err != nil {
		return platformPins{}, fmt.Errorf("configuration error: %w", err)
	}
	if r.ImageManifestPath != "" {
		image, err := LoadImageManifest(r.ImageManifestPath)
		if err != nil {
			return platformPins{}, err
		}
		pins.image = &image
	}
	manual, _ := refvalues.ParseRegisterPins(r.RTMRs) // ValidatePinCombination parsed it
	for idx, v := range manual {
		reg := [RegisterSize]byte(v)
		if idx == 3 {
			pins.rtmr3 = &reg
			continue
		}
		if pins.rtmrs == nil {
			pins.rtmrs = make(map[int][RegisterSize]byte)
		}
		pins.rtmrs[idx] = reg
	}
	switch {
	case r.ExpectedRTMR3 != "":
		reg, err := ParseRegisterHex(r.ExpectedRTMR3)
		if err != nil {
			return platformPins{}, fmt.Errorf("expected_rtmr3 %w", err)
		}
		pins.rtmr3 = &reg
	case r.OperatorPubkeyPath != "":
		seed, err := operatorSeed(r.OperatorPubkeyPath)
		if err != nil {
			return platformPins{}, fmt.Errorf("configuration error: %w", err)
		}
		pins.rtmr3 = &seed
	}
	if r.InitDataDigest != "" {
		pins.initData, _ = parseInitDataDigest(r.InitDataDigest) // validated above
	}
	// An all-zero floor is no floor: every SNP TCB component is >= 0, so it
	// gates nothing, while a non-nil floor would reject all TDX evidence as a
	// cross-platform pin. The CLI already drops it (parseMinTCBFlag); this
	// repeats the rule for a hand-edited config file.
	if r.MinTCB != nil && *r.MinTCB != (config.TCBFloor{}) {
		pins.minTCB = &teetypes.SnpTcb{
			Bootloader: r.MinTCB.Bootloader,
			Tee:        r.MinTCB.TEE,
			Snp:        r.MinTCB.SNP,
			Microcode:  r.MinTCB.Microcode,
		}
	}
	if r.StaticAllowlist || r.InitData != "" {
		return platformPins{}, fmt.Errorf("configuration error: static_allowlist and init_data are no longer supported (c8s does not seal the allowlist into its mesh CA); remove the remote and add it again without them, and pin the init-data digest with init_data_digest instead")
	}
	statuses, err := ParseTDXTCBStatuses(r.TDXTCBStatus)
	if err != nil {
		return platformPins{}, fmt.Errorf("configuration error: %w", err)
	}
	pins.tdxTCBStatuses = statuses
	return pins, nil
}
