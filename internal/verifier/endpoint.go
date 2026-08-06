package verifier

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/confidential-dot-ai/TEErminator/internal/config"
	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/attestation/teeverify"
)

// ErrNotImplemented is returned for attestation modes that are defined but not
// yet wired up; the proxy fails closed on them instead of forwarding.
var ErrNotImplemented = errors.New("attestation flow not implemented")

// Endpoint attestation (config.AttestEndpoint, "attest-lb") is the ordinary-TLS
// native-client protocol: after each new TLS handshake and before releasing
// application bytes, the proxy calls the LB's attest-lb endpoint with a fresh
// nonce. The returned hardware evidence binds that nonce, the exact serving
// leaf DER observed on this very connection, and the LB's mesh leaf and issuing
// mesh CA into report_data, and the mesh leaf key proves possession over the
// same transcript. The mesh CA is thereby DERIVED from the hardware-committed
// response — no out-of-band CA file is required — and both the mesh leaf and
// the serving leaf must chain to it, so the serving key is TEE-held
// (public_tls.mode=cds; a WebPKI-secret front door refuses the endpoint).

// wellKnownAttestLB is the LB's ordinary-TLS attestation endpoint. It lives at
// the LB origin, independent of the remote's forwarding path.
const wellKnownAttestLB = "/.well-known/c8s/attest-lb"

// attestLBVersion is the binding identifier the attest-lb endpoint must return;
// any other response shape (including the retired "c8s-verify/v1" and the
// encrypted-session "c8s/attest-pq/v1") is rejected even if its evidence is
// otherwise valid — there is no endpoint negotiation or fallback.
const attestLBVersion = "c8s/attest-lb/v1"

// proofAlgorithmECDSASHA384 is the only identity-proof algorithm accepted.
const proofAlgorithmECDSASHA384 = "ecdsa-sha384"

// notBeforeSkew is the single documented clock-skew allowance: a
// certificate whose NotBefore is at most this far in the future is accepted, so
// a freshly rotated mesh CA/leaf remains usable by a client whose clock trails
// the cluster's. NotAfter has no allowance.
const notBeforeSkew = 5 * time.Minute

// Trust modes a verdict can carry: deployment-class means the
// mesh CA was derived from the hardware-committed response; specific-cluster
// means it additionally byte-equals an operator-pinned CA (`certs add`).
const (
	TrustDeploymentClass = "deployment-class"
	TrustSpecificCluster = "specific-cluster"
)

// ProfileCAVouched is the workload-stamp guarantee label this client reports.
// TEErminator cannot see the deployment's enforcement profile (preventive vs
// observed), so it always reports the weaker generic label.
const ProfileCAVouched = "ca-vouched"

// SessionVerdict is the outcome of a session attestation. LeafSHA256 is the
// SHA-256 of the exact serving-leaf DER the evidence was bound to; the
// transport pins forwarded requests to a connection presenting that same
// certificate (not merely the same key) and re-attests otherwise.
type SessionVerdict struct {
	Measurement string
	// Platform is the TEE platform the verified evidence came from (the
	// attestation-go verifier's post-verification platform tag).
	Platform string
	// WorkloadName / AllowlistVersion are set only when a workload policy was
	// requested and verified against the committed mesh leaf's stamp.
	WorkloadName string
	// AllowlistVersion is the store's version counter as STAMPED on the mesh
	// leaf. It is CA-vouched (the stamp sits in the chain-verified leaf) but
	// UNVERIFIED against any served allowlist: `--allowlist` checks the stamped
	// digest against the pinned file's bytes, and a canonical-allowlist
	// document carries no version field to compare this counter with. Report it
	// as what the deployment claims, never as a checked fact.
	AllowlistVersion string
	// TrustMode is TrustDeploymentClass or TrustSpecificCluster.
	TrustMode string
	// Profile is always ProfileCAVouched (see the constant).
	Profile    string
	LeafSHA256 [32]byte
	// LeafNotAfter is the serving leaf's expiry. A verdict says nothing past
	// it — the certificate it is scoped to has stopped being valid — so the
	// verdict cache bounds reuse at min(ReattestInterval, LeafNotAfter) rather
	// than at the caller-settable interval alone.
	LeafNotAfter time.Time
	// RTMRsPinned lists the TDX runtime measurement registers this verdict
	// enforced, as "<index>:<hex>". On TDX the launch-digest allowlist covers
	// only MRTD (the TDVF firmware): without RTMR[1]/[2] the guest kernel and
	// rootfs are unverified, and without RTMR[3] the runtime chain is. A
	// verdict that proves neither must not look like one that proves both.
	RTMRsPinned []string
	// TCBFloor names the SNP TCB floor this verdict enforced (empty when no
	// --min-tcb pin is set).
	TCBFloor string
	// Warning is a policy gap in an otherwise passing verdict — currently the
	// MRTD-only note for specific-cluster TDX remotes without an image pin.
	Warning string
}

// identityProof mirrors the attest-lb bundle's proof of possession by the mesh
// leaf key. All hashes and the signature are base64url without padding.
type identityProof struct {
	Algorithm    string `json:"algorithm"`
	LeafSHA256   string `json:"leaf_sha256"`
	MeshCASHA256 string `json:"mesh_ca_sha256"`
	Signature    string `json:"signature"`
}

// attestationBundle mirrors the relevant fields of the attest-lb response.
type attestationBundle struct {
	Version       string          `json:"version"`
	Platform      string          `json:"platform"`
	Nonce         string          `json:"nonce"`
	Evidence      json.RawMessage `json:"evidence"`
	CDSCertPEM    string          `json:"cds_cert_pem"`
	IdentityProof identityProof   `json:"identity_proof"`
}

// EndpointAttester implements the attest-lb mode. baseURL is the LB origin
// (scheme://host); client must be the transport whose observed TLS state the
// proxy forwards over, so the serving leaf bound into the evidence is the one
// application traffic rides. pinnedCAs are the operator's `certs add`
// certificates: they are OPTIONAL hardening — the mesh CA is derived from the
// hardware-committed response either way — and only upgrade the verdict to
// specific-cluster when one of them byte-equals the committed CA.
type EndpointAttester struct {
	client    *http.Client
	attestURL *url.URL
	remote    config.Remote
	pinnedCAs []*x509.Certificate
}

// NewEndpointAttester builds an endpoint attester.
func NewEndpointAttester(baseURL string, client *http.Client, remote config.Remote, pinnedCAs []*x509.Certificate) (*EndpointAttester, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("attest-lb: parse base URL: %w", err)
	}
	u.Path = wellKnownAttestLB
	u.RawQuery = ""
	// The leaf the attester observes must be the leaf traffic rides, so the
	// fetch is not allowed to move: an on-path attacker who terminates it with
	// any certificate could otherwise redirect to the genuine LB, and the
	// client would attest — and pin — a host it was never configured to reach.
	// A redirect is surfaced as its own non-200 response instead. The client is
	// copied rather than mutated so a caller's shared client keeps its own
	// policy.
	c := *client
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &EndpointAttester{
		client:    &c,
		attestURL: u,
		remote:    remote,
		pinnedCAs: pinnedCAs,
	}, nil
}

// Attest runs the per-handshake attest-lb verification and returns the verdict,
// or an error (fail closed). The checks run strictly in this order: serving
// leaf capture, bundle shape (version, nonce echo), served chain parsing and
// committed-CA selection, identity-proof field equality, hardware evidence over
// the recomputed transcript, proof of possession, mesh-leaf chain, serving-leaf
// chain, measurement policy, workload policy.
func (e *EndpointAttester) Attest(ctx context.Context) (*SessionVerdict, error) {
	// Platform pins are resolved before any network round trip: a malformed
	// image manifest, RTMR[3] pin, or TCB floor is a configuration error. The
	// manifest is re-read per attestation so an updated file takes effect (the
	// verdict-cache key hashes its content, so a change also invalidates any
	// cached verdict).
	pins, err := loadPlatformPins(e.remote)
	if err != nil {
		return nil, fmt.Errorf("attest-lb: %w", err)
	}

	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("attest-lb: generate nonce: %w", err)
	}
	nonceB64 := base64.RawURLEncoding.EncodeToString(nonce)

	u := *e.attestURL
	q := u.Query()
	q.Set("nonce", nonceB64)
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("attest-lb: build request: %w", err)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("attest-lb: fetch attestation: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			slog.Error("error closing response Body", "error", err)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("attest-lb: attestation endpoint returned %d: %s", resp.StatusCode, body)
	}

	// (a) The exact leaf on this connection is what the evidence must bind and
	// what the proxy pins forwarded traffic to.
	servingLeaf, err := servingLeafFromTLS(resp.TLS)
	if err != nil {
		return nil, fmt.Errorf("attest-lb: %w", err)
	}

	// (b) Bundle shape: distinct binding identifier, exact nonce echo.
	var bundle attestationBundle
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&bundle); err != nil {
		return nil, fmt.Errorf("attest-lb: decode bundle: %w", err)
	}
	if bundle.Version != attestLBVersion {
		return nil, fmt.Errorf("attest-lb: response version %q does not match the required binding identifier %q (no cross-endpoint fallback)", bundle.Version, attestLBVersion)
	}
	if bundle.Nonce != nonceB64 {
		return nil, fmt.Errorf("attest-lb: nonce mismatch (LB echoed %q)", bundle.Nonce)
	}

	// (c) Served chain: first block is the mesh leaf; the committed CA is
	// selected among the remaining blocks by the proof's mesh_ca_sha256.
	meshLeaf, servedCAs, err := parseCDSCertPEM(bundle.CDSCertPEM)
	if err != nil {
		return nil, fmt.Errorf("attest-lb: %w", err)
	}
	committedCA, err := selectCommittedCA(servedCAs, bundle.IdentityProof.MeshCASHA256)
	if err != nil {
		return nil, fmt.Errorf("attest-lb: %w", err)
	}

	// (d) Identity-proof fields must name exactly the parsed certificates.
	if bundle.IdentityProof.Algorithm != proofAlgorithmECDSASHA384 {
		return nil, fmt.Errorf("attest-lb: unsupported identity-proof algorithm %q (want %q)", bundle.IdentityProof.Algorithm, proofAlgorithmECDSASHA384)
	}
	leafHash, err := base64.RawURLEncoding.DecodeString(bundle.IdentityProof.LeafSHA256)
	if err != nil {
		return nil, fmt.Errorf("attest-lb: decode identity_proof.leaf_sha256: %w", err)
	}
	meshLeafSum := sha256.Sum256(meshLeaf.Raw)
	if !bytes.Equal(leafHash, meshLeafSum[:]) {
		return nil, fmt.Errorf("attest-lb: identity_proof.leaf_sha256 does not match the served mesh leaf")
	}

	// (e) Recompute report_data from the CONNECTION's serving leaf, the parsed
	// mesh identity, and our nonce, and require the hardware evidence to bind
	// exactly it. A bundle relayed through any other serving leaf fails here
	// even when both leaves share an issuer.
	reportData := attestLBReportData(nonce, servingLeaf.Raw, meshLeaf.Raw, committedCA.Raw)
	res, err := verifyEvidence(bundle, reportData[:], pins.minTCB)
	if err != nil {
		return nil, err
	}
	measurement := res.Claims.LaunchDigest
	// The platform the policies dispatch on is the VERIFIED result's tag — the
	// verifier only returns it after the platform-specific signature chain
	// checked out — falling back to the bundle tag it dispatched on.
	platform := res.Platform
	if platform == "" {
		platform = teetypes.PlatformType(bundle.Platform)
	}

	// (f) Proof of possession: the mesh leaf key signs SHA-384(report_data).
	if err := verifyIdentityProof(meshLeaf, reportData[:], bundle.IdentityProof.Signature); err != nil {
		return nil, fmt.Errorf("attest-lb: %w", err)
	}

	// (g)+(h) Both the committed mesh identity and the serving leaf must chain
	// to the committed CA — the latter is what makes the serving key TEE-held.
	now := time.Now()
	if err := verifyDirectChain(meshLeaf, committedCA, now); err != nil {
		return nil, fmt.Errorf("attest-lb: mesh leaf: %w", err)
	}
	if err := verifyDirectChain(servingLeaf, committedCA, now); err != nil {
		return nil, fmt.Errorf("attest-lb: serving leaf: %w", err)
	}

	// (i) Measurement policy. Without an image manifest the launch-digest
	// allowlist is the whole of it, and an empty allowlist is a configuration
	// error, never a permissive default: nothing else in this flow pins WHAT
	// software the attested front door runs. With a manifest the allowlist is
	// not consulted at all — the launch digest is compared byte-exactly against
	// the manifest's MRTD in pins.enforce, alongside the RTMR[1]/[2] registers
	// of the same build tuple.
	if pins.image == nil {
		if err := checkMeasurement(measurement, e.remote.Measurements); err != nil {
			return nil, err
		}
	}

	v := &SessionVerdict{
		Measurement:  measurement,
		Platform:     string(platform),
		TrustMode:    TrustDeploymentClass,
		Profile:      ProfileCAVouched,
		LeafSHA256:   sha256.Sum256(servingLeaf.Raw),
		LeafNotAfter: servingLeaf.NotAfter,
	}

	// (i') Platform-complete pins: TDX runtime registers and the SNP TCB floor
	// are enforced on the verified claims, fail closed — including any pin set
	// against evidence from a platform it cannot apply to.
	if err := pins.enforce(platform, res, v); err != nil {
		return nil, fmt.Errorf("attest-lb: %w", err)
	}

	// (j) Workload policy, only when pinned, only after everything above.
	if e.remote.WorkloadName != "" || e.remote.AllowlistPath != "" {
		stamp, err := e.checkWorkloadPolicy(meshLeaf)
		if err != nil {
			return nil, fmt.Errorf("attest-lb: %w", err)
		}
		v.WorkloadName = stamp.Name
		v.AllowlistVersion = stamp.AllowlistVersion
	}

	// An operator CA pin upgrades the derived-CA verdict to specific-cluster
	// when the committed CA byte-equals it.
	for _, pinned := range e.pinnedCAs {
		if bytes.Equal(pinned.Raw, committedCA.Raw) {
			v.TrustMode = TrustSpecificCluster
			break
		}
	}

	// TDX completeness rule: MRTD (the only register the launch-digest
	// allowlist covers on TDX) measures just the TDVF firmware, so without an
	// image pin the guest kernel (RTMR[1]) and rootfs (RTMR[2]) are unmeasured.
	// A deployment-class verdict rests on that measurement policy alone and is
	// refused; a specific-cluster verdict additionally rests on the operator's
	// mesh-CA pin, so it passes with a prominent warning instead. SNP needs no
	// equivalent: its launch digest (with kernel-hashes) already covers
	// firmware, kernel, initrd, and cmdline. Keying on pins.image says exactly
	// "the full tuple was enforced": enforce above already failed the verdict
	// closed unless the launch digest byte-equalled this manifest's MRTD, so a
	// run that reaches here with a manifest matched all three registers.
	if isTDXPlatform(platform) && pins.image == nil {
		if v.TrustMode == TrustDeploymentClass {
			return nil, fmt.Errorf("attest-lb: configuration error: deployment-class trust over TDX evidence needs an image pin — the measurement allowlist covers only MRTD, which measures the TDVF firmware, so the guest kernel and rootfs are unmeasured; pin the full MRTD+RTMR[1]+RTMR[2] tuple with `remote add --image-manifest`")
		}
		v.Warning = "TDX policy covers MRTD only — the guest kernel (RTMR[1]) and rootfs (RTMR[2]) are UNMEASURED by this policy; pin the full image tuple with `remote add --image-manifest`"
	}
	return v, nil
}

// isTDXPlatform reports whether the verified evidence came from an Intel TDX
// guest, whose launch digest (MRTD) covers only the TDVF firmware and whose
// runtime registers carry the rest of the image. The dstack platform, while
// TDX-based, is deliberately excluded: its claim layout is not covered by
// this policy, so TDX pins against it fail closed as cross-platform.
func isTDXPlatform(p teetypes.PlatformType) bool {
	switch p {
	case teetypes.PlatformTDX, teetypes.PlatformAzTDX, teetypes.PlatformGcpTDX:
		return true
	}
	return false
}

// isSNPPlatform reports whether the verified evidence came from an AMD SEV-SNP
// guest (whose report carries the four-component TCB the --min-tcb floor is
// defined over).
func isSNPPlatform(p teetypes.PlatformType) bool {
	switch p {
	case teetypes.PlatformSNP, teetypes.PlatformAzSNP, teetypes.PlatformGcpSNP:
		return true
	}
	return false
}

// platformPins are the resolved platform-complete measurement pins of one
// remote: the TDX image tuple (all three of MRTD, RTMR[1] and RTMR[2] compare
// exactly against the verified claims), the optional TDX runtime-register pin
// (RTMR[3]), and the SNP TCB floor. Any pin set against evidence from a
// platform it cannot apply to is a hard error.
type platformPins struct {
	image  *ImagePins
	rtmr3  *[RegisterSize]byte
	minTCB *teetypes.SnpTcb
}

// loadPlatformPins resolves a remote's platform pins; every failure is a
// configuration error.
func loadPlatformPins(r config.Remote) (platformPins, error) {
	var pins platformPins
	if r.ImageManifestPath != "" {
		// An image manifest pins the launch digest exactly, so a second,
		// looser source of accepted launch digests is not a widening of the
		// policy but a hole in it: an allowlist entry that is not the
		// manifest's MRTD would admit a guest the manifest does not describe
		// while its RTMR[1]/[2] stayed pinned to the manifest. Refuse the
		// combination rather than silently letting one of the two win.
		if len(r.Measurements) > 0 {
			return platformPins{}, fmt.Errorf("configuration error: --measurements and --image-manifest are mutually exclusive: the manifest pins the launch digest exactly against its own MRTD, so a separate allowlist could only admit an image the manifest does not describe")
		}
		image, err := LoadImageManifest(r.ImageManifestPath)
		if err != nil {
			return platformPins{}, err
		}
		pins.image = &image
	}
	if r.ExpectedRTMR3 != "" {
		reg, err := ParseRegisterHex(r.ExpectedRTMR3)
		if err != nil {
			return platformPins{}, fmt.Errorf("expected_rtmr3 %w", err)
		}
		pins.rtmr3 = &reg
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
	return pins, nil
}

// enforce applies the platform pins to the verified claims, recording what was
// enforced in the verdict. It fails closed on any pin whose platform does not
// match the evidence, on absent or malformed claims, and on any mismatch —
// never an ignored option.
func (p platformPins) enforce(platform teetypes.PlatformType, res *teetypes.VerificationResult, v *SessionVerdict) error {
	if (p.image != nil || p.rtmr3 != nil) && !isTDXPlatform(platform) {
		return fmt.Errorf("a TDX pin (image manifest / expected RTMR[3]) is set but the evidence platform is %q: runtime measurement registers exist only on TDX, so this policy cannot be enforced against %q evidence", platform, platform)
	}
	if p.minTCB != nil && !isSNPPlatform(platform) {
		return fmt.Errorf("an SNP TCB floor (min_tcb) is set but the evidence platform is %q: the four-component TCB exists only on SEV-SNP, so this policy cannot be enforced against %q evidence", platform, platform)
	}

	if p.image != nil {
		// On TDX the launch digest IS the MRTD, and it comes out of the same
		// build as RTMR[1]/[2]. Comparing it byte-exactly — rather than
		// admitting it into an allowlist that may carry other digests — is what
		// makes the manifest ONE image pin instead of three independent ones:
		// otherwise a guest whose firmware differs from the manifest verifies
		// while the kernel and rootfs registers stay pinned to the manifest.
		mb, err := hex.DecodeString(strings.ToLower(strings.TrimSpace(res.Claims.LaunchDigest)))
		if err != nil || len(mb) == 0 {
			return fmt.Errorf("cannot enforce the image pin: launch_digest is missing or malformed (%q)", res.Claims.LaunchDigest)
		}
		if !bytes.Equal(mb, p.image.MRTD[:]) {
			return fmt.Errorf("MRTD mismatch: launch measurement %s does not match the image manifest MRTD %s (a different guest firmware/image booted)",
				hex.EncodeToString(mb), hex.EncodeToString(p.image.MRTD[:]))
		}
	}

	check := func(idx int, meaning string, want []byte) error {
		key := fmt.Sprintf("rtmr_%d", idx)
		got, _ := res.Claims.PlatformData[key].(string)
		got = strings.ToLower(strings.TrimSpace(got))
		if got == "" {
			return fmt.Errorf("cannot enforce the RTMR[%d] pin: the verified claims carry no %s", idx, key)
		}
		gb, err := hex.DecodeString(got)
		if err != nil || len(gb) != RegisterSize {
			return fmt.Errorf("cannot enforce the RTMR[%d] pin: %s claim is malformed (%q)", idx, key, got)
		}
		if !bytes.Equal(gb, want) {
			return fmt.Errorf("RTMR[%d] (%s) is %s, expected %s", idx, meaning, got, hex.EncodeToString(want))
		}
		v.RTMRsPinned = append(v.RTMRsPinned, fmt.Sprintf("%d:%s", idx, hex.EncodeToString(want)))
		return nil
	}
	if p.image != nil {
		if err := check(1, "guest kernel", p.image.RTMR1[:]); err != nil {
			return err
		}
		if err := check(2, "guest rootfs", p.image.RTMR2[:]); err != nil {
			return err
		}
	}
	if p.rtmr3 != nil {
		if err := check(3, "runtime operator-key/workload chain", p.rtmr3[:]); err != nil {
			return err
		}
	}
	if p.minTCB != nil {
		// The floor was already handed to attestation-go as
		// VerifyParams.MinTCB, so the verifier engine enforced it against both
		// the reported and current TCB; this recheck against the verified
		// claims keeps the policy fail-closed independently of the evidence
		// seam.
		if err := checkTCBFloor(res.Claims.TCB, p.minTCB); err != nil {
			return err
		}
		v.TCBFloor = fmt.Sprintf("bootloader=%d,tee=%d,snp=%d,microcode=%d",
			p.minTCB.Bootloader, p.minTCB.Tee, p.minTCB.Snp, p.minTCB.Microcode)
	}
	return nil
}

// checkTCBFloor compares the verified reported-TCB claims component-wise
// against the pinned floor, failing closed when a component claim is absent.
func checkTCBFloor(tcb teetypes.TcbInfo, floor *teetypes.SnpTcb) error {
	for _, c := range []struct {
		name string
		got  *uint8
		min  uint8
	}{
		{"bootloader", tcb.Bootloader, floor.Bootloader},
		{"tee", tcb.Tee, floor.Tee},
		{"snp", tcb.Snp, floor.Snp},
		{"microcode", tcb.Microcode, floor.Microcode},
	} {
		if c.got == nil {
			return fmt.Errorf("cannot enforce the TCB floor: the verified claims carry no %s TCB component", c.name)
		}
		if *c.got < c.min {
			return fmt.Errorf("TCB %s is %d, below the pinned minimum %d", c.name, *c.got, c.min)
		}
	}
	return nil
}

// attestLBReportData is the normative attest-lb transcript hash:
//
//	report_data = SHA-384( LP("c8s/attest-lb/v1") || LP(nonce) ||
//	    LP(SHA-256(serving_leaf_DER)) || LP(SHA-256(mesh_leaf_DER)) ||
//	    LP(SHA-256(mesh_CA_DER)) )
//
// where LP(x) = uint32-big-endian(len(x)) || x. The serving-leaf hash covers
// the FULL certificate DER, not the SPKI, so a substituted certificate with the
// same key still fails.
func attestLBReportData(nonce, servingLeafDER, meshLeafDER, meshCADER []byte) [48]byte {
	h := sha512.New384()
	lp := func(b []byte) {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(b)))
		h.Write(n[:])
		h.Write(b)
	}
	lp([]byte(attestLBVersion))
	lp(nonce)
	servingSum := sha256.Sum256(servingLeafDER)
	lp(servingSum[:])
	meshSum := sha256.Sum256(meshLeafDER)
	lp(meshSum[:])
	caSum := sha256.Sum256(meshCADER)
	lp(caSum[:])
	var out [48]byte
	h.Sum(out[:0])
	return out
}

// parseCDSCertPEM splits cds_cert_pem into the mesh leaf (first block) and the
// remaining served CA candidates.
func parseCDSCertPEM(pemChain string) (leaf *x509.Certificate, cas []*x509.Certificate, err error) {
	rest := []byte(pemChain)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, nil, fmt.Errorf("cds_cert_pem: unexpected %q PEM block", block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("cds_cert_pem: parse certificate: %w", err)
		}
		if leaf == nil {
			leaf = cert
		} else {
			cas = append(cas, cert)
		}
	}
	if leaf == nil {
		return nil, nil, fmt.Errorf("cds_cert_pem contains no certificate")
	}
	if len(cas) == 0 {
		return nil, nil, fmt.Errorf("cds_cert_pem contains no issuing CA after the mesh leaf")
	}
	return leaf, cas, nil
}

// selectCommittedCA picks the served CA whose DER SHA-256 equals the proof's
// commitment (base64url, no padding). The commitment — not position in the
// chain — is what selects the CA, so a served-but-uncommitted CA can never
// become a trust anchor.
func selectCommittedCA(cas []*x509.Certificate, meshCASHA256 string) (*x509.Certificate, error) {
	want, err := base64.RawURLEncoding.DecodeString(meshCASHA256)
	if err != nil {
		return nil, fmt.Errorf("decode identity_proof.mesh_ca_sha256: %w", err)
	}
	if len(want) != sha256.Size {
		return nil, fmt.Errorf("identity_proof.mesh_ca_sha256 must be %d bytes, got %d", sha256.Size, len(want))
	}
	for _, ca := range cas {
		sum := sha256.Sum256(ca.Raw)
		if bytes.Equal(sum[:], want) {
			return ca, nil
		}
	}
	return nil, fmt.Errorf("no served CA matches identity_proof.mesh_ca_sha256")
}

// verifyIdentityProof checks the mesh leaf key's proof of possession: an
// ECDSA-SHA384 ASN.1 signature over SHA-384(report_data).
func verifyIdentityProof(meshLeaf *x509.Certificate, reportData []byte, sigB64 string) error {
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("decode identity_proof.signature: %w", err)
	}
	pub, ok := meshLeaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("mesh leaf public key is %T, want ECDSA", meshLeaf.PublicKey)
	}
	digest := sha512.Sum384(reportData)
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		return fmt.Errorf("identity proof signature does not verify with the mesh leaf key")
	}
	return nil
}

// verifyDirectChain requires cert to be DIRECTLY issued by ca and both to be
// within their validity windows (NotBefore softened by the one documented
// notBeforeSkew; NotAfter strict). This is deliberately chosen over
// x509.Verify with a pool of one: the protocol commits exactly one CA, so a
// chain through any uncommitted intermediate must fail — CheckSignatureFrom
// makes that structural while still enforcing the CA's BasicConstraints and
// KeyUsageCertSign — and Verify cannot express the single NotBefore skew
// without also shifting its NotAfter check. Name and EKU checks are irrelevant
// here: identity is bound by the transcript's hash commitments, not by names.
func verifyDirectChain(cert, ca *x509.Certificate, now time.Time) error {
	if err := cert.CheckSignatureFrom(ca); err != nil {
		return fmt.Errorf("does not chain to the committed mesh CA: %w", err)
	}
	if err := checkValidity(cert, now); err != nil {
		return err
	}
	if err := checkValidity(ca, now); err != nil {
		return fmt.Errorf("committed mesh CA: %w", err)
	}
	return nil
}

// checkValidity enforces the certificate validity window with the documented
// NotBefore skew allowance.
func checkValidity(cert *x509.Certificate, now time.Time) error {
	if now.Add(notBeforeSkew).Before(cert.NotBefore) {
		return fmt.Errorf("certificate is not yet valid (NotBefore %s, allowance %s)", cert.NotBefore.Format(time.RFC3339), notBeforeSkew)
	}
	if now.After(cert.NotAfter) {
		return fmt.Errorf("certificate expired at %s", cert.NotAfter.Format(time.RFC3339))
	}
	return nil
}

// checkWorkloadPolicy reads the .1.5 stamp off the committed (chain-verified)
// mesh leaf and enforces the remote's workload pins, fail closed: with a pin
// set, an absent, malformed, duplicated, mismatched, or unresolvable stamp is
// an error.
func (e *EndpointAttester) checkWorkloadPolicy(meshLeaf *x509.Certificate) (*MatchedWorkload, error) {
	stamp, err := matchedWorkloadFromCert(meshLeaf)
	if err != nil {
		return nil, fmt.Errorf("workload policy: %w", err)
	}
	if stamp == nil {
		return nil, fmt.Errorf("workload policy: pin set but the mesh leaf carries no matched-workload stamp")
	}
	if e.remote.WorkloadName != "" && stamp.Name != e.remote.WorkloadName {
		return nil, fmt.Errorf("workload policy: mesh leaf is stamped for workload %q, pinned %q", stamp.Name, e.remote.WorkloadName)
	}
	if e.remote.AllowlistPath != "" {
		// Hash EXACTLY the file bytes as read — canonical bytes only, never a
		// reserialization.
		raw, err := os.ReadFile(e.remote.AllowlistPath)
		if err != nil {
			return nil, fmt.Errorf("workload policy: read pinned allowlist: %w", err)
		}
		digest := sha256.Sum256(raw)
		if !bytes.Equal(digest[:], stamp.AllowlistDigest) {
			return nil, fmt.Errorf("workload policy: stamped allowlist digest does not match the pinned allowlist file %s", e.remote.AllowlistPath)
		}
		doc, err := ParsePinnedAllowlist(raw)
		if err != nil {
			return nil, fmt.Errorf("workload policy: %w", err)
		}
		if _, ok := doc.Workloads[stamp.Name]; !ok {
			return nil, fmt.Errorf("workload policy: stamped workload %q does not resolve in the pinned allowlist", stamp.Name)
		}
	}
	return stamp, nil
}

// verifyEvidence is the evidence-verification seam: production points at
// verifyEndpointEvidence; ordered-flow tests substitute a stub so the full
// attest-lb sequence runs without live hardware evidence.
var verifyEvidence = verifyEndpointEvidence

// verifyEndpointEvidence verifies the hardware evidence through the shared
// attestation-go verifier (teeverify dispatches on the bundle's platform tag)
// and requires that the evidence binds expectedReportData — the attest-lb
// transcript hash — directly in the report_data for bare-metal platforms, or
// in the AK-signed vTPM quote for the Azure ones. minTCB, when set, is handed
// to the verifier engine as the SNP TCB floor (go-sev-guest validates it
// against the report's TCB fields). Debug-launched guests are rejected by the
// engine unconditionally: VerifyParams.AllowDebug defaults to false and is
// never set here. All evidence parsing and cryptographic verification lives
// in attestation-go; only the binding anchor and the policies are computed
// here.
func verifyEndpointEvidence(b attestationBundle, expectedReportData []byte, minTCB *teetypes.SnpTcb) (*teetypes.VerificationResult, error) {
	raw, err := json.Marshal(teetypes.AttestationEvidence{
		Platform: teetypes.PlatformType(b.Platform),
		Evidence: b.Evidence,
	})
	if err != nil {
		return nil, fmt.Errorf("attest-lb: re-encode evidence: %w", err)
	}
	res, err := teeverify.Verify(raw, teetypes.VerifyParams{
		ExpectedReportData: expectedReportData,
		MinTCB:             minTCB,
	})
	if err != nil {
		return nil, fmt.Errorf("attest-lb (%s): %w", b.Platform, err)
	}
	if err := checkVerificationResult(res, b.Platform); err != nil {
		return nil, err
	}
	return res, nil
}

// checkVerificationResult asserts the verifier's own verdict fields rather than
// inferring them from a nil error. Every attestation-go platform path happens to
// return an error today when the hardware signature or the report-data binding
// fails, but that is a property of the current implementations, not of the
// interface: reading the fields keeps the client fail-closed across a refactor
// that starts reporting a failure in the result instead of in err.
func checkVerificationResult(res *teetypes.VerificationResult, platform string) error {
	if res == nil {
		return fmt.Errorf("attest-lb (%s): verifier returned no result", platform)
	}
	if !res.SignatureValid {
		return fmt.Errorf("attest-lb (%s): hardware signature on the evidence did not verify", platform)
	}
	// We always supply ExpectedReportData, so a nil ReportDataMatch means the
	// verifier never evaluated the binding — the transcript would be unchecked.
	if res.ReportDataMatch == nil || !*res.ReportDataMatch {
		return fmt.Errorf("attest-lb (%s): evidence does not bind the attest-lb transcript (report_data mismatch)", platform)
	}
	return nil
}

// servingLeafFromTLS returns the exact peer leaf certificate of the connection.
func servingLeafFromTLS(state *tls.ConnectionState) (*x509.Certificate, error) {
	if state == nil || len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no TLS peer certificate to bind the session to")
	}
	return state.PeerCertificates[0], nil
}

// checkMeasurement enforces the remote's launch-digest allowlist. In attest-lb
// mode an all-empty measurement policy is a configuration error, not a
// permissive default: nothing else in this flow pins WHAT
// software the attested front door runs. Both sides are compared as decoded
// bytes, so an entry that is not a launch digest at all — `--measurements ""`
// yields one such — is a configuration error rather than a value that could
// match a platform whose LaunchDigest claim came back empty.
func checkMeasurement(measurement string, allowed []string) error {
	if len(allowed) == 0 {
		return fmt.Errorf("attest-lb: empty measurement policy is a configuration error: pin the accepted launch digests with `remote add --measurements`")
	}
	want := make([][]byte, 0, len(allowed))
	for _, a := range allowed {
		b, err := hex.DecodeString(strings.ToLower(strings.TrimSpace(a)))
		if err != nil || len(b) == 0 {
			return fmt.Errorf("attest-lb: configuration error: --measurements entry %q is not a non-empty hex launch digest", a)
		}
		want = append(want, b)
	}
	m, err := hex.DecodeString(strings.ToLower(strings.TrimSpace(measurement)))
	if err != nil || len(m) == 0 {
		return fmt.Errorf("attest-lb: cannot enforce the measurement policy: launch_digest is missing or malformed (%q)", measurement)
	}
	for _, w := range want {
		if bytes.Equal(w, m) {
			return nil
		}
	}
	return fmt.Errorf("launch measurement %s is not in the allowlist", measurement)
}

// AllowlistSchema is the schema identifier a pinned canonical-allowlist
// document must carry.
const AllowlistSchema = "c8s.allowlist/v1"

// PinnedAllowlist is the parsed view of a pinned canonical-allowlist document.
// Parsing is only used to resolve workload names; the digest that matters is
// SHA-256 over the exact file bytes, never over a reserialization.
type PinnedAllowlist struct {
	Schema    string                     `json:"schema"`
	Workloads map[string]json.RawMessage `json:"workloads"`
}

// ParsePinnedAllowlist parses raw canonical-allowlist bytes and checks the
// schema identifier.
func ParsePinnedAllowlist(raw []byte) (*PinnedAllowlist, error) {
	var doc PinnedAllowlist
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("pinned allowlist: parse: %w", err)
	}
	if doc.Schema != AllowlistSchema {
		return nil, fmt.Errorf("pinned allowlist: schema %q is not %q", doc.Schema, AllowlistSchema)
	}
	return &doc, nil
}
