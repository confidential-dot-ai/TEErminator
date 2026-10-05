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
	"regexp"
	"slices"
	"strings"
	"sync"
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
// response — no out-of-band CA file is required. In cds mode, the serving leaf
// chains to that mesh CA. In acme mode, the serving leaf must pass WebPKI name
// and chain validation. In both modes, fresh hardware evidence binds the exact
// serving certificate observed on the connection.

// wellKnownAttestLB is the LB's ordinary-TLS attestation endpoint. It lives at
// the LB origin, independent of the remote's forwarding path.
const wellKnownAttestLB = "/.well-known/c8s/attest-lb"

// attestLBVersion is the binding identifier the attest-lb endpoint must return;
// any other response shape (including the retired "c8s-verify/v1" and the
// encrypted-session "c8s/attest-pq/v1") is rejected even if its evidence is
// otherwise valid — there is no endpoint negotiation or fallback.
const attestLBVersion = "c8s/attest-lb/v1"

// These are the only front-door modes that keep the serving key in the TEE.
// A webpki key is host-visible and is valid for attest-pq only.
const (
	frontDoorModeCDS    = "cds"
	frontDoorModeWebPKI = "webpki"
	frontDoorModeACME   = "acme"
)

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
	// as what the deployment claims, never as a checked fact — the document
	// behind the counter is what `allowlist fetch` checks.
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
	// Stamp is the matched-workload stamp carried by the chain-verified mesh
	// leaf, or nil when the leaf carries none. It is read on every attestation
	// and ENFORCED only when the remote pins a workload name or an allowlist
	// file, so a caller that needs the allowlist snapshot the match was decided
	// under (`allowlist fetch`) reads it off this verdict rather than running a
	// second handshake. It is CA-vouched, not hardware-attested: the hardware
	// evidence binds the mesh leaf into the transcript, and the mesh CA's
	// signature over that leaf is what vouches for the stamp inside it.
	Stamp *MatchedWorkload
	// StaticAllowlistDigest is the hex SHA-256 the committed mesh CA seals as
	// its one lifetime policy, set only when the remote pins --static-allowlist
	// and every sealed-policy check passed (staticallowlist.go). Unlike the
	// leaf stamp it is hardware-rooted: the CA DER is committed in fresh
	// evidence, and the CA's own embedded evidence verified under the remote's
	// measurement policy.
	StaticAllowlistDigest string
	// SealedCALaunch is the launch digest of the sealed CA's verified evidence,
	// set alongside StaticAllowlistDigest.
	SealedCALaunch string
	// AllowlistBound lists the policy digests (sha256:<hex>) the attested CDS
	// rollout state says may be running. The transcript commits the state, and
	// the committed mesh CA signs it. Empty when the router serves no state.
	AllowlistBound []string
	// MeasuredPolicies lists every allowlist policy the router's TDX node
	// enforced since boot, replayed from RTMR[3] onto the expected_rtmr3 seed.
	MeasuredPolicies []string
	// Warning is a policy gap in an otherwise passing verdict — the MRTD-only
	// note for specific-cluster TDX remotes without an image pin, or a seal
	// that is verified but pinned to no reviewed document.
	Warning string
}

// addWarning appends w to the verdict's warning, keeping any earlier one.
func (v *SessionVerdict) addWarning(w string) {
	if v.Warning != "" {
		v.Warning += "; "
	}
	v.Warning += w
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
	FrontDoorMode string          `json:"front_door_mode"`
	IdentityProof identityProof   `json:"identity_proof"`
	CDSState      *cdsState       `json:"cds_state,omitempty"`
	// MeasuredPolicies lists the allowlist policies the router's TDX node
	// extended into RTMR[3] after its seed, read after the evidence.
	MeasuredPolicies []string `json:"measured_policies,omitempty"`
}

// cdsState is a pinned-allowlist router's CDS rollout state: the exact state
// JSON bytes and the mesh CA's ASN.1 ECDSA signature over SHA-384 of the
// challenge context, a zero byte and those bytes.
type cdsState struct {
	State     []byte `json:"state"`
	Signature []byte `json:"signature"`
}

// rolloutState holds the rollout-state fields this client checks.
type rolloutState struct {
	Bound        []string `json:"bound"`
	Lease        int64    `json:"lease_seconds"`
	Nonce        string   `json:"nonce"`
	IssuedAt     int64    `json:"issued_at"`
	ExpiresAt    int64    `json:"expires_at"`
	OperatorKeys string   `json:"operator_keys"`
}

// rolloutStateChallengeContext prefixes the state CDS signs for a nonce
// (c8s pkg/rolloutstate.ContextChallenge).
const rolloutStateChallengeContext = "c8s/rollout-state-challenge/v1"

// rolloutStateMaxSkew is the clock skew allowed around a state's validity
// window (c8s pkg/rolloutstate.MaxClockSkew).
const rolloutStateMaxSkew = 2 * time.Minute

// operatorKeysNone is rolloutState.OperatorKeys for an immutable allowlist.
const operatorKeysNone = "none"

// EndpointAttester implements the attest-lb mode. baseURL is the LB origin
// (scheme://host); client must be the transport whose observed TLS state the
// proxy forwards over, so the serving leaf bound into the evidence is the one
// application traffic rides. pinnedCAs are the operator's `certs add`
// certificates: they are OPTIONAL hardening — the mesh CA is derived from the
// hardware-committed response either way — and only upgrade the verdict to
// specific-cluster when one of them byte-equals the committed CA.
type EndpointAttester struct {
	client      *http.Client
	attestURL   *url.URL
	remote      config.Remote
	pinnedCAs   []*x509.Certificate
	webPKIRoots *x509.CertPool

	// mu guards sealedCA, the memoised verification of the committed mesh
	// CA's embedded evidence under --static-allowlist.
	mu       sync.Mutex
	sealedCA *sealedCAMemo
}

// NewEndpointAttester builds an endpoint attester.
func NewEndpointAttester(baseURL string, client *http.Client, remote config.Remote, pinnedCAs []*x509.Certificate, webPKIRoots *x509.CertPool) (*EndpointAttester, error) {
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
		client:      &c,
		attestURL:   u,
		remote:      remote,
		pinnedCAs:   pinnedCAs,
		webPKIRoots: webPKIRoots,
	}, nil
}

// Attest runs the per-handshake attest-lb verification and returns the verdict,
// or an error (fail closed). The checks run strictly in this order: serving
// leaf capture, bundle shape (version, nonce echo), served chain parsing and
// committed-CA selection, identity-proof field equality, hardware evidence over
// the recomputed transcript, proof of possession, mesh-leaf chain, serving-leaf
// trust, measurement policy, workload policy, sealed policy.
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
	if !isTEEFrontDoorMode(bundle.FrontDoorMode) {
		return nil, fmt.Errorf("attest-lb: unsupported front_door_mode %q (want %q or %q; %q is attest-pq-only)", bundle.FrontDoorMode, frontDoorModeCDS, frontDoorModeACME, frontDoorModeWebPKI)
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
	var stateDigest []byte
	if bundle.CDSState != nil {
		sum := sha512.Sum384(bundle.CDSState.State)
		stateDigest = sum[:]
	}
	reportData := attestLBReportData(bundle.FrontDoorMode, nonce, servingLeaf.Raw, meshLeaf.Raw, committedCA.Raw, stateDigest)
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

	// (g) The committed mesh identity must chain to the committed mesh CA.
	now := time.Now()
	if err := verifyDirectChain(meshLeaf, committedCA, now); err != nil {
		return nil, fmt.Errorf("attest-lb: mesh leaf: %w", err)
	}

	// (h) The serving-certificate trust rule depends on the front-door mode.
	// A cds leaf is issued by the mesh CA. An ACME leaf is issued by WebPKI,
	// while the fresh hardware evidence above binds its exact DER to this session.
	switch bundle.FrontDoorMode {
	case frontDoorModeCDS:
		if err := verifyDirectChain(servingLeaf, committedCA, now); err != nil {
			return nil, fmt.Errorf("attest-lb: serving leaf: %w", err)
		}
	case frontDoorModeACME:
		serverName := e.remote.ServerName
		if serverName == "" {
			serverName = e.attestURL.Hostname()
		}
		if err := verifyWebPKIChain(servingLeaf, resp.TLS.PeerCertificates[1:], serverName, e.webPKIRoots, now); err != nil {
			return nil, fmt.Errorf("attest-lb: ACME serving leaf: %w", err)
		}
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
	if err := pins.enforce(platform, res, v, bundle.MeasuredPolicies); err != nil {
		return nil, fmt.Errorf("attest-lb: %w", err)
	}

	// (j) Matched-workload stamp, only after everything above: the mesh leaf's
	// chain to the committed CA is what vouches for it. It is READ on every
	// attestation — a present-but-damaged stamp is an error even unpinned, a
	// verifier must not read damage as absence — and ENFORCED only when the
	// remote pins a workload name or an allowlist file.
	stamp, err := matchedWorkloadFromCert(meshLeaf)
	if err != nil {
		return nil, fmt.Errorf("attest-lb: workload policy: %w", err)
	}
	v.Stamp = stamp
	if e.remote.WorkloadName != "" || e.remote.AllowlistPath != "" {
		if err := e.checkWorkloadPolicy(stamp); err != nil {
			return nil, fmt.Errorf("attest-lb: %w", err)
		}
		v.WorkloadName = stamp.Name
		v.AllowlistVersion = stamp.AllowlistVersion
	}

	// (j') Rollout state: committed by the transcript, signed by the committed
	// mesh CA, and answering this nonce. With pinned policies, every policy
	// that may run must be pinned.
	if bundle.CDSState != nil {
		st, err := verifyRolloutState(bundle.CDSState, committedCA, nonce)
		if err != nil {
			return nil, fmt.Errorf("attest-lb: %w", err)
		}
		v.AllowlistBound = st.Bound
		if err := checkPinnedPolicies(st, e.remote.PinnedPolicies, v.MeasuredPolicies); err != nil {
			return nil, fmt.Errorf("attest-lb: %w", err)
		}
		if e.remote.Immutable && st.OperatorKeys != operatorKeysNone {
			return nil, fmt.Errorf("attest-lb: the remote requires an immutable allowlist, but CDS accepts writes from operator key set %q", st.OperatorKeys)
		}
		if e.remote.TrustOperator {
			if err := e.checkOperatorSignatures(ctx, st, v.MeasuredPolicies); err != nil {
				return nil, fmt.Errorf("attest-lb: %w", err)
			}
		}
	} else if len(e.remote.PinnedPolicies) > 0 || e.remote.TrustOperator || e.remote.Immutable {
		return nil, fmt.Errorf("attest-lb: pinned or operator-signed policies need the CDS rollout state, which this router does not serve (c8s router.attest.pinnedAllowlist)")
	}

	// (k) Sealed policy, only when pinned: the committed CA — whose DER the
	// evidence above commits — must carry the static-allowlist stamp and its
	// own verifiable launch evidence, the pinned allowlist file must hash to
	// the sealed digest, and the leaf stamp must have been decided under it.
	if pins.sealed {
		if err := e.checkStaticAllowlist(ctx, committedCA, stamp, pins, v); err != nil {
			return nil, fmt.Errorf("attest-lb: static allowlist: %w", err)
		}
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
		v.addWarning("TDX policy covers MRTD only — the guest kernel (RTMR[1]) and rootfs (RTMR[2]) are UNMEASURED by this policy; pin the full image tuple with `remote add --image-manifest`")
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
// (RTMR[3], which only ever rides on top of an image tuple — see
// ValidatePinCombination), the SNP TCB floor, and the sealed-policy pin with
// its optional init-data digest. Any pin set against evidence from a platform
// it cannot apply to is a hard error.
type platformPins struct {
	image  *ImagePins
	rtmr3  *[RegisterSize]byte
	minTCB *teetypes.SnpTcb
	// sealed requires the committed mesh CA to carry a verified static
	// allowlist seal; initData additionally pins the sealed CA evidence's
	// init-data claim (pod-as-CVM).
	sealed   bool
	initData []byte
}

// ValidatePinCombination enforces the two rules that relate a remote's TDX
// pins to each other. They hold independently of any evidence, so both the
// `remote add` flags and the stored config go through this one implementation
// — a hand-edited config file must not reach a state the CLI refuses to write.
//
//   - An image manifest pins the launch digest exactly against its own MRTD, so
//     a second, looser source of accepted launch digests is not a widening of
//     the policy but a hole in it: an allowlist entry that is not the
//     manifest's MRTD would admit a guest the manifest does not describe while
//     its RTMR[1]/[2] stayed pinned to the manifest.
//   - RTMR[3] records events extended into a guest whose image the untrusted
//     host selects. Without an image pin that host can boot anything and
//     reproduce the chain, so a lone RTMR[3] pin reads like a proof of identity
//     — reported as an enforced register — while proving none.
//
// c8s applies both rules to `c8s verify` (internal/cmds/verify, buildPolicy).
func ValidatePinCombination(measurements []string, imageManifestPath, expectedRTMR3 string) error {
	if imageManifestPath != "" && len(measurements) > 0 {
		return fmt.Errorf("--measurements and --image-manifest are mutually exclusive: the manifest pins MRTD, RTMR[1] and RTMR[2] exactly against this one build, so a separate launch-digest allowlist could only admit an image it does not describe")
	}
	if expectedRTMR3 != "" && imageManifestPath == "" {
		return fmt.Errorf("--expected-rtmr3 requires --image-manifest: RTMR[3] records events extended into a guest whose image the untrusted host selects, so pinning it without pinning the image proves nothing about what is running")
	}
	return nil
}

// loadPlatformPins resolves a remote's platform pins; every failure is a
// configuration error.
func loadPlatformPins(r config.Remote) (platformPins, error) {
	var pins platformPins
	if err := ValidatePinCombination(r.Measurements, r.ImageManifestPath, r.ExpectedRTMR3); err != nil {
		return platformPins{}, fmt.Errorf("configuration error: %w", err)
	}
	if r.ImageManifestPath != "" {
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
	initData, err := ValidateStaticAllowlistPins(r.StaticAllowlist, r.InitData)
	if err != nil {
		return platformPins{}, fmt.Errorf("configuration error: %w", err)
	}
	pins.sealed = r.StaticAllowlist
	pins.initData = initData
	return pins, nil
}

// enforce applies the platform pins to the verified claims, recording what was
// enforced in the verdict. It fails closed on any pin whose platform does not
// match the evidence, on absent or malformed claims, and on any mismatch —
// never an ignored option.
//
// expected_rtmr3 is the value before the node measured any allowlist policy;
// RTMR[3] may also be it followed by a prefix of measured, which then becomes
// the verdict's MeasuredPolicies.
func (p platformPins) enforce(platform teetypes.PlatformType, res *teetypes.VerificationResult, v *SessionVerdict, measured []string) error {
	if (p.image != nil || p.rtmr3 != nil) && !isTDXPlatform(platform) {
		return fmt.Errorf("a TDX pin (image manifest / expected RTMR[3]) is set but the evidence platform is %q: runtime measurement registers exist only on TDX, so this policy cannot be enforced against %q evidence", platform, platform)
	}
	if p.minTCB != nil && !isSNPPlatform(platform) {
		return fmt.Errorf("an SNP TCB floor (min_tcb) is set but the evidence platform is %q: the four-component TCB exists only on SEV-SNP, so this policy cannot be enforced against %q evidence", platform, platform)
	}

	if p.image != nil {
		if err := checkImageMRTD(res, p.image); err != nil {
			return err
		}
	}

	check := func(idx int, meaning string, want []byte) error {
		if err := checkRTMR(res, idx, meaning, want); err != nil {
			return err
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
		want := p.rtmr3[:]
		if checkRTMR(res, 3, "", want) != nil {
			reg := *p.rtmr3
			for i, d := range measured {
				reg = extendRegister(reg, d)
				if checkRTMR(res, 3, "", reg[:]) == nil {
					want, v.MeasuredPolicies = reg[:], slices.Clone(measured[:i+1])
					break
				}
			}
		}
		if err := check(3, "runtime operator-key/policy chain", want); err != nil {
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

// checkImageMRTD compares the launch digest byte-exactly against the image
// manifest's MRTD. On TDX the launch digest IS the MRTD, and it comes out of
// the same build as RTMR[1]/[2]: comparing it exactly — rather than admitting
// it into an allowlist that may carry other digests — is what makes the
// manifest ONE image pin instead of three independent ones; otherwise a guest
// whose firmware differs from the manifest verifies while the kernel and
// rootfs registers stay pinned to the manifest.
func checkImageMRTD(res *teetypes.VerificationResult, image *ImagePins) error {
	mb, err := hex.DecodeString(strings.ToLower(strings.TrimSpace(res.Claims.LaunchDigest)))
	if err != nil || len(mb) == 0 {
		return fmt.Errorf("cannot enforce the image pin: launch_digest is missing or malformed (%q)", res.Claims.LaunchDigest)
	}
	if !bytes.Equal(mb, image.MRTD[:]) {
		return fmt.Errorf("MRTD mismatch: launch measurement %s does not match the image manifest MRTD %s (a different guest firmware/image booted)",
			hex.EncodeToString(mb), hex.EncodeToString(image.MRTD[:]))
	}
	return nil
}

// checkRTMR compares one pinned TDX runtime register against the verified
// claims, failing closed on an absent or malformed claim.
func checkRTMR(res *teetypes.VerificationResult, idx int, meaning string, want []byte) error {
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

// isTEEFrontDoorMode reports whether mode keeps the public serving key inside
// the TEE. Only these modes can support the attest-lb transport binding.
func isTEEFrontDoorMode(mode string) bool {
	return mode == frontDoorModeCDS || mode == frontDoorModeACME
}

// attestLBReportData is the normative attest-lb transcript hash:
//
//	report_data = SHA-384( LP("c8s/attest-lb/v1") || LP(front_door_mode) || LP(nonce) ||
//	    LP(SHA-256(serving_leaf_DER)) || LP(SHA-256(mesh_leaf_DER)) ||
//	    LP(SHA-256(mesh_CA_DER)) || LP(state_digest) )
//
// where LP(x) = uint32-big-endian(len(x)) || x and state_digest is SHA-384 of
// the bundle's exact cds_state bytes, empty without one. The serving-leaf hash covers
// the FULL certificate DER, not the SPKI, so a substituted certificate with the
// same key still fails.
func attestLBReportData(frontDoorMode string, nonce, servingLeafDER, meshLeafDER, meshCADER, stateDigest []byte) [48]byte {
	h := sha512.New384()
	lp := func(b []byte) {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(b)))
		h.Write(n[:])
		h.Write(b)
	}
	lp([]byte(attestLBVersion))
	lp([]byte(frontDoorMode))
	lp(nonce)
	servingSum := sha256.Sum256(servingLeafDER)
	lp(servingSum[:])
	meshSum := sha256.Sum256(meshLeafDER)
	lp(meshSum[:])
	caSum := sha256.Sum256(meshCADER)
	lp(caSum[:])
	// Present only with a rollout state, so a bundle without one hashes as
	// before the field existed.
	if len(stateDigest) > 0 {
		lp(stateDigest)
	}
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

// verifyWebPKIChain verifies an ACME serving certificate after hardware
// evidence identifies the front-door mode. No application data is sent before
// this check. A nil roots pool selects the operating system trust store.
func verifyWebPKIChain(leaf *x509.Certificate, peers []*x509.Certificate, serverName string, roots *x509.CertPool, now time.Time) error {
	intermediates := x509.NewCertPool()
	for _, cert := range peers {
		intermediates.AddCert(cert)
	}
	_, err := leaf.Verify(x509.VerifyOptions{
		DNSName:       serverName,
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		return fmt.Errorf(
			"WebPKI verification for %q failed: %w (hint: in acme mode, set --server-name to the public hostname on the certificate; for a staging or private ACME directory, add its root certificate with `certs add`)",
			serverName, err)
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

// checkWorkloadPolicy enforces the remote's workload pins against the stamp
// carried by the committed (chain-verified) mesh leaf, fail closed: with a pin
// set, an absent, mismatched, or unresolvable stamp is an error. stamp is nil
// when the leaf carries none (a malformed or duplicated one never reaches
// here — matchedWorkloadFromCert already failed).
func (e *EndpointAttester) checkWorkloadPolicy(stamp *MatchedWorkload) error {
	if stamp == nil {
		return fmt.Errorf("workload policy: pin set but the mesh leaf carries no matched-workload stamp")
	}
	if e.remote.WorkloadName != "" && stamp.Name != e.remote.WorkloadName {
		return fmt.Errorf("workload policy: mesh leaf is stamped for workload %q, pinned %q", stamp.Name, e.remote.WorkloadName)
	}
	if e.remote.AllowlistPath != "" {
		// Hash EXACTLY the file bytes as read — canonical bytes only, never a
		// reserialization. This is the same check `allowlist fetch` runs over
		// the bytes the cluster serves, so both go through checkAllowlistBytes.
		raw, err := readPinnedAllowlist(e.remote.AllowlistPath)
		if err != nil {
			return fmt.Errorf("workload policy: %w", err)
		}
		if err := checkAllowlistBytes(raw, stamp); err != nil {
			var mismatch *AllowlistDigestMismatch
			if errors.As(err, &mismatch) {
				return fmt.Errorf("workload policy: stamped allowlist digest does not match the pinned allowlist file %s (stamped %s, file %s)",
					e.remote.AllowlistPath, mismatch.stampedHex(), mismatch.servedHex())
			}
			return fmt.Errorf("workload policy: %w", err)
		}
	}
	return nil
}

// verifyRolloutState checks that ca's key signed the state and that it
// answers nonce.
func verifyRolloutState(s *cdsState, ca *x509.Certificate, nonce []byte) (*rolloutState, error) {
	key, ok := ca.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("rollout state: mesh CA key is %T, not ECDSA", ca.PublicKey)
	}
	h := sha512.New384()
	h.Write([]byte(rolloutStateChallengeContext))
	h.Write([]byte{0})
	h.Write(s.State)
	if !ecdsa.VerifyASN1(key, h.Sum(nil), s.Signature) {
		return nil, fmt.Errorf("rollout state: signature does not verify against the committed mesh CA")
	}
	var st rolloutState
	if err := json.Unmarshal(s.State, &st); err != nil {
		return nil, fmt.Errorf("rollout state: %w", err)
	}
	if st.Nonce != hex.EncodeToString(nonce) {
		return nil, fmt.Errorf("rollout state answers another nonce")
	}
	skew := int64(rolloutStateMaxSkew / time.Second)
	if now := time.Now().Unix(); st.IssuedAt <= 0 || st.ExpiresAt < st.IssuedAt || st.IssuedAt > now+skew || now > st.ExpiresAt+skew {
		return nil, fmt.Errorf("rollout state is outside its validity window (issued_at %d, expires_at %d)", st.IssuedAt, st.ExpiresAt)
	}
	for _, d := range st.Bound {
		if !policyDigestRE.MatchString(d) {
			return nil, fmt.Errorf("rollout state: bound digest %q is not sha256:<64 lowercase hex>", d)
		}
	}
	return &st, nil
}

// policyDigestRE is the only digest shape a bound may carry; it is used in
// URLs and file names.
var policyDigestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// checkPinnedPolicies requires every policy that may run to be pinned, and a
// lease that fences open connections before a new policy is enforced. No
// pins means the caller follows the deployment and only reports the bound.
//
// history, the policies the node enforced since boot, must be pinned too.
func checkPinnedPolicies(st *rolloutState, pins, history []string) error {
	if len(pins) == 0 {
		return nil
	}
	for _, d := range history {
		if !slices.Contains(pins, d) {
			return fmt.Errorf("pinned policies: the node enforced policy %s since boot (RTMR[3]) and it is not pinned; review it at /.well-known/c8s/objects/sha256/%s", d, strings.TrimPrefix(d, "sha256:"))
		}
	}
	if st.Lease <= 0 {
		return fmt.Errorf("pinned policies: CDS enforces allowlist writes without an activation lease, so open connections are not fenced")
	}
	for _, d := range st.Bound {
		if !slices.Contains(pins, d) {
			return fmt.Errorf("pinned policies: policy %s may be running and is not pinned; review it at /.well-known/c8s/objects/sha256/%s", d, strings.TrimPrefix(d, "sha256:"))
		}
	}
	return nil
}

// readPinnedAllowlist reads the pinned allowlist file EXACTLY as stored —
// canonical bytes only, never a reserialization — since every digest in this
// client is taken over those bytes.
func readPinnedAllowlist(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read pinned allowlist: %w", err)
	}
	return raw, nil
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
