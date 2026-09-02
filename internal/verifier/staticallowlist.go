package verifier

// Sealed-policy (static allowlist) verification, vendored from c8s pkg/ratls
// (staticallowlist.go, extension.go) and internal/localverify, kept honest by
// the golden DER vector shared with c8s (staticallowlist_test.go).
//
// A CDS started with --static-allowlist enforces one allowlist document for
// its whole lifetime and mints its mesh CA with two extra extensions: the
// RA-TLS attestation extension (…1.1) over the CA public key, and the
// static-allowlist stamp (…1.3) = SHA-256 of the sealed document's canonical
// bytes. attest-lb already commits SHA-256(mesh_CA_DER) into the nonce-fresh
// report_data, so both extensions are covered by per-handshake hardware
// evidence with no protocol change.
//
// The …1.3 value alone is CA-self-asserted. What makes it enforced is the
// pairing this file requires: the …1.1 evidence proves the CA key was born
// inside a measured CDS launch that the remote's own measurement policy
// admits, and measured CDS code refuses to start unless the digest it stamps
// is the digest of the document it loaded, then refuses every mutation.
// Changing the policy therefore means launching a new CDS and minting a new
// CA, which every pinning client notices through the CA hash in fresh
// evidence.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/snp"
	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/attestation/teeverify"
	"github.com/google/go-sev-guest/verify/trust"
)

// OIDs under the confidential.ai arc 1.3.6.1.4.1.66378.1:
//
//	1.3.6.1.4.1.66378.1.1 - RA-TLS attestation extension
//	1.3.6.1.4.1.66378.1.3 - static allowlist extension
var (
	oidRATLSAttestation = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66378, 1, 1}
	oidStaticAllowlist  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66378, 1, 3}
)

// staticAllowlistVersion is the only stamp encoding version this parser
// accepts. An unknown version fails closed.
const staticAllowlistVersion = 1

// RA-TLS extension TEE types.
const (
	teeTypeSEVSNP = 1
	teeTypeTDX    = 2
)

// snpReportSize is the exact size of a raw AMD SEV-SNP ATTESTATION_REPORT.
const snpReportSize = 0x4A0

// initDataDigestSize is the size of a pinned init-data digest (SHA-256 of the
// CDS pod's kata init-data document).
const initDataDigestSize = 32

// staticAllowlistASN1 is the DER encoding:
//
//	StaticAllowlist ::= SEQUENCE {
//	    formatVersion    INTEGER,           -- exactly 1
//	    allowlistDigest  OCTET STRING (32)  -- SHA-256(Allowlist.Canonical())
//	}
type staticAllowlistASN1 struct {
	FormatVersion   int
	AllowlistDigest []byte
}

// unmarshalStaticAllowlist decodes a static-allowlist extension value and
// returns the sealed digest, requiring the one canonical encoding: minimal
// DER, no trailing bytes or fields, byte-exact against re-encoding.
func unmarshalStaticAllowlist(der []byte) ([]byte, error) {
	var raw staticAllowlistASN1
	rest, err := asn1.Unmarshal(der, &raw)
	if err != nil {
		return nil, fmt.Errorf("unmarshal static allowlist: %w", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("%d trailing bytes after static-allowlist extension", len(rest))
	}
	if raw.FormatVersion != staticAllowlistVersion {
		return nil, fmt.Errorf("unsupported static-allowlist version %d (supported: %d)", raw.FormatVersion, staticAllowlistVersion)
	}
	reencoded, err := asn1.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("re-encode static allowlist: %w", err)
	}
	if !bytes.Equal(reencoded, der) {
		return nil, fmt.Errorf("static-allowlist extension is not the exact v%d encoding (%d bytes, canonical is %d)", staticAllowlistVersion, len(der), len(reencoded))
	}
	if len(raw.AllowlistDigest) != allowlistDigestSize {
		return nil, fmt.Errorf("static-allowlist digest must be %d bytes, got %d", allowlistDigestSize, len(raw.AllowlistDigest))
	}
	return raw.AllowlistDigest, nil
}

// staticAllowlistFromCert returns the certificate's sealed allowlist digest,
// or nil when the certificate carries no stamp. A present but malformed or
// duplicated extension is an error, never nil.
func staticAllowlistFromCert(cert *x509.Certificate) ([]byte, error) {
	var found []byte
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(oidStaticAllowlist) {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("certificate carries more than one static-allowlist extension")
		}
		digest, err := unmarshalStaticAllowlist(ext.Value)
		if err != nil {
			return nil, err
		}
		found = digest
	}
	return found, nil
}

// ratlsAttestationASN1 is the RA-TLS extension's DER encoding:
//
//	TEEAttestation ::= SEQUENCE {
//	    teeType     INTEGER,        -- 1 = SEV-SNP, 2 = TDX
//	    report      OCTET STRING,   -- raw SNP report, or a JSON {platform, evidence} envelope
//	    certChain   OCTET STRING    -- VCEK DER for a raw SNP report, else empty
//	}
type ratlsAttestationASN1 struct {
	TEEType   int
	Report    []byte
	CertChain []byte
}

// caEvidence is a sealed CA's embedded evidence in the shape the attestation-go
// verifier consumes, with the report_data anchor it must bind.
type caEvidence struct {
	platform string
	evidence json.RawMessage
	// expectedReportData is SHA-384 over the CA public key (PKIX DER for
	// ECDSA, raw bytes for Ed25519), unpadded; the verifier zero-pads it to
	// the platform's report_data width.
	expectedReportData []byte
}

// caEvidenceFromCert extracts the RA-TLS attestation extension from a sealed
// CA certificate. An embedded JSON envelope (TDX, az-snp) is forwarded
// verbatim; a raw bare-metal SNP report is wrapped as attestation-go's snp
// evidence object. A certificate without the extension, or with a duplicated
// or malformed one, is an error.
func caEvidenceFromCert(cert *x509.Certificate) (*caEvidence, error) {
	var value []byte
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(oidRATLSAttestation) {
			continue
		}
		if value != nil {
			return nil, fmt.Errorf("certificate carries more than one RA-TLS attestation extension")
		}
		value = ext.Value
	}
	if value == nil {
		return nil, fmt.Errorf("certificate carries no RA-TLS attestation extension (OID %s)", oidRATLSAttestation)
	}

	var raw ratlsAttestationASN1
	rest, err := asn1.Unmarshal(value, &raw)
	if err != nil {
		return nil, fmt.Errorf("unmarshal RA-TLS attestation: %w", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("%d trailing bytes after RA-TLS attestation extension", len(rest))
	}
	if raw.TEEType != teeTypeSEVSNP && raw.TEEType != teeTypeTDX {
		return nil, fmt.Errorf("unsupported RA-TLS TEE type %d", raw.TEEType)
	}

	erd, err := reportDataForKey(cert.PublicKey)
	if err != nil {
		return nil, err
	}
	ev := &caEvidence{expectedReportData: erd}

	report := bytes.TrimSpace(raw.Report)
	if len(report) > 0 && report[0] == '{' {
		var envelope teetypes.AttestationEvidence
		if err := json.Unmarshal(report, &envelope); err != nil {
			return nil, fmt.Errorf("parse embedded attestation evidence: %w", err)
		}
		if envelope.Platform == "" || len(envelope.Evidence) == 0 {
			return nil, fmt.Errorf("embedded attestation evidence is missing platform or evidence")
		}
		ev.platform = string(envelope.Platform)
		ev.evidence = envelope.Evidence
		return ev, nil
	}
	if raw.TEEType == teeTypeTDX {
		return nil, fmt.Errorf("TDX RA-TLS extension must carry a JSON attestation-api envelope; got %d raw bytes", len(raw.Report))
	}
	if len(raw.Report) != snpReportSize {
		return nil, fmt.Errorf("raw SEV-SNP report is %d bytes, expected %d", len(raw.Report), snpReportSize)
	}
	inner := map[string]any{"attestation_report": base64.StdEncoding.EncodeToString(raw.Report)}
	if len(raw.CertChain) > 0 {
		inner["cert_chain"] = map[string]any{"vcek": base64.StdEncoding.EncodeToString(raw.CertChain)}
	}
	evidence, err := json.Marshal(inner)
	if err != nil {
		return nil, fmt.Errorf("marshal snp evidence: %w", err)
	}
	ev.platform = string(teetypes.PlatformSNP)
	ev.evidence = evidence
	return ev, nil
}

// reportDataForKey is the nonce-free RA-TLS binding every c8s certificate
// uses: SHA-384 over the public key (PKIX DER for ECDSA, raw for Ed25519).
func reportDataForKey(pub any) ([]byte, error) {
	var keyBytes []byte
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		der, err := x509.MarshalPKIXPublicKey(k)
		if err != nil {
			return nil, fmt.Errorf("marshal CA public key: %w", err)
		}
		keyBytes = der
	case ed25519.PublicKey:
		keyBytes = []byte(k)
	default:
		return nil, fmt.Errorf("unsupported CA public key type %T", pub)
	}
	sum := sha512.Sum384(keyBytes)
	return sum[:], nil
}

// ValidateStaticAllowlistPins checks how the sealed-policy pins relate to each
// other and returns the parsed init-data digest. Shared by `remote add` and the
// stored config, so a hand-edited file cannot reach a state the CLI refuses to
// write: --init-data pins the sealed CA's launch-committed document, so it
// requires --static-allowlist and is 32 bytes of hex.
func ValidateStaticAllowlistPins(staticAllowlist bool, initData string) ([]byte, error) {
	if initData == "" {
		return nil, nil
	}
	if !staticAllowlist {
		return nil, fmt.Errorf("--init-data requires --static-allowlist: it pins the init-data claim of the sealed mesh CA's evidence, which nothing reads without the seal")
	}
	digest, err := hex.DecodeString(initData)
	if err != nil {
		return nil, fmt.Errorf("--init-data is not hex: %v", err)
	}
	if len(digest) != initDataDigestSize {
		return nil, fmt.Errorf("--init-data is %d bytes, want %d (SHA-256 of the CDS init-data document)", len(digest), initDataDigestSize)
	}
	return digest, nil
}

// KDS getter bounds for a bare SNP report whose VCEK is not inline: the retry
// backoff is capped so several attempts fit inside a handshake deadline, and
// the getter's own timeout backstops a context with no deadline.
const (
	kdsMaxRetryDelay = 8 * time.Second
	kdsMaxFetchTime  = 2 * time.Minute
)

// verifyCAEvidence is the sealed-CA evidence seam: production points at
// verifySealedCAEvidence; tests substitute a stub.
var verifyCAEvidence = verifySealedCAEvidence

// verifySealedCAEvidence verifies a sealed CA's embedded evidence through
// attestation-go. A bare-metal/GCP SNP report from an RA-TLS certificate may
// carry no VCEK inline; the envelope verifier requires one, so that case drops
// to snp.VerifyReportContext, which fetches the VCEK from AMD KDS bounded by
// ctx. Everything else verifies offline through the envelope path.
func verifySealedCAEvidence(ctx context.Context, platform string, evidence json.RawMessage, params teetypes.VerifyParams) (*teetypes.VerificationResult, error) {
	if platform == string(teetypes.PlatformSNP) || platform == string(teetypes.PlatformGcpSNP) {
		var se snp.SnpEvidence
		if err := json.Unmarshal(evidence, &se); err != nil {
			return nil, fmt.Errorf("parse snp evidence: %w", err)
		}
		if se.CertChain == nil || se.CertChain.Vcek == "" {
			report, err := base64.StdEncoding.DecodeString(se.AttestationReport)
			if err != nil {
				return nil, fmt.Errorf("decode attestation_report: %w", err)
			}
			getter := &trust.RetryHTTPSGetter{
				Timeout:       kdsMaxFetchTime,
				MaxRetryDelay: kdsMaxRetryDelay,
				Getter:        &trust.SimpleHTTPSGetter{},
			}
			return snp.VerifyReportContext(ctx, report, nil, params,
				teetypes.PlatformType(platform), snp.MinReportVersion, snp.Options{Getter: getter})
		}
	}
	envelope, err := json.Marshal(teetypes.AttestationEvidence{
		Platform: teetypes.PlatformType(platform),
		Evidence: evidence,
	})
	if err != nil {
		return nil, fmt.Errorf("re-encode evidence: %w", err)
	}
	return teeverify.Verify(envelope, params)
}

// sealedCAMemo caches the verified result for one sealed CA under one set of
// verifier parameters. The CA certificate is immutable and its evidence is not
// nonce-bound, so re-verifying the same DER under the same parameters can only
// repeat the answer — and on bare-metal SNP it would repeat the AMD KDS fetch
// on every re-attestation. Policy is still enforced on the memoised claims
// every time; only the signature-chain work is skipped.
type sealedCAMemo struct {
	key    [32]byte
	result *teetypes.VerificationResult
}

// sealedCAKey identifies one (CA DER, verifier parameters) pair.
func sealedCAKey(caDER []byte, params teetypes.VerifyParams) [32]byte {
	h := sha512.New512_256()
	h.Write(caDER)
	h.Write([]byte{0})
	h.Write(params.ExpectedInitDataHash)
	h.Write([]byte{0})
	if params.MinTCB != nil {
		fmt.Fprintf(h, "%d,%d,%d,%d", params.MinTCB.Bootloader, params.MinTCB.Tee, params.MinTCB.Snp, params.MinTCB.Microcode)
	}
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// verifiedSealedCA returns the verified claims of the committed CA's embedded
// evidence, bound to the CA public key and to the remote's init-data pin and
// SNP TCB floor, from the memo when the same CA was verified under the same
// parameters before.
func (e *EndpointAttester) verifiedSealedCA(ctx context.Context, ca *x509.Certificate, pins platformPins) (*teetypes.VerificationResult, error) {
	ev, err := caEvidenceFromCert(ca)
	if err != nil {
		return nil, fmt.Errorf("sealed mesh CA: %w", err)
	}
	params := teetypes.VerifyParams{
		ExpectedReportData:   ev.expectedReportData,
		ExpectedInitDataHash: pins.initData,
		MinTCB:               pins.minTCB,
	}
	key := sealedCAKey(ca.Raw, params)

	e.mu.Lock()
	memo := e.sealedCA
	e.mu.Unlock()
	if memo != nil && memo.key == key {
		return memo.result, nil
	}

	res, err := verifyCAEvidence(ctx, ev.platform, ev.evidence, params)
	if err != nil {
		return nil, fmt.Errorf("sealed mesh CA evidence (%s) was refused: %w", ev.platform, err)
	}
	if err := checkSealedCAResult(res, params); err != nil {
		return nil, err
	}
	if res.Platform == "" {
		res.Platform = teetypes.PlatformType(ev.platform)
	}
	e.mu.Lock()
	e.sealedCA = &sealedCAMemo{key: key, result: res}
	e.mu.Unlock()
	return res, nil
}

// checkSealedCAResult asserts the verifier's own verdict fields for the CA
// evidence, as checkVerificationResult does for the handshake evidence, plus
// the init-data binding when one is pinned.
func checkSealedCAResult(res *teetypes.VerificationResult, params teetypes.VerifyParams) error {
	if res == nil {
		return fmt.Errorf("sealed mesh CA: verifier returned no result")
	}
	if !res.SignatureValid {
		return fmt.Errorf("sealed mesh CA: hardware signature on the evidence did not verify")
	}
	if res.ReportDataMatch == nil || !*res.ReportDataMatch {
		return fmt.Errorf("sealed mesh CA: evidence does not bind the CA public key (report_data mismatch)")
	}
	if params.ExpectedInitDataHash != nil && (res.InitDataMatch == nil || !*res.InitDataMatch) {
		return fmt.Errorf("sealed mesh CA: evidence does not bind the pinned init-data digest")
	}
	return nil
}

// enforceSealedCA applies the remote's measurement policy to the sealed CA's
// verified claims: the CA must come from a launch the operator pinned — the
// launch-digest allowlist, or the full TDX image tuple — under the SNP TCB
// floor when one is set. RTMR[3] is deliberately not applied: it records the
// runtime chain of the guest that extends it, which is the front door's, not
// CDS's. Cross-platform pins fail closed as they do for the handshake evidence.
func (p platformPins) enforceSealedCA(res *teetypes.VerificationResult, measurements []string) error {
	platform := res.Platform
	if p.image != nil {
		if !isTDXPlatform(platform) {
			return fmt.Errorf("an image manifest is pinned but the sealed mesh CA's evidence platform is %q; a sealed deployment runs CDS on the pinned image", platform)
		}
		if err := checkImageMRTD(res, p.image); err != nil {
			return err
		}
		for _, reg := range []struct {
			idx     int
			meaning string
			want    []byte
		}{{1, "guest kernel", p.image.RTMR1[:]}, {2, "guest rootfs", p.image.RTMR2[:]}} {
			if err := checkRTMR(res, reg.idx, reg.meaning, reg.want); err != nil {
				return err
			}
		}
	} else if err := checkMeasurement(res.Claims.LaunchDigest, measurements); err != nil {
		return err
	}
	if p.minTCB != nil {
		if !isSNPPlatform(platform) {
			return fmt.Errorf("an SNP TCB floor is pinned but the sealed mesh CA's evidence platform is %q", platform)
		}
		if err := checkTCBFloor(res.Claims.TCB, p.minTCB); err != nil {
			return err
		}
	}
	return nil
}

// checkStaticAllowlist enforces the remote's sealed-policy pin on the
// committed (hardware-committed, chain-verifying) mesh CA, fail closed:
//
//  1. the CA carries exactly one well-formed static-allowlist stamp;
//  2. the CA's embedded RA-TLS evidence verifies, binds the CA public key
//     (and the pinned init-data digest), and its launch passes the remote's
//     measurement policy;
//  3. the pinned allowlist file's exact bytes hash to the sealed digest;
//  4. the mesh leaf's matched-workload stamp, when present, was decided under
//     the sealed digest and not some other snapshot.
//
// Without a pinned allowlist file the seal is verified but not compared to a
// reviewed document, which the verdict flags as a warning.
func (e *EndpointAttester) checkStaticAllowlist(ctx context.Context, committedCA *x509.Certificate, stamp *MatchedWorkload, pins platformPins, v *SessionVerdict) error {
	digest, err := staticAllowlistFromCert(committedCA)
	if err != nil {
		return fmt.Errorf("committed mesh CA: %w", err)
	}
	if digest == nil {
		return fmt.Errorf("pinned but the committed mesh CA carries no static-allowlist stamp (is this CDS running with --static-allowlist?)")
	}

	res, err := e.verifiedSealedCA(ctx, committedCA, pins)
	if err != nil {
		return err
	}
	if err := pins.enforceSealedCA(res, e.remote.Measurements); err != nil {
		return fmt.Errorf("sealed mesh CA launch policy: %w", err)
	}

	if e.remote.AllowlistPath != "" {
		raw, err := readPinnedAllowlist(e.remote.AllowlistPath)
		if err != nil {
			return err
		}
		fileDigest := sha256.Sum256(raw)
		if !bytes.Equal(fileDigest[:], digest) {
			return fmt.Errorf("sealed policy digest %x does not match SHA-256 %x of the pinned allowlist file %s", digest, fileDigest[:], e.remote.AllowlistPath)
		}
	} else {
		v.addWarning("the sealed policy digest is verified but pinned to no reviewed document; store the reviewed allowlist with `remote add --allowlist <file>` or `allowlist fetch --pin` so the seal is compared against it")
	}
	if stamp != nil && !bytes.Equal(stamp.AllowlistDigest, digest) {
		return fmt.Errorf("the mesh leaf's matched-workload stamp was decided under allowlist digest %x, not the sealed digest %x", stamp.AllowlistDigest, digest)
	}

	v.StaticAllowlistDigest = hex.EncodeToString(digest)
	v.SealedCALaunch = res.Claims.LaunchDigest
	return nil
}
