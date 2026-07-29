// Attesting CDS: the trust root a client verifies ONCE and then caches.
//
// Until now the mesh CA arrived out of band — `teerminator certs add mesh-ca.pem`
// — so "this leaf was issued by the cluster" rested on a file the operator sent
// you. Attesting CDS replaces that: CDS's own RA-TLS certificate carries
// hardware evidence over its config-claims, and those claims commit the digest
// of the mesh CA it issues under (and of the allowlist it is serving). Verify
// that certificate and the mesh CA stops being an anchor you were handed.
//
// Wire formats mirrored from c8s pkg/ratls (extension.go, claims.go). They are
// reimplemented rather than imported because TEErminator deliberately does not
// depend on the c8s module; the REPORTDATA transcript below must therefore stay
// byte-identical to ReportDataForKeyAndClaims or every verification fails
// closed.

package verifier

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/attestation/teeverify"
)

// RA-TLS extension OIDs (c8s pkg/ratls, the 1.3.6.1.4.1.59888 arc).
var (
	oidRATLSAttestation  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 59888, 1, 1}
	oidRATLSConfigClaims = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 59888, 1, 3}
)

// claimsDomainSep tags the config-claims REPORTDATA transcript. Must match
// c8s pkg/ratls claimsDomainSep exactly.
var claimsDomainSep = []byte("c8s/config-claims/v1\x00")

// claimsDigestSize is the width of every digest carried in config-claims.
const claimsDigestSize = 32

// unsetDigest marks a claims field that does not apply. All-zero is unreachable
// as a real SHA-256, so a pin on a real value can never be met by the sentinel.
var unsetDigest = make([]byte, claimsDigestSize)

// discoveryDocument is the subset of the LB's /v1/discovery document we read.
//
// cds_identity is CDS's OWN certificate. It is NOT cds_tls, which is the
// certificate CDS ISSUED to the LB — a distinction the field names in older
// deployments actively obscure (/.well-known/cds-cert.pem serves the LB's leaf).
type discoveryDocument struct {
	CDSIdentity *struct {
		CertificatePEM    string `json:"certificate_pem"`
		CertificateSHA256 string `json:"certificate_sha256"`
		ObservedAt        string `json:"observed_at"`
	} `json:"cds_identity"`
}

// configClaims is the parsed config-claims extension.
type configClaims struct {
	OperatorKeysDigest []byte
	SeedDigest         []byte
	WorkloadDigest     []byte
	MeshCADigest       []byte // v2+; sentinel on v1
	AllowlistDigest    []byte // v3+; sentinel on v1/v2
}

type claimsV1 struct {
	Version            int
	OperatorKeysDigest []byte
	SeedDigest         []byte
	WorkloadDigest     []byte
}

type claimsV2 struct {
	Version            int
	OperatorKeysDigest []byte
	SeedDigest         []byte
	WorkloadDigest     []byte
	MeshCADigest       []byte
}

type claimsV3 struct {
	Version            int
	OperatorKeysDigest []byte
	SeedDigest         []byte
	WorkloadDigest     []byte
	MeshCADigest       []byte
	AllowlistDigest    []byte
}

// attestationASN1 mirrors c8s pkg/ratls attestationASN1.
type attestationASN1 struct {
	TEEType   int
	Report    []byte
	CertChain []byte
}

// CDSIdentity is a VERIFIED CDS attestation: what the client caches.
//
// Fingerprint is the cache key and the invalidation signal in one. CDS re-issues
// its certificate whenever the live allowlist changes, so a fingerprint that has
// not moved means the policy has not moved — the cache stays valid without any
// staleness window to tune, and a changed fingerprint is exactly when to
// re-attest.
type CDSIdentity struct {
	Fingerprint     [32]byte
	LaunchDigest    string
	MeshCADigest    []byte
	AllowlistDigest []byte
	NotAfter        time.Time
}

// FingerprintHex renders the cache key.
func (id *CDSIdentity) FingerprintHex() string { return hex.EncodeToString(id.Fingerprint[:]) }

// CDSPolicy is what a caller pins when attesting CDS.
type CDSPolicy struct {
	// Measurements are acceptable hex launch digests. Empty accepts any
	// genuine TEE, which is UNSAFE outside development — the caller decides,
	// exactly as it does for the LB.
	Measurements []string
	// ExpectedRTMR3 pins the deployment (operator key). TDX only.
	ExpectedRTMR3 string
}

// FetchCDSIdentityPEM reads cds_identity out of the LB's discovery document.
//
// The document is fetched over whatever transport the caller supplies and is
// NOT trusted: the certificate inside is self-authenticating, carrying hardware
// evidence over its own public key and claims, so a tampered or substituted
// copy simply fails AttestCDSIdentity. That is what makes it safe to relay
// through the LB (or anything else) rather than requiring the client to reach
// CDS, which is typically cluster-internal.
func FetchCDSIdentityPEM(ctx context.Context, client *http.Client, discoveryURL string) ([]byte, error) {
	u, err := url.Parse(discoveryURL)
	if err != nil {
		return nil, fmt.Errorf("cds-identity: parse discovery URL: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("cds-identity: build request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cds-identity: fetch discovery: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // read-only
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("cds-identity: discovery returned %d: %s", resp.StatusCode, body)
	}

	var doc discoveryDocument
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&doc); err != nil {
		return nil, fmt.Errorf("cds-identity: decode discovery: %w", err)
	}
	if doc.CDSIdentity == nil || doc.CDSIdentity.CertificatePEM == "" {
		return nil, fmt.Errorf("cds-identity: discovery carries no cds_identity — the cluster predates it; " +
			"pin the mesh CA out of band with `teerminator certs add mesh-ca.pem` instead")
	}
	return []byte(doc.CDSIdentity.CertificatePEM), nil
}

// AttestCDSIdentity verifies a CDS RA-TLS certificate and returns what it
// vouches for. Every failure is fail-closed: an unparseable extension, evidence
// that does not bind this certificate's key and claims, a launch digest outside
// the policy, or an RTMR[3] mismatch all return an error rather than a partial
// result.
func AttestCDSIdentity(certPEM []byte, policy CDSPolicy) (*CDSIdentity, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("cds-identity: not a PEM CERTIFICATE")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("cds-identity: parse certificate: %w", err)
	}

	attExt := extensionValue(cert, oidRATLSAttestation)
	if attExt == nil {
		return nil, fmt.Errorf("cds-identity: certificate carries no RA-TLS attestation extension (%s) — "+
			"this is not a CDS RA-TLS certificate (a mesh-issued leaf is not one)", oidRATLSAttestation)
	}
	claimsDER := extensionValue(cert, oidRATLSConfigClaims)
	if claimsDER == nil {
		return nil, fmt.Errorf("cds-identity: certificate carries no config-claims extension (%s), "+
			"so it vouches for no mesh CA or allowlist and cannot serve as a trust root", oidRATLSConfigClaims)
	}

	var raw attestationASN1
	rest, err := asn1.Unmarshal(attExt, &raw)
	if err != nil {
		return nil, fmt.Errorf("cds-identity: unmarshal attestation extension: %w", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("cds-identity: %d trailing bytes after attestation extension", len(rest))
	}

	// TDX always carries a JSON attestation-api envelope in the extension.
	envelope := bytes.TrimSpace(raw.Report)
	if len(envelope) == 0 || envelope[0] != '{' {
		return nil, fmt.Errorf("cds-identity: attestation extension carries no JSON evidence envelope; " +
			"only envelope-carrying platforms (TDX, az-snp) can be verified here")
	}
	var evidence teetypes.AttestationEvidence
	if err := json.Unmarshal(envelope, &evidence); err != nil {
		return nil, fmt.Errorf("cds-identity: parse evidence envelope: %w", err)
	}

	// REPORTDATA must bind BOTH this certificate's public key and the exact
	// claims bytes it carries. Binding the key alone would let an attacker
	// graft a different claims extension onto genuine evidence and have it
	// read as attested.
	expected, err := reportDataForKeyAndClaims(cert.PublicKey, claimsDER)
	if err != nil {
		return nil, err
	}

	wantRTMR3, err := rtmr3Pin(policy.ExpectedRTMR3, string(evidence.Platform))
	if err != nil {
		return nil, err
	}

	res, err := teeverify.Verify(attExt2Evidence(evidence), teetypes.VerifyParams{ExpectedReportData: expected})
	if err != nil {
		return nil, fmt.Errorf("cds-identity (%s): %w", evidence.Platform, err)
	}

	if err := checkMeasurement(res.Claims.LaunchDigest, policy.Measurements); err != nil {
		return nil, fmt.Errorf("cds-identity: %w", err)
	}
	if wantRTMR3 != nil {
		if err := checkRTMR3Claim(res.Claims.PlatformData, wantRTMR3); err != nil {
			return nil, fmt.Errorf("cds-identity: %w", err)
		}
	}

	claims, err := parseConfigClaims(claimsDER)
	if err != nil {
		return nil, err
	}

	return &CDSIdentity{
		Fingerprint:     sha256.Sum256(cert.Raw),
		LaunchDigest:    res.Claims.LaunchDigest,
		MeshCADigest:    claims.MeshCADigest,
		AllowlistDigest: claims.AllowlistDigest,
		NotAfter:        cert.NotAfter,
	}, nil
}

// attExt2Evidence re-encodes the envelope for teeverify, matching how the
// endpoint attester hands evidence to the same verifier.
func attExt2Evidence(e teetypes.AttestationEvidence) []byte {
	out, err := json.Marshal(e)
	if err != nil {
		// teetypes.AttestationEvidence round-trips by construction; a failure
		// here would mean the struct changed shape underneath us.
		return nil
	}
	return out
}

// VerifyMeshCA checks a served mesh CA against the digest CDS attested to
// issuing under, and returns a pool anchored on it. This is the step that
// retires the out-of-band pin: the CA is accepted because attested hardware
// vouched for its digest, not because someone sent you the file.
func (id *CDSIdentity) VerifyMeshCA(caPEM []byte) (*x509.CertPool, error) {
	if !hasDigest(id.MeshCADigest) {
		return nil, fmt.Errorf("cds-identity: attested claims carry no mesh-CA digest (claims v1), " +
			"so the mesh CA cannot be derived from them — pin it out of band")
	}
	block, _ := pem.Decode(caPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("cds-identity: mesh CA is not a PEM CERTIFICATE")
	}
	got := sha256.Sum256(block.Bytes)
	if !bytes.Equal(got[:], id.MeshCADigest) {
		return nil, fmt.Errorf("cds-identity: served mesh CA digest %x does not match the attested value %x — "+
			"this CA is not the one the verified CDS issues under "+
			"(note CDS regenerates its mesh CA on restart, and the LB serves a cached copy until get-cert renews)",
			got[:], id.MeshCADigest)
	}
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("cds-identity: parse mesh CA: %w", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return pool, nil
}

// VerifyAllowlist checks the EXACT bytes of a GET /allowlist response against
// the attested live-allowlist digest.
//
// The raw response is hashed verbatim, with no parsing or re-serialization:
// CDS commits SHA-256 of the canonical bytes it serves, so re-encoding here
// would compute a different digest for semantically identical content and the
// mismatch would look like tampering rather than a serialization bug.
func (id *CDSIdentity) VerifyAllowlist(raw []byte) error {
	if !hasDigest(id.AllowlistDigest) {
		return fmt.Errorf("cds-identity: attested claims carry no live-allowlist digest (claims v1/v2), " +
			"so the served allowlist cannot be checked against them")
	}
	got := sha256.Sum256(raw)
	if !bytes.Equal(got[:], id.AllowlistDigest) {
		return fmt.Errorf("cds-identity: served allowlist digest %x does not match the attested value %x — "+
			"the admission policy served is not the one CDS attested to (hash the raw response bytes, "+
			"not a re-serialized copy)", got[:], id.AllowlistDigest)
	}
	return nil
}

// reportDataForKeyAndClaims recomputes the REPORTDATA transcript c8s binds:
//
//	SHA-384( "c8s/config-claims/v1\0" || framed(pubkey) || framed(claims) || framed(nonce) )
//
// where framed(x) is an 8-byte big-endian length followed by x, and the nonce
// is empty for a self-signed serving certificate (c8s pkg/ratls provider.go
// passes nil). Domain separation plus length framing is what stops the fields
// being re-split into an equivalent byte stream.
func reportDataForKeyAndClaims(pub any, claims []byte) ([]byte, error) {
	keyBytes, err := marshalPublicKey(pub)
	if err != nil {
		return nil, err
	}
	h := sha512.New384()
	h.Write(claimsDomainSep)
	for _, field := range [][]byte{keyBytes, claims, nil} {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(field)))
		h.Write(size[:])
		h.Write(field)
	}
	return h.Sum(nil), nil
}

func marshalPublicKey(pub any) ([]byte, error) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		return x509.MarshalPKIXPublicKey(k)
	case ed25519.PublicKey:
		return []byte(k), nil
	default:
		return nil, fmt.Errorf("cds-identity: unsupported key type %T", pub)
	}
}

// parseConfigClaims decodes the config-claims extension, accepting v1, v2 and
// v3. Fields absent from an older version read as the sentinel, so a client
// asking for a property those claims never carried gets an explicit failure
// rather than a zero value that quietly compares equal to nothing.
func parseConfigClaims(der []byte) (*configClaims, error) {
	var probe struct {
		Version int
		Rest    asn1.RawValue `asn1:"optional"`
	}
	if _, err := asn1.Unmarshal(der, &probe); err != nil {
		return nil, fmt.Errorf("cds-identity: unmarshal config claims: %w", err)
	}

	var out *configClaims
	switch probe.Version {
	case 3:
		var raw claimsV3
		if err := unmarshalExact(der, &raw, 3); err != nil {
			return nil, err
		}
		out = &configClaims{raw.OperatorKeysDigest, raw.SeedDigest, raw.WorkloadDigest, raw.MeshCADigest, raw.AllowlistDigest}
	case 2:
		var raw claimsV2
		if err := unmarshalExact(der, &raw, 2); err != nil {
			return nil, err
		}
		out = &configClaims{raw.OperatorKeysDigest, raw.SeedDigest, raw.WorkloadDigest, raw.MeshCADigest, append([]byte(nil), unsetDigest...)}
	case 1:
		var raw claimsV1
		if err := unmarshalExact(der, &raw, 1); err != nil {
			return nil, err
		}
		out = &configClaims{raw.OperatorKeysDigest, raw.SeedDigest, raw.WorkloadDigest, append([]byte(nil), unsetDigest...), append([]byte(nil), unsetDigest...)}
	default:
		return nil, fmt.Errorf("cds-identity: unsupported config-claims version %d (supported: 1, 2, 3) — "+
			"the cluster is newer than this build; upgrade teerminator rather than ignoring the claims", probe.Version)
	}

	for _, d := range [][]byte{out.OperatorKeysDigest, out.SeedDigest, out.WorkloadDigest, out.MeshCADigest, out.AllowlistDigest} {
		if len(d) != claimsDigestSize {
			return nil, fmt.Errorf("cds-identity: config-claims digest is %d bytes, want %d", len(d), claimsDigestSize)
		}
	}
	return out, nil
}

// unmarshalExact requires the input to be the ONE canonical encoding of that
// shape. encoding/asn1 tolerates trailing elements and non-minimal encodings;
// demanding a byte-exact round-trip keeps "parses as vN" equivalent to "is the
// vN encoding", which matters because REPORTDATA binds these raw bytes.
func unmarshalExact(der []byte, v any, version int) error {
	rest, err := asn1.Unmarshal(der, v)
	if err != nil {
		return fmt.Errorf("cds-identity: unmarshal v%d config claims: %w", version, err)
	}
	if len(rest) > 0 {
		return fmt.Errorf("cds-identity: %d trailing bytes after config-claims extension", len(rest))
	}
	reencoded, err := asn1.Marshal(derefForMarshal(v))
	if err != nil {
		return fmt.Errorf("cds-identity: re-encode config claims: %w", err)
	}
	if !bytes.Equal(reencoded, der) {
		return fmt.Errorf("cds-identity: config-claims extension is not the exact v%d encoding", version)
	}
	return nil
}

// derefForMarshal dereferences the pointer asn1.Unmarshal required, since
// asn1.Marshal rejects pointers.
func derefForMarshal(v any) any {
	switch t := v.(type) {
	case *claimsV1:
		return *t
	case *claimsV2:
		return *t
	case *claimsV3:
		return *t
	default:
		return v
	}
}

func extensionValue(cert *x509.Certificate, oid asn1.ObjectIdentifier) []byte {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oid) {
			return ext.Value
		}
	}
	return nil
}

func hasDigest(d []byte) bool {
	return len(d) == claimsDigestSize && !bytes.Equal(d, unsetDigest)
}

// rtmr3Pin parses an RTMR[3] pin and refuses one the platform cannot enforce,
// mirroring the endpoint attester: a pin silently dropped reads as enforced.
func rtmr3Pin(hexPin, platform string) ([]byte, error) {
	if hexPin == "" {
		return nil, nil
	}
	want, err := parseRTMR3(hexPin)
	if err != nil {
		return nil, err
	}
	if platform != string(teetypes.PlatformTDX) {
		return nil, fmt.Errorf("cds-identity: CDS platform is %q but expected_rtmr3 is set: "+
			"the runtime measurement register is TDX-only and the pin cannot be enforced here", platform)
	}
	return want, nil
}

// checkRTMR3Claim compares the signature-verified rtmr_3 claim. Read off the
// quote body rather than passed to the verifier as an RTMR pin, because
// go-tdx-guest numbers registers 1-4 and reports RTMR[3] as "RTMR[4]" — which
// reads like a hardware fault instead of the identity mismatch it is.
func checkRTMR3Claim(platformData map[string]any, want []byte) error {
	got, _ := platformData["rtmr_3"].(string)
	got = strings.ToLower(strings.TrimSpace(got))
	if got == "" {
		return fmt.Errorf("quote carries no rtmr_3, so expected_rtmr3 cannot be enforced")
	}
	gotBytes, err := hex.DecodeString(got)
	if err != nil {
		return fmt.Errorf("rtmr_3 claim is malformed (%q)", got)
	}
	if !bytes.Equal(gotBytes, want) {
		return fmt.Errorf("RTMR[3] mismatch: CDS reports %s, expected %s "+
			"(this is not the deployment the pin was taken from)", got, hex.EncodeToString(want))
	}
	return nil
}

// DeriveMeshCA performs the attest-once step end to end: fetch CDS's own
// certificate from the LB's discovery document, verify its attestation against
// policy, then fetch the served mesh CA and accept it only if it matches the
// digest those verified claims commit to.
//
// This is what replaces `certs add mesh-ca.pem`. The CA is no longer trusted
// because an operator sent you the file; it is trusted because attested
// hardware, running a measured CDS, vouched for its digest. Both fetches may
// traverse untrusted transport: the certificate is self-authenticating and the
// CA is checked against an attested digest, so tampering only causes failure.
//
// Returns the CA PEM to store and the verified identity — whose Fingerprint is
// the cache key to re-attest on, since CDS re-issues on every allowlist change.
func DeriveMeshCA(
	ctx context.Context,
	client *http.Client,
	discoveryURL, meshCAURL string,
	policy CDSPolicy,
) ([]byte, *CDSIdentity, error) {
	certPEM, err := FetchCDSIdentityPEM(ctx, client, discoveryURL)
	if err != nil {
		return nil, nil, err
	}
	id, err := AttestCDSIdentity(certPEM, policy)
	if err != nil {
		return nil, nil, err
	}

	caPEM, err := fetchPEM(ctx, client, meshCAURL)
	if err != nil {
		return nil, nil, fmt.Errorf("cds-identity: fetch mesh CA: %w", err)
	}
	if _, err := id.VerifyMeshCA(caPEM); err != nil {
		return nil, nil, err
	}
	return caPEM, id, nil
}

func fetchPEM(ctx context.Context, client *http.Client, rawURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck // read-only
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s returned %d", rawURL, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}
