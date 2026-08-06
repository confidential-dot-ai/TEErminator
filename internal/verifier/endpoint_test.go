package verifier

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	_ "embed"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/TEErminator/internal/config"
	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

//go:embed testdata/attestation.json
var azSnpFixture []byte

//go:embed testdata/attest_lb_transcript_vectors.json
var transcriptVectors []byte

// TestAttestLBTranscriptGoldenVectors pins the report_data construction to the
// golden vectors in testdata — a verbatim copy of c8s
// pkg/overenc/testdata/attest_lb_transcript_vectors.json, so this client and
// the c8s server cannot drift on the transcript. The browser client is NOT a
// third party to these: c8s-verify-js implements no attest-lb flow (its
// PROTOCOL.md scopes the endpoint to native clients and src/verify.ts rejects
// the binding identifier), so only the matched-workload golden DER is shared
// three ways.
func TestAttestLBTranscriptGoldenVectors(t *testing.T) {
	var vectors []struct {
		Description       string `json:"description"`
		NonceB64          string `json:"nonce_b64"`
		ServingLeafDERB64 string `json:"serving_leaf_der_b64"`
		MeshLeafDERB64    string `json:"mesh_leaf_der_b64"`
		MeshCADERB64      string `json:"mesh_ca_der_b64"`
		ReportDataB64     string `json:"report_data_b64"`
	}
	if err := json.Unmarshal(transcriptVectors, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) == 0 {
		t.Fatal("no vectors")
	}
	unb64 := func(s string) []byte {
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	for _, v := range vectors {
		t.Run(v.Description, func(t *testing.T) {
			got := attestLBReportData(unb64(v.NonceB64), unb64(v.ServingLeafDERB64), unb64(v.MeshLeafDERB64), unb64(v.MeshCADERB64))
			if want := unb64(v.ReportDataB64); !bytes.Equal(got[:], want) {
				t.Fatalf("report_data = %x, want %x", got, want)
			}
		})
	}
}

// certAndKey is one minted fixture certificate.
type certAndKey struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

var fixtureSerial int64 = 1000

func mintCert(t *testing.T, tmpl *x509.Certificate, parent *certAndKey, curve elliptic.Curve) *certAndKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fixtureSerial++
	tmpl.SerialNumber = big.NewInt(fixtureSerial)
	// A caller that presets the window keeps it (the validity tests do); every
	// other fixture gets the default comfortably-valid one.
	if tmpl.NotBefore.IsZero() {
		tmpl.NotBefore = time.Now().Add(-time.Hour)
	}
	if tmpl.NotAfter.IsZero() {
		tmpl.NotAfter = time.Now().Add(time.Hour)
	}
	signerCert, signerKey := tmpl, key
	if parent != nil {
		signerCert, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signerCert, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pemEncodeCert(der)
	return &certAndKey{cert: cert, key: key, pem: pemBytes}
}

func pemEncodeCert(der []byte) []byte {
	b64 := base64.StdEncoding.EncodeToString(der)
	var sb strings.Builder
	sb.WriteString("-----BEGIN CERTIFICATE-----\n")
	for len(b64) > 64 {
		sb.WriteString(b64[:64] + "\n")
		b64 = b64[64:]
	}
	sb.WriteString(b64 + "\n-----END CERTIFICATE-----\n")
	return []byte(sb.String())
}

func mintCA(t *testing.T, cn string) *certAndKey {
	return mintCert(t, &x509.Certificate{
		Subject:               pkix.Name{CommonName: cn},
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}, nil, elliptic.P384())
}

func mintLeaf(t *testing.T, ca *certAndKey, cn string, exts []pkix.Extension) *certAndKey {
	return mintCert(t, &x509.Certificate{
		Subject:         pkix.Name{CommonName: cn},
		DNSNames:        []string{cn},
		IPAddresses:     []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		ExtraExtensions: exts,
	}, ca, elliptic.P256())
}

// defaultAllowlistRaw is the pinned canonical-allowlist document the default
// fixture stamp commits to (hashed exactly as these bytes).
var defaultAllowlistRaw = []byte(`{"schema":"c8s.allowlist/v1","workloads":{"api":{"containers":[]}}}`)

func stampExt(t *testing.T, name, version string, digest []byte) pkix.Extension {
	t.Helper()
	value, err := asn1.Marshal(matchedWorkloadASN1{
		FormatVersion:    1,
		Name:             name,
		AllowlistVersion: version,
		AllowlistDigest:  digest,
	})
	if err != nil {
		t.Fatal(err)
	}
	return pkix.Extension{Id: oidMatchedWorkload, Value: value}
}

// lbFixture is a full in-test chain: mesh CA -> mesh leaf (stamped) and
// -> serving leaf, plus the allowlist bytes the stamp commits to.
type lbFixture struct {
	ca           *certAndKey
	mesh         *certAndKey
	serving      *certAndKey
	allowlistRaw []byte
}

type fixtureOpts struct {
	allowlistRaw []byte           // default defaultAllowlistRaw
	stampExts    []pkix.Extension // default: golden stamp {v1,"api","7",SHA-256(allowlistRaw)}
	noStamp      bool
	servingCA    *certAndKey // default: the fixture CA
	meshCA       *certAndKey // default: the fixture CA
}

func newLBFixture(t *testing.T, opts fixtureOpts) *lbFixture {
	t.Helper()
	f := &lbFixture{allowlistRaw: opts.allowlistRaw}
	if f.allowlistRaw == nil {
		f.allowlistRaw = defaultAllowlistRaw
	}
	f.ca = mintCA(t, "mesh-ca")
	exts := opts.stampExts
	if exts == nil && !opts.noStamp {
		digest := sha256.Sum256(f.allowlistRaw)
		exts = []pkix.Extension{stampExt(t, "api", "7", digest[:])}
	}
	meshCA := opts.meshCA
	if meshCA == nil {
		meshCA = f.ca
	}
	servingCA := opts.servingCA
	if servingCA == nil {
		servingCA = f.ca
	}
	f.mesh = mintLeaf(t, meshCA, "mesh-leaf", exts)
	f.serving = mintLeaf(t, servingCA, "serving-leaf", nil)
	return f
}

// bundleSpec controls what the fixture LB serves; the zero value is the honest
// bundle for the fixture.
type bundleSpec struct {
	version    string // default attestLBVersion
	platform   string // default "test"
	echoNonce  string // default: echo the request nonce
	servingDER []byte // DER committed into the transcript; default: the actual serving leaf
	cdsPEM     string // default: mesh leaf PEM + CA PEM
	algorithm  string // default "ecdsa-sha384"
	meshCAHash []byte // default SHA-256(CA DER)
	signKey    *ecdsa.PrivateKey
	breakSig   bool
	evidence   func(reportData []byte) json.RawMessage // default: stub shape {"report_data": ...}
}

// newServer serves the attest-lb bundle over TLS with the fixture's serving
// certificate as the server certificate — the test server's TLS cert IS the
// serving leaf the evidence commits to.
func (f *lbFixture) newServer(t *testing.T, spec bundleSpec) *httptest.Server {
	t.Helper()
	handler := func(w http.ResponseWriter, r *http.Request) {
		nonceB64 := r.URL.Query().Get("nonce")
		nonce, err := base64.RawURLEncoding.DecodeString(nonceB64)
		if err != nil {
			http.Error(w, "bad nonce", http.StatusBadRequest)
			return
		}
		servingDER := spec.servingDER
		if servingDER == nil {
			servingDER = f.serving.cert.Raw
		}
		reportData := attestLBReportData(nonce, servingDER, f.mesh.cert.Raw, f.ca.cert.Raw)
		digest := sha512.Sum384(reportData[:])
		signKey := spec.signKey
		if signKey == nil {
			signKey = f.mesh.key
		}
		sig, err := ecdsa.SignASN1(rand.Reader, signKey, digest[:])
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if spec.breakSig {
			sig[len(sig)-1] ^= 0x01
		}
		version := spec.version
		if version == "" {
			version = attestLBVersion
		}
		platform := spec.platform
		if platform == "" {
			platform = "test"
		}
		echo := spec.echoNonce
		if echo == "" {
			echo = nonceB64
		}
		cdsPEM := spec.cdsPEM
		if cdsPEM == "" {
			cdsPEM = string(f.mesh.pem) + string(f.ca.pem)
		}
		algorithm := spec.algorithm
		if algorithm == "" {
			algorithm = proofAlgorithmECDSASHA384
		}
		caHash := spec.meshCAHash
		if caHash == nil {
			sum := sha256.Sum256(f.ca.cert.Raw)
			caHash = sum[:]
		}
		evidence := spec.evidence
		if evidence == nil {
			evidence = func(rd []byte) json.RawMessage {
				j, _ := json.Marshal(map[string]string{"report_data": base64.RawURLEncoding.EncodeToString(rd)})
				return j
			}
		}
		meshSum := sha256.Sum256(f.mesh.cert.Raw)
		servingSum := sha256.Sum256(servingDER)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"version":      version,
			"platform":     platform,
			"generation":   1,
			"nonce":        echo,
			"evidence":     evidence(reportData[:]),
			"cds_cert_pem": cdsPEM,
			"identity_proof": map[string]string{
				"algorithm":      algorithm,
				"leaf_sha256":    base64.RawURLEncoding.EncodeToString(meshSum[:]),
				"mesh_ca_sha256": base64.RawURLEncoding.EncodeToString(caHash),
				"signature":      base64.RawURLEncoding.EncodeToString(sig),
			},
			"serving_leaf_sha256": base64.RawURLEncoding.EncodeToString(servingSum[:]),
		})
	}
	ts := httptest.NewUnstartedServer(http.HandlerFunc(handler))
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{{
		Certificate: [][]byte{f.serving.cert.Raw},
		PrivateKey:  f.serving.key,
	}}}
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ts
}

// stubClaims parameterizes the evidence stub's verified result; the zero value
// yields launch digest "a1" with no platform-specific claims. The result's
// Platform always echoes the bundle's tag, as the real verifier does.
type stubClaims struct {
	launchDigest string
	platformData map[string]any
	tcb          teetypes.TcbInfo
}

// stubCalls records what the attester handed the evidence seam.
type stubCalls struct {
	minTCB *teetypes.SnpTcb
}

// stubEvidence swaps the evidence-verification seam for a stub that only
// checks the bundle's report_data against the client's recomputed transcript,
// so the full ordered attest-lb flow runs without live hardware evidence.
func stubEvidence(t *testing.T) {
	stubEvidenceClaims(t, stubClaims{})
}

// stubEvidenceClaims is stubEvidence with a configurable verified result, and
// returns a recorder of what reached the seam.
func stubEvidenceClaims(t *testing.T, sc stubClaims) *stubCalls {
	t.Helper()
	if sc.launchDigest == "" {
		sc.launchDigest = "a1"
	}
	calls := &stubCalls{}
	orig := verifyEvidence
	verifyEvidence = func(b attestationBundle, expected []byte, minTCB *teetypes.SnpTcb) (*teetypes.VerificationResult, error) {
		calls.minTCB = minTCB
		var ev struct {
			ReportData string `json:"report_data"`
		}
		if err := json.Unmarshal(b.Evidence, &ev); err != nil {
			return nil, err
		}
		got, err := base64.RawURLEncoding.DecodeString(ev.ReportData)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(got, expected) {
			return nil, errors.New("stub evidence: report_data does not match the recomputed transcript")
		}
		return &teetypes.VerificationResult{
			SignatureValid: true,
			Platform:       teetypes.PlatformType(b.Platform),
			Claims: teetypes.Claims{
				LaunchDigest: sc.launchDigest,
				TCB:          sc.tcb,
				PlatformData: sc.platformData,
			},
		}, nil
	}
	t.Cleanup(func() { verifyEvidence = orig })
	return calls
}

// newLBAttester builds an attester against ts, mirroring the proxy's attest-lb
// trust construction: no TLS-layer PKI verification — trust is deferred
// entirely to the attest-lb verification of the observed leaf.
func newLBAttester(t *testing.T, ts *httptest.Server, remote config.Remote, pinnedCAs []*x509.Certificate) *EndpointAttester {
	t.Helper()
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	ea, err := NewEndpointAttester(ts.URL, client, remote, pinnedCAs)
	if err != nil {
		t.Fatal(err)
	}
	return ea
}

// measuredRemote is the minimal valid attest-lb policy; the uppercase digest
// exercises the case-insensitive membership check against the stub's "a1".
func measuredRemote() config.Remote {
	return config.Remote{Mode: config.AttestEndpoint, Measurements: []string{"A1"}}
}

func TestAttestLBHappyPath(t *testing.T) {
	stubEvidence(t)
	f := newLBFixture(t, fixtureOpts{})
	ts := f.newServer(t, bundleSpec{})

	t.Run("deployment-class without CA pin", func(t *testing.T) {
		ea := newLBAttester(t, ts, measuredRemote(), nil)
		v, err := ea.Attest(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if v.Measurement != "a1" {
			t.Errorf("Measurement = %q", v.Measurement)
		}
		if v.TrustMode != TrustDeploymentClass {
			t.Errorf("TrustMode = %q, want %q", v.TrustMode, TrustDeploymentClass)
		}
		if v.Profile != ProfileCAVouched {
			t.Errorf("Profile = %q, want %q", v.Profile, ProfileCAVouched)
		}
		if want := sha256.Sum256(f.serving.cert.Raw); v.LeafSHA256 != want {
			t.Errorf("LeafSHA256 does not pin the exact serving-leaf DER")
		}
		if v.WorkloadName != "" || v.AllowlistVersion != "" {
			t.Errorf("unpinned verdict carries workload fields: %+v", v)
		}
	})

	t.Run("specific-cluster with matching CA pin", func(t *testing.T) {
		ea := newLBAttester(t, ts, measuredRemote(), []*x509.Certificate{f.ca.cert})
		v, err := ea.Attest(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if v.TrustMode != TrustSpecificCluster {
			t.Errorf("TrustMode = %q, want %q", v.TrustMode, TrustSpecificCluster)
		}
	})

	t.Run("non-matching CA pin stays deployment-class", func(t *testing.T) {
		other := mintCA(t, "other-ca")
		ea := newLBAttester(t, ts, measuredRemote(), []*x509.Certificate{other.cert})
		v, err := ea.Attest(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if v.TrustMode != TrustDeploymentClass {
			t.Errorf("TrustMode = %q, want %q", v.TrustMode, TrustDeploymentClass)
		}
	})
}

func TestAttestLBRejectsWrongVersion(t *testing.T) {
	stubEvidence(t)
	f := newLBFixture(t, fixtureOpts{})
	for _, version := range []string{"c8s-verify/v1", "c8s/attest-pq/v1"} {
		t.Run(version, func(t *testing.T) {
			ts := f.newServer(t, bundleSpec{version: version})
			ea := newLBAttester(t, ts, measuredRemote(), nil)
			_, err := ea.Attest(context.Background())
			if err == nil || !strings.Contains(err.Error(), version) || !strings.Contains(err.Error(), attestLBVersion) {
				t.Fatalf("want version-mismatch error naming %q and %q, got %v", version, attestLBVersion, err)
			}
		})
	}
}

func TestAttestLBRejectsNonceMismatch(t *testing.T) {
	stubEvidence(t)
	f := newLBFixture(t, fixtureOpts{})
	ts := f.newServer(t, bundleSpec{echoNonce: "bm90LXRoZS1ub25jZQ"})
	ea := newLBAttester(t, ts, measuredRemote(), nil)
	_, err := ea.Attest(context.Background())
	if err == nil || !strings.Contains(err.Error(), "nonce mismatch") {
		t.Fatalf("want nonce mismatch error, got %v", err)
	}
}

func TestAttestLBRejectsTamperedServingLeaf(t *testing.T) {
	stubEvidence(t)
	f := newLBFixture(t, fixtureOpts{})
	// The evidence commits to a slightly different DER than the certificate the
	// connection actually presents.
	tampered := append([]byte(nil), f.serving.cert.Raw...)
	tampered[len(tampered)-1] ^= 0x01
	ts := f.newServer(t, bundleSpec{servingDER: tampered})
	ea := newLBAttester(t, ts, measuredRemote(), nil)
	_, err := ea.Attest(context.Background())
	if err == nil || !strings.Contains(err.Error(), "transcript") {
		t.Fatalf("want transcript mismatch, got %v", err)
	}
}

func TestAttestLBRejectsRelayedBundle(t *testing.T) {
	stubEvidence(t)
	f := newLBFixture(t, fixtureOpts{})
	// A genuine bundle minted for another serving leaf under the SAME issuer,
	// relayed through this connection: exact-DER binding must reject it.
	genuine := mintLeaf(t, f.ca, "genuine-front-door", nil)
	ts := f.newServer(t, bundleSpec{servingDER: genuine.cert.Raw})
	ea := newLBAttester(t, ts, measuredRemote(), nil)
	_, err := ea.Attest(context.Background())
	if err == nil || !strings.Contains(err.Error(), "transcript") {
		t.Fatalf("want transcript mismatch for relayed bundle, got %v", err)
	}
}

func TestAttestLBRejectsUnknownCommittedCA(t *testing.T) {
	stubEvidence(t)
	f := newLBFixture(t, fixtureOpts{})
	bogus := sha256.Sum256([]byte("not-a-served-ca"))
	ts := f.newServer(t, bundleSpec{meshCAHash: bogus[:]})
	ea := newLBAttester(t, ts, measuredRemote(), nil)
	_, err := ea.Attest(context.Background())
	if err == nil || !strings.Contains(err.Error(), "no served CA matches") {
		t.Fatalf("want committed-CA selection failure, got %v", err)
	}
}

func TestAttestLBRejectsBadProof(t *testing.T) {
	stubEvidence(t)
	f := newLBFixture(t, fixtureOpts{})

	t.Run("broken signature", func(t *testing.T) {
		ts := f.newServer(t, bundleSpec{breakSig: true})
		ea := newLBAttester(t, ts, measuredRemote(), nil)
		_, err := ea.Attest(context.Background())
		if err == nil || !strings.Contains(err.Error(), "identity proof signature") {
			t.Fatalf("want proof signature failure, got %v", err)
		}
	})

	t.Run("wrong key", func(t *testing.T) {
		other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		ts := f.newServer(t, bundleSpec{signKey: other})
		ea := newLBAttester(t, ts, measuredRemote(), nil)
		if _, err := ea.Attest(context.Background()); err == nil || !strings.Contains(err.Error(), "identity proof signature") {
			t.Fatalf("want proof signature failure, got %v", err)
		}
	})

	t.Run("wrong algorithm", func(t *testing.T) {
		ts := f.newServer(t, bundleSpec{algorithm: "ecdsa-sha256"})
		ea := newLBAttester(t, ts, measuredRemote(), nil)
		if _, err := ea.Attest(context.Background()); err == nil || !strings.Contains(err.Error(), "algorithm") {
			t.Fatalf("want algorithm error, got %v", err)
		}
	})
}

func TestAttestLBRejectsMeshLeafNotChaining(t *testing.T) {
	stubEvidence(t)
	foreign := mintCA(t, "foreign-ca")
	f := newLBFixture(t, fixtureOpts{meshCA: foreign})
	ts := f.newServer(t, bundleSpec{})
	ea := newLBAttester(t, ts, measuredRemote(), nil)
	_, err := ea.Attest(context.Background())
	if err == nil || !strings.Contains(err.Error(), "mesh leaf") {
		t.Fatalf("want mesh-leaf chain failure, got %v", err)
	}
}

func TestAttestLBRejectsServingLeafNotChaining(t *testing.T) {
	stubEvidence(t)
	foreign := mintCA(t, "foreign-ca")
	f := newLBFixture(t, fixtureOpts{servingCA: foreign})
	ts := f.newServer(t, bundleSpec{})
	ea := newLBAttester(t, ts, measuredRemote(), nil)
	_, err := ea.Attest(context.Background())
	if err == nil || !strings.Contains(err.Error(), "serving leaf") {
		t.Fatalf("want serving-leaf chain failure, got %v", err)
	}
}

func TestAttestLBEmptyMeasurementsIsConfigError(t *testing.T) {
	stubEvidence(t)
	f := newLBFixture(t, fixtureOpts{})
	ts := f.newServer(t, bundleSpec{})
	ea := newLBAttester(t, ts, config.Remote{Mode: config.AttestEndpoint}, nil)
	_, err := ea.Attest(context.Background())
	if err == nil || !strings.Contains(err.Error(), "configuration error") {
		t.Fatalf("want empty-measurement configuration error, got %v", err)
	}
}

func TestAttestLBRejectsMeasurementNotInAllowlist(t *testing.T) {
	stubEvidence(t)
	f := newLBFixture(t, fixtureOpts{})
	ts := f.newServer(t, bundleSpec{})
	remote := config.Remote{Mode: config.AttestEndpoint, Measurements: []string{"deadbeef"}}
	ea := newLBAttester(t, ts, remote, nil)
	_, err := ea.Attest(context.Background())
	if err == nil || !strings.Contains(err.Error(), "not in the allowlist") {
		t.Fatalf("want measurement rejection, got %v", err)
	}
}

// TestCheckMeasurementValidatesHex covers the launch digest as a VALUE rather
// than as a string: an empty allowlist is already a configuration error, but
// `--measurements ""` yields one empty entry, which is not empty as a list and
// would string-match a platform whose LaunchDigest claim came back empty.
func TestCheckMeasurementValidatesHex(t *testing.T) {
	for _, tc := range []struct {
		name        string
		measurement string
		allowed     []string
		wantErr     string
	}{
		{"match", "aabb", []string{"AABB"}, ""},
		{"no match", "aabb", []string{"ccdd"}, "not in the allowlist"},
		{"empty allowlist", "aabb", nil, "empty measurement policy"},
		{"empty allowlist entry", "aabb", []string{""}, "not a non-empty hex launch digest"},
		{"non-hex allowlist entry", "aabb", []string{"zz"}, "not a non-empty hex launch digest"},
		{"empty claim against an empty entry", "", []string{""}, "not a non-empty hex launch digest"},
		{"empty claim", "", []string{"aabb"}, "launch_digest is missing or malformed"},
		{"non-hex claim", "not-a-digest", []string{"aabb"}, "launch_digest is missing or malformed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkMeasurement(tc.measurement, tc.allowed)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("checkMeasurement = %v, want it accepted", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("checkMeasurement = %v, want an error containing %q", err, tc.wantErr)
			}
		})
	}
}

// writeAllowlist writes raw to a temp file and returns its path.
func writeAllowlist(t *testing.T, raw []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "allowlist.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestAttestLBWorkloadPolicy(t *testing.T) {
	stubEvidence(t)

	attest := func(t *testing.T, f *lbFixture, remote config.Remote) (*SessionVerdict, error) {
		t.Helper()
		remote.Mode = config.AttestEndpoint
		remote.Measurements = []string{"a1"}
		ts := f.newServer(t, bundleSpec{})
		ea := newLBAttester(t, ts, remote, nil)
		return ea.Attest(context.Background())
	}

	t.Run("name and allowlist pins match", func(t *testing.T) {
		f := newLBFixture(t, fixtureOpts{})
		v, err := attest(t, f, config.Remote{
			WorkloadName:  "api",
			AllowlistPath: writeAllowlist(t, f.allowlistRaw),
		})
		if err != nil {
			t.Fatal(err)
		}
		if v.WorkloadName != "api" || v.AllowlistVersion != "7" {
			t.Fatalf("verdict workload = %q v%q, want api v7", v.WorkloadName, v.AllowlistVersion)
		}
	})

	t.Run("name pin mismatch", func(t *testing.T) {
		f := newLBFixture(t, fixtureOpts{})
		_, err := attest(t, f, config.Remote{WorkloadName: "other"})
		if err == nil || !strings.Contains(err.Error(), `stamped for workload "api"`) {
			t.Fatalf("want name mismatch, got %v", err)
		}
	})

	t.Run("absent stamp fails closed", func(t *testing.T) {
		f := newLBFixture(t, fixtureOpts{noStamp: true})
		_, err := attest(t, f, config.Remote{WorkloadName: "api"})
		if err == nil || !strings.Contains(err.Error(), "no matched-workload stamp") {
			t.Fatalf("want absent-stamp failure, got %v", err)
		}
	})

	t.Run("malformed stamp fails closed", func(t *testing.T) {
		digest := sha256.Sum256(defaultAllowlistRaw)
		good := stampExt(t, "api", "7", digest[:])
		bad := pkix.Extension{Id: oidMatchedWorkload, Value: good.Value[:len(good.Value)-2]}
		f := newLBFixture(t, fixtureOpts{stampExts: []pkix.Extension{bad}})
		_, err := attest(t, f, config.Remote{WorkloadName: "api"})
		if err == nil || !strings.Contains(err.Error(), "workload policy") {
			t.Fatalf("want malformed-stamp failure, got %v", err)
		}
	})

	t.Run("allowlist digest mismatch", func(t *testing.T) {
		f := newLBFixture(t, fixtureOpts{})
		// Same document with one extra byte: digest of the exact file bytes differs.
		_, err := attest(t, f, config.Remote{
			WorkloadName:  "api",
			AllowlistPath: writeAllowlist(t, append(f.allowlistRaw, '\n')),
		})
		if err == nil || !strings.Contains(err.Error(), "digest does not match") {
			t.Fatalf("want digest mismatch, got %v", err)
		}
	})

	t.Run("stamped name unresolved in pinned allowlist", func(t *testing.T) {
		// The stamp commits to this exact document, but names a workload the
		// document does not contain.
		doc := []byte(`{"schema":"c8s.allowlist/v1","workloads":{"web":{"containers":[]}}}`)
		f := newLBFixture(t, fixtureOpts{allowlistRaw: doc})
		_, err := attest(t, f, config.Remote{AllowlistPath: writeAllowlist(t, doc)})
		if err == nil || !strings.Contains(err.Error(), "does not resolve") {
			t.Fatalf("want unresolved-name failure, got %v", err)
		}
	})
}

var rtmr3Hex = strings.Repeat("4d", RegisterSize)

// pinManifest writes an image manifest carrying the shared register fixtures
// (mrtdHex/rtmr1Hex/rtmr2Hex) and returns its path.
func pinManifest(t *testing.T) string {
	t.Helper()
	return writeManifest(t, `{"mrtd":"`+mrtdHex+`","rtmr1":"`+rtmr1Hex+`","rtmr2":"`+rtmr2Hex+`"}`)
}

// tdxStubClaims is the verified-claims shape of a TDX guest matching the
// shared register fixtures: launch digest MRTD, all runtime registers present.
func tdxStubClaims() stubClaims {
	return stubClaims{
		launchDigest: mrtdHex,
		platformData: map[string]any{
			"rtmr_0": strings.Repeat("00", RegisterSize),
			"rtmr_1": rtmr1Hex,
			"rtmr_2": rtmr2Hex,
			"rtmr_3": rtmr3Hex,
		},
	}
}

func TestAttestLBTDXImagePins(t *testing.T) {
	t.Run("happy path pins all three runtime registers", func(t *testing.T) {
		stubEvidenceClaims(t, tdxStubClaims())
		f := newLBFixture(t, fixtureOpts{})
		ts := f.newServer(t, bundleSpec{platform: "tdx"})
		// No --measurements: the manifest is the whole launch-digest policy —
		// MRTD is compared against it exactly, like RTMR[1]/[2].
		remote := config.Remote{
			Mode:              config.AttestEndpoint,
			ImageManifestPath: pinManifest(t),
			ExpectedRTMR3:     rtmr3Hex,
		}
		ea := newLBAttester(t, ts, remote, nil)
		v, err := ea.Attest(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if v.Measurement != mrtdHex {
			t.Errorf("Measurement = %q, want the manifest MRTD", v.Measurement)
		}
		if v.Platform != "tdx" {
			t.Errorf("Platform = %q, want tdx", v.Platform)
		}
		want := []string{"1:" + rtmr1Hex, "2:" + rtmr2Hex, "3:" + rtmr3Hex}
		if len(v.RTMRsPinned) != len(want) {
			t.Fatalf("RTMRsPinned = %v, want %v", v.RTMRsPinned, want)
		}
		for i := range want {
			if v.RTMRsPinned[i] != want[i] {
				t.Errorf("RTMRsPinned[%d] = %q, want %q", i, v.RTMRsPinned[i], want[i])
			}
		}
		if v.Warning != "" {
			t.Errorf("complete TDX policy must not warn, got %q", v.Warning)
		}
	})

	t.Run("RTMR mismatch fails", func(t *testing.T) {
		sc := tdxStubClaims()
		sc.platformData["rtmr_1"] = strings.Repeat("ee", RegisterSize)
		stubEvidenceClaims(t, sc)
		f := newLBFixture(t, fixtureOpts{})
		ts := f.newServer(t, bundleSpec{platform: "tdx"})
		remote := config.Remote{Mode: config.AttestEndpoint, ImageManifestPath: pinManifest(t)}
		ea := newLBAttester(t, ts, remote, nil)
		_, err := ea.Attest(context.Background())
		if err == nil || !strings.Contains(err.Error(), "RTMR[1]") {
			t.Fatalf("want RTMR[1] mismatch, got %v", err)
		}
	})

	t.Run("absent rtmr claim fails closed", func(t *testing.T) {
		sc := tdxStubClaims()
		delete(sc.platformData, "rtmr_2")
		stubEvidenceClaims(t, sc)
		f := newLBFixture(t, fixtureOpts{})
		ts := f.newServer(t, bundleSpec{platform: "tdx"})
		remote := config.Remote{Mode: config.AttestEndpoint, ImageManifestPath: pinManifest(t)}
		ea := newLBAttester(t, ts, remote, nil)
		_, err := ea.Attest(context.Background())
		if err == nil || !strings.Contains(err.Error(), "carry no rtmr_2") {
			t.Fatalf("want absent-claim failure, got %v", err)
		}
	})

	t.Run("absent rtmr3 claim fails closed", func(t *testing.T) {
		sc := tdxStubClaims()
		delete(sc.platformData, "rtmr_3")
		stubEvidenceClaims(t, sc)
		f := newLBFixture(t, fixtureOpts{})
		ts := f.newServer(t, bundleSpec{platform: "tdx"})
		remote := config.Remote{
			Mode:              config.AttestEndpoint,
			ImageManifestPath: pinManifest(t),
			ExpectedRTMR3:     rtmr3Hex,
		}
		ea := newLBAttester(t, ts, remote, nil)
		_, err := ea.Attest(context.Background())
		if err == nil || !strings.Contains(err.Error(), "carry no rtmr_3") {
			t.Fatalf("want absent-claim failure, got %v", err)
		}
	})

	// The MRTD is pinned EXACTLY against the manifest, not unioned into a
	// launch-digest allowlist. A guest whose firmware differs from the manifest
	// must fail even though its RTMR[1]/[2] match the manifest — that is the
	// combination a union admits, and it is a different image.
	t.Run("MRTD not matching the manifest fails", func(t *testing.T) {
		sc := tdxStubClaims()
		sc.launchDigest = strings.Repeat("9f", RegisterSize)
		stubEvidenceClaims(t, sc)
		f := newLBFixture(t, fixtureOpts{})
		ts := f.newServer(t, bundleSpec{platform: "tdx"})
		remote := config.Remote{Mode: config.AttestEndpoint, ImageManifestPath: pinManifest(t)}
		ea := newLBAttester(t, ts, remote, nil)
		_, err := ea.Attest(context.Background())
		if err == nil || !strings.Contains(err.Error(), "MRTD mismatch") {
			t.Fatalf("want an MRTD mismatch, got %v", err)
		}
	})

	t.Run("malformed launch digest fails closed", func(t *testing.T) {
		sc := tdxStubClaims()
		sc.launchDigest = "not-a-digest"
		stubEvidenceClaims(t, sc)
		f := newLBFixture(t, fixtureOpts{})
		ts := f.newServer(t, bundleSpec{platform: "tdx"})
		remote := config.Remote{Mode: config.AttestEndpoint, ImageManifestPath: pinManifest(t)}
		ea := newLBAttester(t, ts, remote, nil)
		_, err := ea.Attest(context.Background())
		if err == nil || !strings.Contains(err.Error(), "launch_digest is missing or malformed") {
			t.Fatalf("want a malformed-launch-digest failure, got %v", err)
		}
	})

	// An allowlist alongside a manifest can only name digests the manifest does
	// not: refusing the pair is what stopped the MRTD from being negotiable.
	t.Run("measurements alongside an image manifest is a config error", func(t *testing.T) {
		stubEvidenceClaims(t, tdxStubClaims())
		f := newLBFixture(t, fixtureOpts{})
		ts := f.newServer(t, bundleSpec{platform: "tdx"})
		remote := config.Remote{
			Mode:              config.AttestEndpoint,
			Measurements:      []string{strings.Repeat("9f", RegisterSize)},
			ImageManifestPath: pinManifest(t),
		}
		ea := newLBAttester(t, ts, remote, nil)
		_, err := ea.Attest(context.Background())
		if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
			t.Fatalf("want a mutually-exclusive configuration error, got %v", err)
		}
	})

	t.Run("TDX pins against SNP evidence fail closed", func(t *testing.T) {
		stubEvidence(t)
		f := newLBFixture(t, fixtureOpts{})
		ts := f.newServer(t, bundleSpec{platform: "snp"})
		remote := config.Remote{
			Mode:              config.AttestEndpoint,
			ImageManifestPath: pinManifest(t),
		}
		ea := newLBAttester(t, ts, remote, nil)
		_, err := ea.Attest(context.Background())
		if err == nil || !strings.Contains(err.Error(), `evidence platform is "snp"`) {
			t.Fatalf("want cross-platform failure naming snp, got %v", err)
		}
	})

	t.Run("malformed manifest is a config error before any round trip", func(t *testing.T) {
		stubEvidence(t)
		f := newLBFixture(t, fixtureOpts{})
		ts := f.newServer(t, bundleSpec{platform: "tdx"})
		remote := config.Remote{
			Mode:              config.AttestEndpoint,
			ImageManifestPath: writeManifest(t, `{"mrtd":"`+mrtdHex+`"}`),
		}
		ea := newLBAttester(t, ts, remote, nil)
		_, err := ea.Attest(context.Background())
		if err == nil || !strings.Contains(err.Error(), `missing "rtmr1"`) {
			t.Fatalf("want manifest load failure, got %v", err)
		}
	})
}

func p8(v uint8) *uint8 { return &v }

func snpStubTCB() teetypes.TcbInfo {
	return teetypes.TcbInfo{Type: "Snp", Bootloader: p8(4), Tee: p8(0), Snp: p8(8), Microcode: p8(210)}
}

func TestAttestLBMinTCB(t *testing.T) {
	floor := &config.TCBFloor{Bootloader: 3, TEE: 0, SNP: 8, Microcode: 209}
	remote := func() config.Remote {
		return config.Remote{Mode: config.AttestEndpoint, Measurements: []string{"a1"}, MinTCB: floor}
	}

	t.Run("floor reaches the verifier engine and passes on the claims", func(t *testing.T) {
		calls := stubEvidenceClaims(t, stubClaims{tcb: snpStubTCB()})
		f := newLBFixture(t, fixtureOpts{})
		ts := f.newServer(t, bundleSpec{platform: "snp"})
		ea := newLBAttester(t, ts, remote(), nil)
		v, err := ea.Attest(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		wantEngine := &teetypes.SnpTcb{Bootloader: 3, Tee: 0, Snp: 8, Microcode: 209}
		if calls.minTCB == nil || *calls.minTCB != *wantEngine {
			t.Errorf("engine received MinTCB %+v, want %+v", calls.minTCB, wantEngine)
		}
		if v.TCBFloor != "bootloader=3,tee=0,snp=8,microcode=209" {
			t.Errorf("TCBFloor = %q", v.TCBFloor)
		}
	})

	t.Run("claims below the floor fail", func(t *testing.T) {
		tcb := snpStubTCB()
		tcb.Microcode = p8(100)
		stubEvidenceClaims(t, stubClaims{tcb: tcb})
		f := newLBFixture(t, fixtureOpts{})
		ts := f.newServer(t, bundleSpec{platform: "snp"})
		ea := newLBAttester(t, ts, remote(), nil)
		_, err := ea.Attest(context.Background())
		if err == nil || !strings.Contains(err.Error(), "below the pinned minimum") {
			t.Fatalf("want floor violation, got %v", err)
		}
	})

	t.Run("absent TCB component fails closed", func(t *testing.T) {
		tcb := snpStubTCB()
		tcb.Snp = nil
		stubEvidenceClaims(t, stubClaims{tcb: tcb})
		f := newLBFixture(t, fixtureOpts{})
		ts := f.newServer(t, bundleSpec{platform: "snp"})
		ea := newLBAttester(t, ts, remote(), nil)
		_, err := ea.Attest(context.Background())
		if err == nil || !strings.Contains(err.Error(), "carry no snp TCB component") {
			t.Fatalf("want absent-component failure, got %v", err)
		}
	})

	t.Run("min-tcb against TDX evidence fails closed", func(t *testing.T) {
		stubEvidenceClaims(t, tdxStubClaims())
		f := newLBFixture(t, fixtureOpts{})
		ts := f.newServer(t, bundleSpec{platform: "tdx"})
		r := remote()
		r.Measurements = []string{mrtdHex}
		ea := newLBAttester(t, ts, r, nil)
		_, err := ea.Attest(context.Background())
		if err == nil || !strings.Contains(err.Error(), `evidence platform is "tdx"`) {
			t.Fatalf("want cross-platform failure naming tdx, got %v", err)
		}
	})
}

// TestAttestLBTDXCompleteness covers the TDX completeness rule: MRTD alone is
// not a complete image policy, so a deployment-class verdict without an image
// pin is refused, while a specific-cluster one passes with a warning.
func TestAttestLBTDXCompleteness(t *testing.T) {
	t.Run("deployment-class TDX without image manifest is a config error", func(t *testing.T) {
		stubEvidenceClaims(t, tdxStubClaims())
		f := newLBFixture(t, fixtureOpts{})
		ts := f.newServer(t, bundleSpec{platform: "tdx"})
		remote := config.Remote{Mode: config.AttestEndpoint, Measurements: []string{mrtdHex}}
		ea := newLBAttester(t, ts, remote, nil)
		_, err := ea.Attest(context.Background())
		if err == nil || !strings.Contains(err.Error(), "configuration error") || !strings.Contains(err.Error(), "--image-manifest") {
			t.Fatalf("want MRTD-only configuration error, got %v", err)
		}
	})

	t.Run("specific-cluster TDX without image manifest warns", func(t *testing.T) {
		stubEvidenceClaims(t, tdxStubClaims())
		f := newLBFixture(t, fixtureOpts{})
		ts := f.newServer(t, bundleSpec{platform: "tdx"})
		remote := config.Remote{Mode: config.AttestEndpoint, Measurements: []string{mrtdHex}}
		ea := newLBAttester(t, ts, remote, []*x509.Certificate{f.ca.cert})
		v, err := ea.Attest(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if v.TrustMode != TrustSpecificCluster {
			t.Fatalf("TrustMode = %q, want %q", v.TrustMode, TrustSpecificCluster)
		}
		if !strings.Contains(v.Warning, "MRTD only") {
			t.Errorf("Warning = %q, want the MRTD-only note", v.Warning)
		}
	})

	// The completeness rule keys on the image pin, so the pin must mean "this
	// exact image booted" and nothing weaker. With a manifest, a guest whose
	// MRTD is not the manifest's cannot produce a verdict at all — least of all
	// one reported as a complete TDX policy with no warning, which is what a
	// launch-digest allowlist unioned with the manifest's MRTD allowed.
	t.Run("a manifest verdict is complete only for the manifest's own image", func(t *testing.T) {
		sc := tdxStubClaims()
		sc.launchDigest = strings.Repeat("9f", RegisterSize)
		stubEvidenceClaims(t, sc)
		f := newLBFixture(t, fixtureOpts{})
		ts := f.newServer(t, bundleSpec{platform: "tdx"})
		remote := config.Remote{Mode: config.AttestEndpoint, ImageManifestPath: pinManifest(t)}
		// Even with the operator's CA pinned — the case that only warns when
		// no image is pinned at all — a foreign MRTD is a hard failure.
		ea := newLBAttester(t, ts, remote, []*x509.Certificate{f.ca.cert})
		v, err := ea.Attest(context.Background())
		if err == nil {
			t.Fatalf("a guest outside the pinned image verified: %+v", v)
		}
		if !strings.Contains(err.Error(), "MRTD mismatch") {
			t.Fatalf("want an MRTD mismatch, got %v", err)
		}
	})

	t.Run("SNP needs no image manifest", func(t *testing.T) {
		stubEvidence(t)
		f := newLBFixture(t, fixtureOpts{})
		ts := f.newServer(t, bundleSpec{platform: "snp"})
		ea := newLBAttester(t, ts, measuredRemote(), nil)
		v, err := ea.Attest(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if v.Warning != "" {
			t.Errorf("SNP verdict must not warn, got %q", v.Warning)
		}
	})
}

// TestCheckVerificationResult asserts the verifier's own verdict fields are
// read rather than inferred from a nil error. Every attestation-go platform
// path happens to return an error on a report-data mismatch today; that is an
// implementation property, not an interface guarantee.
func TestCheckVerificationResult(t *testing.T) {
	yes, no := true, false
	for _, tc := range []struct {
		name    string
		res     *teetypes.VerificationResult
		wantErr string
	}{
		{"valid", &teetypes.VerificationResult{SignatureValid: true, ReportDataMatch: &yes}, ""},
		{"nil result", nil, "no result"},
		{"signature not valid", &teetypes.VerificationResult{ReportDataMatch: &yes}, "hardware signature"},
		{"report data mismatch", &teetypes.VerificationResult{SignatureValid: true, ReportDataMatch: &no}, "report_data mismatch"},
		{"report data unevaluated", &teetypes.VerificationResult{SignatureValid: true}, "report_data mismatch"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkVerificationResult(tc.res, "snp")
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("checkVerificationResult = %v, want it accepted", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("checkVerificationResult = %v, want an error containing %q", err, tc.wantErr)
			}
		})
	}
}

// The following tests run the REAL evidence verifier (attestation-go teeverify)
// through the fixture flow, covering the seam's production side.

func TestAttestLBRejectsUnsupportedPlatform(t *testing.T) {
	f := newLBFixture(t, fixtureOpts{})
	ts := f.newServer(t, bundleSpec{
		platform: "commodore-64",
		evidence: func([]byte) json.RawMessage { return json.RawMessage(`{"bogus":true}`) },
	})
	ea := newLBAttester(t, ts, measuredRemote(), nil)
	_, err := ea.Attest(context.Background())
	if err == nil || !strings.Contains(err.Error(), "unsupported platform") {
		t.Fatalf("want unsupported-platform error, got %v", err)
	}
}

func TestAttestLBRejectsGarbageEvidence(t *testing.T) {
	f := newLBFixture(t, fixtureOpts{})
	ts := f.newServer(t, bundleSpec{
		platform: "snp",
		evidence: func([]byte) json.RawMessage { return json.RawMessage(`{"version":1,"report":"AA"}`) },
	})
	ea := newLBAttester(t, ts, measuredRemote(), nil)
	if _, err := ea.Attest(context.Background()); err == nil {
		t.Fatal("want verification failure for garbage snp evidence")
	}
}

// TestAttestLBRejectsRecordedEvidence serves real az-snp evidence captured from
// an Azure CVM. The hardware report itself verifies (SNP signature + VCEK
// chain), but its vTPM quote is not bound to this session's attest-lb
// transcript, so the attester must fail closed rather than accept replayed
// evidence.
func TestAttestLBRejectsRecordedEvidence(t *testing.T) {
	var envelope struct {
		Platform string          `json:"platform"`
		Evidence json.RawMessage `json:"evidence"`
	}
	if err := json.Unmarshal(azSnpFixture, &envelope); err != nil {
		t.Fatalf("parsing fixture: %v", err)
	}
	f := newLBFixture(t, fixtureOpts{})
	ts := f.newServer(t, bundleSpec{
		platform: envelope.Platform,
		evidence: func([]byte) json.RawMessage { return envelope.Evidence },
	})
	ea := newLBAttester(t, ts, measuredRemote(), nil)
	_, err := ea.Attest(context.Background())
	if err == nil || !strings.Contains(err.Error(), "vTPM") {
		t.Fatalf("want vTPM freshness-binding failure for recorded evidence, got %v", err)
	}
}

// TestAttestLBDoesNotFollowRedirects pins "the leaf the attester observes is
// the leaf traffic rides". The fetch runs over a transport with no PKI
// verification, so an on-path attacker can terminate it with any certificate;
// following a redirect to the genuine LB would have the client attest — and
// pin — a host it was never configured to reach.
func TestAttestLBDoesNotFollowRedirects(t *testing.T) {
	stubEvidence(t)
	f := newLBFixture(t, fixtureOpts{})
	honest := f.newServer(t, bundleSpec{})

	var honestHits atomic.Int32
	redirector := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		honestHits.Add(1)
		http.Redirect(w, r, honest.URL+r.URL.Path+"?"+r.URL.RawQuery, http.StatusFound)
	}))
	t.Cleanup(redirector.Close)

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	ea, err := NewEndpointAttester(redirector.URL, client, measuredRemote(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ea.Attest(context.Background()); err == nil || !strings.Contains(err.Error(), "302") {
		t.Fatalf("want the redirect surfaced as a non-200 response, got %v", err)
	}
	if got := honestHits.Load(); got != 1 {
		t.Fatalf("redirector saw %d requests, want exactly 1 (no follow)", got)
	}
}

func TestAttestLBNon200(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusBadGateway)
	}))
	t.Cleanup(ts.Close)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	ea, err := NewEndpointAttester(ts.URL, client, measuredRemote(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ea.Attest(context.Background()); err == nil || !strings.Contains(err.Error(), "502") {
		t.Fatalf("want 502 error, got %v", err)
	}
}

func TestSessionCachePinning(t *testing.T) {
	c := NewSessionCache(time.Minute)
	if _, fresh, _ := c.FreshSession("r"); fresh {
		t.Fatal("empty cache should not be fresh")
	}
	want := [32]byte{1, 2, 3}
	c.RecordSession("r", true, want, time.Now().Add(time.Hour), nil)
	leaf, fresh, ok := c.FreshSession("r")
	if !fresh || !ok || leaf != want {
		t.Fatalf("FreshSession = (%x, %v, %v), want (%x, true, true)", leaf, fresh, ok, want)
	}
	c.Invalidate("r")
	if _, fresh, _ := c.FreshSession("r"); fresh {
		t.Fatal("invalidated entry should not be fresh")
	}
}
