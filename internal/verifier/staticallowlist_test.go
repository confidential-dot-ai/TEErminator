package verifier

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/TEErminator/internal/config"
	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

// goldenStaticAllowlistDER is the one canonical encoding of {v1, 0x22*32},
// shared with c8s (pkg/ratls) and c8s-verify-js so the parsers cannot drift.
const goldenStaticAllowlistDER = "30250201010420" +
	"2222222222222222222222222222222222222222222222222222222222222222"

func goldenSealedDigest() []byte { return bytes.Repeat([]byte{0x22}, allowlistDigestSize) }

func TestStaticAllowlistGoldenVector(t *testing.T) {
	der, err := hex.DecodeString(goldenStaticAllowlistDER)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := unmarshalStaticAllowlist(der)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(digest, goldenSealedDigest()) {
		t.Fatalf("golden vector parsed to %x", digest)
	}
	reencoded, err := asn1.Marshal(staticAllowlistASN1{1, goldenSealedDigest()})
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(reencoded); got != goldenStaticAllowlistDER {
		t.Fatalf("re-encoded DER = %s, want %s", got, goldenStaticAllowlistDER)
	}
}

func TestStaticAllowlistRejectsDamage(t *testing.T) {
	golden, _ := hex.DecodeString(goldenStaticAllowlistDER)
	marshal := func(v staticAllowlistASN1) []byte {
		der, err := asn1.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	v2 := append([]byte(nil), golden...)
	v2[4] = 0x02
	nonMinimal := append([]byte{0x30, 0x81, golden[1]}, golden[2:]...)
	extraField := append(append([]byte(nil), golden...), 0x02, 0x01, 0x01)
	extraField[1] += 3

	for name, der := range map[string][]byte{
		"trailing bytes":     append(append([]byte(nil), golden...), 0x00),
		"unknown version":    v2,
		"non-minimal length": nonMinimal,
		"extra field":        extraField,
		"empty":              {},
		"short digest":       marshal(staticAllowlistASN1{1, bytes.Repeat([]byte{0x22}, 31)}),
		"long digest":        marshal(staticAllowlistASN1{1, bytes.Repeat([]byte{0x22}, 33)}),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := unmarshalStaticAllowlist(der); err == nil {
				t.Fatal("unmarshalStaticAllowlist accepted damaged DER")
			}
		})
	}
}

func TestStaticAllowlistFromCert(t *testing.T) {
	golden, _ := hex.DecodeString(goldenStaticAllowlistDER)
	ext := pkix.Extension{Id: oidStaticAllowlist, Value: golden}

	t.Run("absent", func(t *testing.T) {
		digest, err := staticAllowlistFromCert(mintCA(t, "plain").cert)
		if err != nil || digest != nil {
			t.Fatalf("staticAllowlistFromCert(no ext) = %x, %v; want nil, nil", digest, err)
		}
	})
	t.Run("present", func(t *testing.T) {
		ca := mintSealedCA(t, sealedCAOpts{digest: goldenSealedDigest()})
		digest, err := staticAllowlistFromCert(ca.cert)
		if err != nil || !bytes.Equal(digest, goldenSealedDigest()) {
			t.Fatalf("staticAllowlistFromCert = %x, %v", digest, err)
		}
	})
	// x509.CreateCertificate refuses duplicate extensions itself, so the
	// hostile shapes are exercised on the parsed-extension view a verifier
	// actually reads.
	t.Run("duplicated", func(t *testing.T) {
		if _, err := staticAllowlistFromCert(&x509.Certificate{Extensions: []pkix.Extension{ext, ext}}); err == nil {
			t.Fatal("accepted a duplicated extension")
		}
	})
	t.Run("malformed", func(t *testing.T) {
		bad := pkix.Extension{Id: oidStaticAllowlist, Value: []byte{0x30, 0x00}}
		if _, err := staticAllowlistFromCert(&x509.Certificate{Extensions: []pkix.Extension{bad}}); err == nil {
			t.Fatal("accepted a malformed extension")
		}
	})
}

func TestReportDataForKey(t *testing.T) {
	ec, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pkix, err := x509.MarshalPKIXPublicKey(&ec.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	want := sha512.Sum384(pkix)
	got, err := reportDataForKey(&ec.PublicKey)
	if err != nil || !bytes.Equal(got, want[:]) {
		t.Fatalf("reportDataForKey(ecdsa) = %x, %v; want SHA-384(PKIX) %x", got, err, want)
	}

	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wantEd := sha512.Sum384(edPub)
	got, err = reportDataForKey(edPub)
	if err != nil || !bytes.Equal(got, wantEd[:]) {
		t.Fatalf("reportDataForKey(ed25519) = %x, %v; want SHA-384(raw) %x", got, err, wantEd)
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reportDataForKey(&rsaKey.PublicKey); err == nil {
		t.Fatal("reportDataForKey accepted an RSA key")
	}
}

// ratlsExt encodes an RA-TLS attestation extension value.
func ratlsExt(t *testing.T, teeType int, report, certChain []byte) pkix.Extension {
	t.Helper()
	value, err := asn1.Marshal(ratlsAttestationASN1{TEEType: teeType, Report: report, CertChain: certChain})
	if err != nil {
		t.Fatal(err)
	}
	return pkix.Extension{Id: oidRATLSAttestation, Value: value}
}

func TestCAEvidenceFromCert(t *testing.T) {
	envelope := []byte(`{"platform":"tdx","evidence":{"quote":"AAAA"}}`)

	t.Run("json envelope forwarded verbatim", func(t *testing.T) {
		ca := mintSealedCA(t, sealedCAOpts{report: envelope})
		ev, err := caEvidenceFromCert(ca.cert)
		if err != nil {
			t.Fatal(err)
		}
		if ev.platform != "tdx" || string(ev.evidence) != `{"quote":"AAAA"}` {
			t.Fatalf("caEvidenceFromCert = %q %s", ev.platform, ev.evidence)
		}
		want, _ := reportDataForKey(ca.cert.PublicKey)
		if !bytes.Equal(ev.expectedReportData, want) {
			t.Fatalf("expectedReportData = %x, want SHA-384 of the CA key %x", ev.expectedReportData, want)
		}
	})

	t.Run("raw snp report wrapped with its vcek", func(t *testing.T) {
		report := bytes.Repeat([]byte{0xab}, snpReportSize)
		vcek := []byte("vcek-der")
		ca := mintSealedCA(t, sealedCAOpts{teeType: teeTypeSEVSNP, report: report, certChain: vcek})
		ev, err := caEvidenceFromCert(ca.cert)
		if err != nil {
			t.Fatal(err)
		}
		if ev.platform != "snp" {
			t.Fatalf("platform = %q, want snp", ev.platform)
		}
		var got struct {
			Report    string `json:"attestation_report"`
			CertChain struct {
				Vcek string `json:"vcek"`
			} `json:"cert_chain"`
		}
		if err := json.Unmarshal(ev.evidence, &got); err != nil {
			t.Fatal(err)
		}
		if got.Report != base64.StdEncoding.EncodeToString(report) || got.CertChain.Vcek != base64.StdEncoding.EncodeToString(vcek) {
			t.Fatalf("snp evidence = %s", ev.evidence)
		}
	})

	t.Run("raw snp report without vcek omits cert_chain", func(t *testing.T) {
		ca := mintSealedCA(t, sealedCAOpts{teeType: teeTypeSEVSNP, report: bytes.Repeat([]byte{0xab}, snpReportSize)})
		ev, err := caEvidenceFromCert(ca.cert)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(ev.evidence), "cert_chain") {
			t.Fatalf("evidence carries a cert_chain with no VCEK: %s", ev.evidence)
		}
	})

	for name, tc := range map[string]struct {
		exts []pkix.Extension
		want string
	}{
		"absent":               {nil, "no RA-TLS attestation extension"},
		"envelope no platform": {[]pkix.Extension{ratlsExt(t, teeTypeTDX, []byte(`{"evidence":{"q":1}}`), nil)}, "missing platform"},
		"envelope bad json":    {[]pkix.Extension{ratlsExt(t, teeTypeTDX, []byte(`{"platform":`), nil)}, "parse embedded"},
		"raw tdx bytes":        {[]pkix.Extension{ratlsExt(t, teeTypeTDX, []byte{1, 2, 3}, nil)}, "must carry a JSON"},
		"raw snp wrong size":   {[]pkix.Extension{ratlsExt(t, teeTypeSEVSNP, []byte{1, 2, 3}, nil)}, "expected 1184"},
		"unknown tee type":     {[]pkix.Extension{ratlsExt(t, 7, envelope, nil)}, "unsupported RA-TLS TEE type"},
		"trailing bytes": {[]pkix.Extension{{Id: oidRATLSAttestation,
			Value: append(ratlsExt(t, teeTypeTDX, envelope, nil).Value, 0x00)}}, "trailing bytes"},
		"duplicated": {[]pkix.Extension{ratlsExt(t, teeTypeTDX, envelope, nil), ratlsExt(t, teeTypeTDX, envelope, nil)}, "more than one"},
	} {
		t.Run(name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			cert := &x509.Certificate{PublicKey: &key.PublicKey, Extensions: tc.exts}
			_, err = caEvidenceFromCert(cert)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("caEvidenceFromCert = %v, want error containing %q", err, tc.want)
			}
		})
	}
}

func TestValidateStaticAllowlistPins(t *testing.T) {
	hexDigest := strings.Repeat("5e", 32)
	if got, err := ValidateStaticAllowlistPins(true, ""); err != nil || got != nil {
		t.Errorf("no init-data = (%x, %v), want (nil, nil)", got, err)
	}
	if got, err := ValidateStaticAllowlistPins(false, ""); err != nil || got != nil {
		t.Errorf("no pins = (%x, %v), want (nil, nil)", got, err)
	}
	got, err := ValidateStaticAllowlistPins(true, hexDigest)
	if err != nil || !bytes.Equal(got, bytes.Repeat([]byte{0x5e}, 32)) {
		t.Errorf("valid init-data = (%x, %v)", got, err)
	}
	for name, tc := range map[string]struct {
		static   bool
		initData string
		want     string
	}{
		"init-data without static": {false, hexDigest, "requires --static-allowlist"},
		"not hex":                  {true, "zz", "not hex"},
		"short":                    {true, "5e5e", "want 32"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ValidateStaticAllowlistPins(tc.static, tc.initData)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ValidateStaticAllowlistPins(%v, %q) = %v, want error containing %q", tc.static, tc.initData, err, tc.want)
			}
		})
	}
}

func TestCheckSealedCAResult(t *testing.T) {
	ok := &teetypes.VerificationResult{SignatureValid: true, ReportDataMatch: teetypes.Ptr(true)}
	if err := checkSealedCAResult(ok, teetypes.VerifyParams{}); err != nil {
		t.Fatalf("passing result rejected: %v", err)
	}
	initData := teetypes.VerifyParams{ExpectedInitDataHash: bytes.Repeat([]byte{1}, 32)}
	for name, tc := range map[string]struct {
		res    *teetypes.VerificationResult
		params teetypes.VerifyParams
		want   string
	}{
		"nil result":            {nil, teetypes.VerifyParams{}, "no result"},
		"signature invalid":     {&teetypes.VerificationResult{ReportDataMatch: teetypes.Ptr(true)}, teetypes.VerifyParams{}, "signature"},
		"report data unchecked": {&teetypes.VerificationResult{SignatureValid: true}, teetypes.VerifyParams{}, "report_data"},
		"report data false":     {&teetypes.VerificationResult{SignatureValid: true, ReportDataMatch: teetypes.Ptr(false)}, teetypes.VerifyParams{}, "report_data"},
		"init data unchecked":   {ok, initData, "init-data"},
		"init data false": {&teetypes.VerificationResult{SignatureValid: true, ReportDataMatch: teetypes.Ptr(true),
			InitDataMatch: teetypes.Ptr(false)}, initData, "init-data"},
	} {
		t.Run(name, func(t *testing.T) {
			err := checkSealedCAResult(tc.res, tc.params)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("checkSealedCAResult = %v, want error containing %q", err, tc.want)
			}
		})
	}
}

// sealedCAOpts shapes a self-signed mesh CA the way a --static-allowlist CDS
// mints one. The zero value carries a verifiable stub envelope over the CA key
// and no static-allowlist stamp.
type sealedCAOpts struct {
	digest     []byte // .1.3 stamp; nil = none
	noEvidence bool   // omit the .1.1 extension
	report     []byte // .1.1 report; default: the stub envelope binding the CA key
	platform   string // the default envelope's platform tag; default "test"
	teeType    int    // default teeTypeTDX
	certChain  []byte
}

// stubCAEnvelope is the sealed CA's embedded evidence in the shape the
// verifyCAEvidence stub reads: {"platform":…,"evidence":{"report_data":…}}.
func stubCAEnvelope(t *testing.T, platform string, erd []byte) []byte {
	t.Helper()
	inner, err := json.Marshal(map[string]string{"report_data": base64.RawURLEncoding.EncodeToString(erd)})
	if err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(map[string]any{"platform": platform, "evidence": json.RawMessage(inner)})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func mintSealedCA(t *testing.T, o sealedCAOpts) *certAndKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var exts []pkix.Extension
	if !o.noEvidence {
		report := o.report
		if report == nil {
			erd, err := reportDataForKey(&key.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			platform := o.platform
			if platform == "" {
				platform = "test"
			}
			report = stubCAEnvelope(t, platform, erd)
		}
		teeType := o.teeType
		if teeType == 0 {
			teeType = teeTypeTDX
		}
		exts = append(exts, ratlsExt(t, teeType, report, o.certChain))
	}
	if o.digest != nil {
		value, err := asn1.Marshal(staticAllowlistASN1{FormatVersion: staticAllowlistVersion, AllowlistDigest: o.digest})
		if err != nil {
			t.Fatal(err)
		}
		exts = append(exts, pkix.Extension{Id: oidStaticAllowlist, Value: value})
	}
	fixtureSerial++
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(fixtureSerial),
		Subject:               pkix.Name{CommonName: "sealed-mesh-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		ExtraExtensions:       exts,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &certAndKey{cert: cert, key: key, pem: pemEncodeCert(der)}
}

// stubCACalls records what the attester handed the sealed-CA evidence seam.
type stubCACalls struct {
	n        int
	platform string
	params   teetypes.VerifyParams
}

// stubCAEvidence swaps the sealed-CA evidence seam for a stub that checks the
// envelope's report_data against the expected CA-key binding and answers with
// sc's claims (launch digest "a1" by default). A non-nil refuse makes the stub
// refuse every call with it.
func stubCAEvidence(t *testing.T, sc stubClaims, refuse error) *stubCACalls {
	t.Helper()
	if sc.launchDigest == "" {
		sc.launchDigest = "a1"
	}
	calls := &stubCACalls{}
	orig := verifyCAEvidence
	verifyCAEvidence = func(_ context.Context, platform string, evidence json.RawMessage, params teetypes.VerifyParams) (*teetypes.VerificationResult, error) {
		calls.n++
		calls.platform = platform
		calls.params = params
		if refuse != nil {
			return nil, refuse
		}
		var ev struct {
			ReportData string `json:"report_data"`
		}
		if err := json.Unmarshal(evidence, &ev); err != nil {
			return nil, err
		}
		got, err := base64.RawURLEncoding.DecodeString(ev.ReportData)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(got, params.ExpectedReportData) {
			return nil, errors.New("stub CA evidence: report_data does not bind the CA key")
		}
		res := &teetypes.VerificationResult{
			SignatureValid:  true,
			Platform:        teetypes.PlatformType(platform),
			ReportDataMatch: teetypes.Ptr(true),
			Claims: teetypes.Claims{
				LaunchDigest: sc.launchDigest,
				TCB:          sc.tcb,
				PlatformData: sc.platformData,
			},
		}
		if params.ExpectedInitDataHash != nil {
			res.InitDataMatch = teetypes.Ptr(true)
		}
		return res, nil
	}
	t.Cleanup(func() { verifyCAEvidence = orig })
	return calls
}

// sealedFixture is the honest sealed deployment: the committed CA seals the
// digest of the default allowlist, which is also what the mesh leaf's stamp
// names.
func sealedFixture(t *testing.T) *lbFixture {
	t.Helper()
	digest := sha256.Sum256(defaultAllowlistRaw)
	return newLBFixture(t, fixtureOpts{ca: mintSealedCA(t, sealedCAOpts{digest: digest[:]})})
}

func sealedRemote(allowlistPath string) config.Remote {
	return config.Remote{
		Mode:            config.AttestEndpoint,
		Measurements:    []string{"a1"},
		StaticAllowlist: true,
		AllowlistPath:   allowlistPath,
	}
}

func TestAttestLBStaticAllowlist(t *testing.T) {
	t.Run("sealed CA, verified evidence, pinned file", func(t *testing.T) {
		stubEvidence(t)
		calls := stubCAEvidence(t, stubClaims{}, nil)
		f := sealedFixture(t)
		ts := f.newServer(t, bundleSpec{})
		ea := newLBAttester(t, ts, sealedRemote(writeAllowlist(t, f.allowlistRaw)), nil)
		v, err := ea.Attest(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		want := sha256.Sum256(f.allowlistRaw)
		if v.StaticAllowlistDigest != hex.EncodeToString(want[:]) {
			t.Errorf("StaticAllowlistDigest = %q, want %x", v.StaticAllowlistDigest, want)
		}
		if v.SealedCALaunch != "a1" {
			t.Errorf("SealedCALaunch = %q, want a1", v.SealedCALaunch)
		}
		if v.Warning != "" {
			t.Errorf("pinned seal must not warn, got %q", v.Warning)
		}
		if calls.n != 1 || calls.platform != "test" {
			t.Fatalf("CA evidence seam called %d times for platform %q, want once for test", calls.n, calls.platform)
		}
		// The CA is immutable: a re-attestation reuses its verified claims.
		if _, err := ea.Attest(context.Background()); err != nil {
			t.Fatal(err)
		}
		if calls.n != 1 {
			t.Fatalf("CA evidence re-verified on re-attestation (%d calls)", calls.n)
		}
	})

	t.Run("no pinned file verifies the seal with a warning", func(t *testing.T) {
		stubEvidence(t)
		stubCAEvidence(t, stubClaims{}, nil)
		f := sealedFixture(t)
		ts := f.newServer(t, bundleSpec{})
		ea := newLBAttester(t, ts, sealedRemote(""), nil)
		v, err := ea.Attest(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if v.StaticAllowlistDigest == "" || !strings.Contains(v.Warning, "no reviewed document") {
			t.Fatalf("verdict = digest %q, warning %q", v.StaticAllowlistDigest, v.Warning)
		}
	})

	t.Run("unsealed CA fails closed", func(t *testing.T) {
		stubEvidence(t)
		stubCAEvidence(t, stubClaims{}, nil)
		f := newLBFixture(t, fixtureOpts{})
		ts := f.newServer(t, bundleSpec{})
		ea := newLBAttester(t, ts, sealedRemote(writeAllowlist(t, f.allowlistRaw)), nil)
		_, err := ea.Attest(context.Background())
		if err == nil || !strings.Contains(err.Error(), "no static-allowlist stamp") {
			t.Fatalf("want unsealed failure, got %v", err)
		}
	})

	t.Run("stamp without CA evidence fails closed", func(t *testing.T) {
		stubEvidence(t)
		stubCAEvidence(t, stubClaims{}, nil)
		digest := sha256.Sum256(defaultAllowlistRaw)
		f := newLBFixture(t, fixtureOpts{ca: mintSealedCA(t, sealedCAOpts{digest: digest[:], noEvidence: true})})
		ts := f.newServer(t, bundleSpec{})
		ea := newLBAttester(t, ts, sealedRemote(""), nil)
		_, err := ea.Attest(context.Background())
		if err == nil || !strings.Contains(err.Error(), "no RA-TLS attestation extension") {
			t.Fatalf("want missing-evidence failure, got %v", err)
		}
	})

	t.Run("refused CA evidence fails closed", func(t *testing.T) {
		stubEvidence(t)
		stubCAEvidence(t, stubClaims{}, errors.New("bad signature"))
		f := sealedFixture(t)
		ts := f.newServer(t, bundleSpec{})
		ea := newLBAttester(t, ts, sealedRemote(""), nil)
		_, err := ea.Attest(context.Background())
		if err == nil || !strings.Contains(err.Error(), "was refused: bad signature") {
			t.Fatalf("want refused-evidence failure, got %v", err)
		}
	})

	t.Run("CA evidence bound to another key fails closed", func(t *testing.T) {
		stubEvidence(t)
		stubCAEvidence(t, stubClaims{}, nil)
		digest := sha256.Sum256(defaultAllowlistRaw)
		other, err := reportDataForKey(mintCA(t, "other").cert.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		f := newLBFixture(t, fixtureOpts{ca: mintSealedCA(t, sealedCAOpts{digest: digest[:], report: stubCAEnvelope(t, "test", other)})})
		ts := f.newServer(t, bundleSpec{})
		ea := newLBAttester(t, ts, sealedRemote(""), nil)
		_, err = ea.Attest(context.Background())
		if err == nil || !strings.Contains(err.Error(), "does not bind the CA key") {
			t.Fatalf("want key-binding failure, got %v", err)
		}
	})

	t.Run("CA launch outside the measurement policy fails closed", func(t *testing.T) {
		stubEvidence(t)
		stubCAEvidence(t, stubClaims{launchDigest: "b2"}, nil)
		f := sealedFixture(t)
		ts := f.newServer(t, bundleSpec{})
		ea := newLBAttester(t, ts, sealedRemote(""), nil)
		_, err := ea.Attest(context.Background())
		if err == nil || !strings.Contains(err.Error(), "launch policy") || !strings.Contains(err.Error(), "b2") {
			t.Fatalf("want CA launch policy failure, got %v", err)
		}
	})

	t.Run("pinned file differing from the seal fails closed", func(t *testing.T) {
		stubEvidence(t)
		stubCAEvidence(t, stubClaims{}, nil)
		// The leaf stamp names the pinned file; the CA seals something else.
		f := newLBFixture(t, fixtureOpts{ca: mintSealedCA(t, sealedCAOpts{digest: goldenSealedDigest()})})
		ts := f.newServer(t, bundleSpec{})
		ea := newLBAttester(t, ts, sealedRemote(writeAllowlist(t, f.allowlistRaw)), nil)
		_, err := ea.Attest(context.Background())
		if err == nil || !strings.Contains(err.Error(), "does not match SHA-256") {
			t.Fatalf("want sealed-digest mismatch, got %v", err)
		}
	})

	t.Run("leaf stamp decided under another snapshot fails closed", func(t *testing.T) {
		stubEvidence(t)
		stubCAEvidence(t, stubClaims{}, nil)
		f := newLBFixture(t, fixtureOpts{ca: mintSealedCA(t, sealedCAOpts{digest: goldenSealedDigest()})})
		ts := f.newServer(t, bundleSpec{})
		ea := newLBAttester(t, ts, sealedRemote(""), nil)
		_, err := ea.Attest(context.Background())
		if err == nil || !strings.Contains(err.Error(), "not the sealed digest") {
			t.Fatalf("want stamp skew failure, got %v", err)
		}
	})

	t.Run("unstamped leaf passes under a pinned-file-free seal", func(t *testing.T) {
		stubEvidence(t)
		stubCAEvidence(t, stubClaims{}, nil)
		f := newLBFixture(t, fixtureOpts{noStamp: true, ca: mintSealedCA(t, sealedCAOpts{digest: goldenSealedDigest()})})
		ts := f.newServer(t, bundleSpec{})
		ea := newLBAttester(t, ts, sealedRemote(""), nil)
		v, err := ea.Attest(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if v.StaticAllowlistDigest != hex.EncodeToString(goldenSealedDigest()) {
			t.Fatalf("StaticAllowlistDigest = %q", v.StaticAllowlistDigest)
		}
	})

	t.Run("init-data and TCB floor reach the CA verifier", func(t *testing.T) {
		stubEvidenceClaims(t, stubClaims{tcb: snpStubTCB()})
		calls := stubCAEvidence(t, stubClaims{tcb: snpStubTCB()}, nil)
		digest := sha256.Sum256(defaultAllowlistRaw)
		f := newLBFixture(t, fixtureOpts{ca: mintSealedCA(t, sealedCAOpts{digest: digest[:], platform: "snp"})})
		ts := f.newServer(t, bundleSpec{platform: "snp"})
		remote := sealedRemote("")
		remote.InitData = strings.Repeat("5e", 32)
		remote.MinTCB = &config.TCBFloor{Bootloader: 1}
		ea := newLBAttester(t, ts, remote, nil)
		if _, err := ea.Attest(context.Background()); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(calls.params.ExpectedInitDataHash, bytes.Repeat([]byte{0x5e}, 32)) {
			t.Errorf("ExpectedInitDataHash = %x", calls.params.ExpectedInitDataHash)
		}
		if calls.params.MinTCB == nil || calls.params.MinTCB.Bootloader != 1 {
			t.Errorf("MinTCB = %+v, want the remote's floor", calls.params.MinTCB)
		}
	})

	t.Run("init-data without the seal is a configuration error", func(t *testing.T) {
		stubEvidence(t)
		f := newLBFixture(t, fixtureOpts{})
		ts := f.newServer(t, bundleSpec{})
		remote := measuredRemote()
		remote.InitData = strings.Repeat("5e", 32)
		ea := newLBAttester(t, ts, remote, nil)
		_, err := ea.Attest(context.Background())
		if err == nil || !strings.Contains(err.Error(), "configuration error") || !strings.Contains(err.Error(), "requires --static-allowlist") {
			t.Fatalf("want configuration error, got %v", err)
		}
	})

	t.Run("image manifest pins the CA tuple too", func(t *testing.T) {
		stubEvidenceClaims(t, tdxStubClaims())
		manifest := pinManifest(t)
		digest := sha256.Sum256(defaultAllowlistRaw)
		// The envelope's platform tag is what the stub echoes back as the
		// verified platform, so it is what the CA-side policy dispatches on.
		attest := func(t *testing.T, caClaims stubClaims, caPlatform string) error {
			t.Helper()
			stubCAEvidence(t, caClaims, nil)
			f := newLBFixture(t, fixtureOpts{ca: mintSealedCA(t, sealedCAOpts{digest: digest[:], platform: caPlatform})})
			ts := f.newServer(t, bundleSpec{platform: "tdx"})
			remote := config.Remote{Mode: config.AttestEndpoint, ImageManifestPath: manifest, StaticAllowlist: true}
			ea := newLBAttester(t, ts, remote, nil)
			_, err := ea.Attest(context.Background())
			return err
		}
		if err := attest(t, tdxStubClaims(), "tdx"); err != nil {
			t.Fatalf("CA on the pinned image: %v", err)
		}
		sc := tdxStubClaims()
		delete(sc.platformData, "rtmr_1")
		if err := attest(t, sc, "tdx"); err == nil || !strings.Contains(err.Error(), "rtmr_1") {
			t.Fatalf("want CA RTMR[1] failure, got %v", err)
		}
		if err := attest(t, tdxStubClaims(), "snp"); err == nil || !strings.Contains(err.Error(), "runs CDS on the pinned image") {
			t.Fatalf("want cross-platform CA failure, got %v", err)
		}
	})
}
