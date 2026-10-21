package verifier

import (
	"context"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/TEErminator/internal/config"
)

func sandboxExt(t *testing.T, id string) pkix.Extension {
	t.Helper()
	value, err := asn1.MarshalWithParams(id, "ia5")
	if err != nil {
		t.Fatal(err)
	}
	return pkix.Extension{Id: oidSandboxID, Value: value}
}

func TestAttestLBSandboxID(t *testing.T) {
	stamp := func(t *testing.T) pkix.Extension {
		return stampExt(t, "api", "7", sha256Of(defaultAllowlistRaw))
	}
	for _, tc := range []struct {
		name    string
		exts    func(t *testing.T) []pkix.Extension
		pin     string
		want    string
		wantErr string
	}{
		{name: "reported unpinned", exts: func(t *testing.T) []pkix.Extension { return []pkix.Extension{stamp(t), sandboxExt(t, "abc123")} }, want: "abc123"},
		{name: "pin matches", exts: func(t *testing.T) []pkix.Extension { return []pkix.Extension{stamp(t), sandboxExt(t, "abc123")} }, pin: "abc123", want: "abc123"},
		{name: "pin mismatch", exts: func(t *testing.T) []pkix.Extension { return []pkix.Extension{stamp(t), sandboxExt(t, "abc123")} }, pin: "other", wantErr: "does not match the pinned"},
		{name: "pin without the extension", exts: func(t *testing.T) []pkix.Extension { return []pkix.Extension{stamp(t)} }, pin: "abc123", wantErr: "carries no sandbox ID"},
		{name: "malformed ID fails unpinned", exts: func(t *testing.T) []pkix.Extension { return []pkix.Extension{stamp(t), sandboxExt(t, "a b")} }, wantErr: "sandbox ID"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stubEvidence(t)
			f := newLBFixture(t, fixtureOpts{stampExts: tc.exts(t)})
			ts := f.newServer(t, bundleSpec{})
			r := measuredRemote()
			r.SandboxID = tc.pin
			v, err := newLBAttester(t, ts, r, nil).Attest(context.Background())
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Attest() = %v, want an error containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if v.SandboxID != tc.want {
				t.Errorf("SandboxID = %q, want %q", v.SandboxID, tc.want)
			}
		})
	}
}

func TestAttestLBInitData(t *testing.T) {
	committed := sha256Of([]byte("init-data document"))
	for _, tc := range []struct {
		name    string
		pin     []byte
		wantErr string
	}{
		{name: "match", pin: committed},
		{name: "mismatch", pin: sha256Of([]byte("other")), wantErr: "init-data"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := stubEvidenceClaims(t, stubClaims{initDataMatch: committed})
			ts := newLBFixture(t, fixtureOpts{}).newServer(t, bundleSpec{})
			r := measuredRemote()
			r.InitDataDigest = hexOf(tc.pin)
			_, err := newLBAttester(t, ts, r, nil).Attest(context.Background())
			if string(calls.pins.initData) != string(tc.pin) {
				t.Errorf("init-data pin handed to the verifier = %x, want %x", calls.pins.initData, tc.pin)
			}
			if tc.wantErr == "" && err != nil || tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("Attest() = %v, want error containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestAttestLBManualRTMRs(t *testing.T) {
	for _, tc := range []struct {
		name     string
		rtmrs    []string
		specific bool
		wantErr  string
	}{
		{name: "kernel and rootfs pinned by hand", rtmrs: []string{"1=" + rtmr1Hex, "2=" + rtmr2Hex}},
		{name: "kernel mismatch", rtmrs: []string{"1=" + rtmr2Hex, "2=" + rtmr2Hex}, wantErr: "RTMR[1]"},
		{name: "kernel alone is not an image pin", rtmrs: []string{"1=" + rtmr1Hex}, wantErr: "needs an image pin"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stubEvidenceClaims(t, tdxStubClaims())
			ts := newLBFixture(t, fixtureOpts{}).newServer(t, bundleSpec{platform: "tdx"})
			r := config.Remote{Mode: config.AttestEndpoint, Measurements: []string{mrtdHex}, RTMRs: tc.rtmrs}
			v, err := newLBAttester(t, ts, r, nil).Attest(context.Background())
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Attest() = %v, want an error containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if want := "1:" + rtmr1Hex + " 2:" + rtmr2Hex; strings.Join(v.RTMRsPinned, " ") != want {
				t.Errorf("RTMRsPinned = %v, want %s", v.RTMRsPinned, want)
			}
		})
	}
}

func sha256Of(b []byte) []byte {
	s := sha256.Sum256(b)
	return s[:]
}

func hexOf(b []byte) string { return hex.EncodeToString(b) }
