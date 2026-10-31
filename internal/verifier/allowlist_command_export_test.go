package verifier

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/confidential-dot-ai/TEErminator/internal/config"
)

// RunAllowlistCommandTests reuses the hardware-only evidence seam for the CLI.
func RunAllowlistCommandTests(t *testing.T, run func(context.Context, ...string) error) {
	old := []byte(`{"schema":"c8s.allowlist/v1","workloads":{"api":{"containers":[]}}}`)
	replacement := append(append([]byte(nil), old...), '\n')
	cases := []struct {
		name, fault, want   string
		inPlace, force, pin bool
	}{
		{name: "new path", pin: true},
		{name: "in place", inPlace: true, force: true, pin: true},
		{name: "no force", inPlace: true, pin: true, want: "currently pins"},
		{name: "force alone", inPlace: true, force: true, want: "pinned allowlist"},
		{name: "ordinary fetch", want: "pinned allowlist"},
		{name: "wrong workload", fault: "workload", pin: true, want: "pinned"},
		{name: "wrong launch", fault: "launch", pin: true, want: "measurement"},
		{name: "wrong image", fault: "image", pin: true, want: "MRTD mismatch"},
		{name: "wrong operator", fault: "operator", pin: true, want: "not signed by any pinned operator key"},
		{name: "wrong route", fault: "route", pin: true, want: "route"},
		{name: "low TCB", fault: "tcb", pin: true, want: "below the pinned minimum"},
		{name: "wrong sandbox", fault: "sandbox", pin: true, want: "sandbox ID"},
		{name: "invalid evidence", fault: "evidence", pin: true, want: "report_data"},
		{name: "serving leaf substitution", fault: "serving", pin: true, want: "report_data"},
		{name: "fetch serving leaf substitution", fault: "fetchleaf", inPlace: true, force: true, pin: true, want: "certificate"},
		{name: "absent stamp", fault: "stamp", pin: true, want: "stamp"},
		{name: "incorrect stamp", fault: "digest", inPlace: true, force: true, pin: true, want: "snapshot"},
		{name: "substituted document", fault: "substitute", inPlace: true, force: true, pin: true, want: "snapshot"},
		{name: "unresolvable workload", fault: "unresolved", inPlace: true, force: true, pin: true, want: "does not resolve"},
		{name: "malformed document", fault: "malformed", inPlace: true, force: true, pin: true, want: "parse"},
		{name: "cancelled", fault: "cancel", inPlace: true, force: true, pin: true, want: "context canceled"},
		{name: "failed retry", fault: "retry", inPlace: true, force: true, pin: true, want: "re-attest attempt failed"},
		{name: "missing output directory", fault: "write", pin: true, want: "temporary file"},
		{name: "rename failure", fault: "rename", force: true, pin: true, want: "renaming"},
		{name: "config save failure", fault: "save", pin: true, want: "saving config"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("XDG_CONFIG_HOME", t.TempDir())
			dir := t.TempDir()
			pinned, out := filepath.Join(dir, "old.json"), filepath.Join(dir, "new.json")
			if tc.inPlace {
				out = pinned
			}
			if err := os.WriteFile(pinned, old, 0o600); err != nil {
				t.Fatal(err)
			}
			cfgPath, err := config.Path()
			if err != nil {
				t.Fatal(err)
			}
			cfgBackup := cfgPath + ".backup"
			claims := stubClaims{tcb: snpStubTCB()}
			opts := fixtureOpts{allowlistRaw: replacement, noStamp: tc.fault == "stamp"}
			served := replacement
			if tc.fault == "digest" {
				opts.stampExts = []pkix.Extension{stampExt(t, "api", "8", make([]byte, 32))}
			}
			if tc.fault == "substitute" || tc.fault == "retry" {
				served = old
			}
			if tc.fault == "unresolved" {
				opts.allowlistRaw = []byte(`{"schema":"c8s.allowlist/v1","workloads":{}}`)
				served = opts.allowlistRaw
			}
			if tc.fault == "malformed" {
				opts.allowlistRaw = []byte(`{"schema":`)
				served = opts.allowlistRaw
			}
			spec := bundleSpec{platform: "snp"}
			if tc.fault == "evidence" {
				spec.evidence = func([]byte) json.RawMessage { return json.RawMessage(`{"report_data":"AA"}`) }
			}
			if tc.fault == "image" {
				claims = tdxStubClaims()
				claims.launchDigest = strings.Repeat("9f", RegisterSize)
				spec.platform = "tdx"
			}
			f := newLBFixture(t, opts)
			if tc.fault == "serving" {
				spec.servingDER = mintLeaf(t, f.ca, "different-leaf", nil).cert.Raw
			}
			if tc.fault == "operator" {
				manifest := routeManifest(1, "unused.example", "api")
				envelope := signRoutes(t, mintLeaf(t, f.ca, "wrong-operator", nil).key, manifest, manifest)
				spec.routes = func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(envelope))
				}
			}
			var attests, fetches, fetchHandshakes atomic.Int32
			var completedAttestation atomic.Bool
			spec.observe = func(r *http.Request) {
				if r.URL.Path == wellKnownAttestLB {
					attests.Add(1)
				}
			}
			spec.allowlist = func(w http.ResponseWriter, _ *http.Request) {
				fetches.Add(1)
				if tc.fault == "save" {
					if err := os.Rename(cfgPath, cfgBackup); err != nil {
						t.Error(err)
					}
					if err := os.Mkdir(cfgPath, 0o700); err != nil {
						t.Error(err)
					}
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(served)
			}
			// The first document mismatch must reach a failing second attestation.
			if tc.fault == "retry" {
				spec.allowlist = func(w http.ResponseWriter, _ *http.Request) {
					fetches.Add(1)
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write(old)
				}
				spec.observe = func(r *http.Request) {
					if r.URL.Path == wellKnownAttestLB && attests.Add(1) > 1 {
						r.URL.RawQuery = "nonce=AA"
					}
				}
			}
			stubEvidenceClaims(t, claims)
			ts := f.newServer(t, spec)
			if tc.fault == "fetchleaf" {
				other := mintLeaf(t, f.ca, "replacement-serving-leaf", nil)
				handler := ts.Config.Handler
				ts.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path != wellKnownAttestLB {
						handler.ServeHTTP(w, r)
						return
					}
					response := httptest.NewRecorder()
					handler.ServeHTTP(response, r)
					completedAttestation.Store(true)
					for key, values := range response.Header() {
						w.Header()[key] = values
					}
					w.Header().Set("Connection", "close")
					w.WriteHeader(response.Code)
					_, _ = w.Write(response.Body.Bytes())
				})
				ts.TLS.Certificates = nil
				ts.TLS.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
					leaf := f.serving
					if completedAttestation.Load() {
						fetchHandshakes.Add(1)
						leaf = other
					}
					return &tls.Certificate{Certificate: [][]byte{leaf.cert.Raw}, PrivateKey: leaf.key}, nil
				}
			}
			remote := config.Remote{Local: "127.0.0.1:8080", Remote: ts.URL, Mode: config.AttestEndpoint, Auth: config.AuthToken, Token: "fixture-token", Status: config.StatusVerified, Measurements: []string{"a1"}, WorkloadName: "api", AllowlistPath: pinned, RouteDigests: []string{hex.EncodeToString(fixtureRouteDigest[:])}, MinTCB: &config.TCBFloor{Bootloader: 3, SNP: 8, Microcode: 209}}
			switch tc.fault {
			case "workload":
				remote.WorkloadName = "other"
			case "launch":
				remote.Measurements = []string{"b2"}
			case "route":
				remote.RouteDigests = []string{strings.Repeat("ff", 32)}
			case "tcb":
				remote.MinTCB.Microcode = 211
			case "sandbox":
				remote.SandboxID = "other"
			case "image":
				remote.Measurements = nil
				remote.MinTCB = nil
				remote.ImageManifestPath = pinManifest(t)
			case "operator":
				remote.RouteDigests = nil
				remote.RouteOperatorKeys = []string{operatorKeyPEM(t, mintLeaf(t, f.ca, "operator", nil).key)}
			case "write":
				out = filepath.Join(dir, "missing", "new.json")
			case "rename":
				if err := os.Mkdir(out, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			cfg := config.Config{Remotes: []config.Remote{remote}}
			if err := cfg.Save(); err != nil {
				t.Fatal(err)
			}
			// Preserve a non-indented config to detect unnecessary in-place rewrites.
			original, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(cfgPath, original, 0o600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.fault == "cancel" {
				cancel()
			}
			args := []string{"allowlist", "fetch", remote.Local, "-o", out, "--timeout", "5s"}
			if tc.pin {
				args = append(args, "--pin")
			}
			if tc.force {
				args = append(args, "--force")
			}
			err = run(ctx, args...)
			if tc.want != "" {
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("want %q, got %v", tc.want, err)
				}
				assertCommandBytes(t, pinned, old)
				if tc.fault == "save" {
					assertCommandBytes(t, out, replacement)
					assertCommandBytes(t, cfgBackup, original)
				} else {
					assertCommandBytes(t, cfgPath, original)
					if !tc.inPlace && tc.fault != "rename" {
						if _, e := os.Stat(out); !os.IsNotExist(e) {
							t.Fatalf("rejected fetch left output: %v", e)
						}
					}
				}
				if tc.fault == "fetchleaf" && (!completedAttestation.Load() || fetchHandshakes.Load() == 0 || fetches.Load() != 0) {
					t.Fatalf("fetch leaf rejection outside expected phase: attested=%v, fetch handshakes=%d, fetch requests=%d", completedAttestation.Load(), fetchHandshakes.Load(), fetches.Load())
				}
				if tc.fault == "digest" || tc.fault == "substitute" {
					if fetches.Load() != 2 {
						t.Fatalf("fetch count=%d, want retry", fetches.Load())
					}
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				assertCommandBytes(t, out, replacement)
				if tc.inPlace {
					assertCommandBytes(t, cfgPath, original)
				} else {
					assertCommandBytes(t, pinned, old)
				}
				saved, e := config.Load()
				if e != nil {
					t.Fatal(e)
				}
				want := remote
				want.AllowlistPath = out
				if !reflect.DeepEqual(saved.Remotes, []config.Remote{want}) {
					t.Fatalf("saved remotes=%+v, want %+v", saved.Remotes, want)
				}
				// Ordinary policy evaluation accepts snapshot B and rejects snapshot A.
				ea := &EndpointAttester{remote: saved.Remotes[0]}
				replacementDigest := sha256.Sum256(replacement)
				replacementStamp := &MatchedWorkload{Name: "api", AllowlistDigest: replacementDigest[:]}
				if e := ea.checkWorkloadPolicy(replacementStamp); e != nil {
					t.Fatalf("ordinary verification rejected replacement snapshot: %v", e)
				}
				digest := sha256.Sum256(old)
				stamp := &MatchedWorkload{Name: "api", AllowlistDigest: digest[:]}
				if e := ea.checkWorkloadPolicy(stamp); e == nil {
					t.Fatal("ordinary verification accepted old snapshot")
				}
			}
			temps, e := filepath.Glob(filepath.Join(dir, ".allowlist-*"))
			if e != nil || len(temps) != 0 {
				t.Fatalf("temporary files=%v: %v", temps, e)
			}
			if tc.name == "no force" && attests.Load() != 0 {
				t.Fatal("overwrite refusal made an attestation request")
			}
		})
	}
}

func assertCommandBytes(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("%s=%q (%v), want %q", path, got, err, want)
	}
}
