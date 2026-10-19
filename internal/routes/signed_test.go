package routes

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

func genKey(t testing.TB, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// mint signs a write token for body with alg. edit changes its claims
// before signing.
func mint(t testing.TB, key *ecdsa.PrivateKey, alg string, body []byte, edit func(map[string]any)) string {
	t.Helper()
	sum := sha256.Sum256(body)
	claims := map[string]any{
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Minute).Unix(),
		"htm": "PUT",
		"htu": "/routes",
		"pbh": base64.RawURLEncoding.EncodeToString(sum[:]),
	}
	if edit != nil {
		edit(claims)
	}
	header, _ := json.Marshal(map[string]string{"alg": alg, "typ": "JWT"})
	payload, _ := json.Marshal(claims)
	return mintRaw(t, key, header, payload)
}

// mintRaw signs a token over exactly header and payload, with the ES
// algorithm of key's curve.
func mintRaw(t testing.TB, key *ecdsa.PrivateKey, header, payload []byte) string {
	t.Helper()
	hash := map[int]crypto.Hash{256: crypto.SHA256, 384: crypto.SHA384, 521: crypto.SHA512}[key.Curve.Params().BitSize]
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	h := hash.New()
	h.Write([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, h.Sum(nil))
	if err != nil {
		t.Fatal(err)
	}
	size := (key.Curve.Params().BitSize + 7) / 8
	sig := make([]byte, 2*size)
	r.FillBytes(sig[:size])
	s.FillBytes(sig[size:])
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func pubPEM(t testing.TB, k *ecdsa.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// TestPublicationVectors checks the envelopes c8s signed and verified: each
// valid one verifies with the same digest, revision and hosts, and each
// invalid one is refused.
func TestPublicationVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/publication_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		OperatorPublicKey string `json:"operator_public_key_pem"`
		OtherPublicKey    string `json:"other_public_key_pem"`
		Valid             []struct {
			Name        string   `json:"name"`
			Envelope    string   `json:"envelope"`
			RouteDigest string   `json:"route_digest"`
			Revision    uint64   `json:"revision"`
			Hosts       []string `json:"hosts"`
		} `json:"valid"`
		Invalid []struct {
			Name     string `json:"name"`
			Envelope string `json:"envelope"`
		} `json:"invalid"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	keys, err := ParsePublicKeys([]byte(v.OperatorPublicKey))
	if err != nil {
		t.Fatal(err)
	}
	other, err := ParsePublicKeys([]byte(v.OtherPublicKey))
	if err != nil {
		t.Fatal(err)
	}
	verify := func(envelope string, keys []*ecdsa.PublicKey) (*Signed, error) {
		env, err := ParseEnvelope([]byte(envelope))
		if err != nil {
			return nil, err
		}
		return VerifySigned(env, keys)
	}
	for _, tc := range v.Valid {
		t.Run(tc.Name, func(t *testing.T) {
			s, err := verify(tc.Envelope, keys)
			if err != nil {
				t.Fatalf("VerifySigned() = %v, want nil", err)
			}
			if got := hex.EncodeToString(s.Digest[:]); got != tc.RouteDigest || s.Manifest.Revision != tc.Revision || !slices.Equal(s.Manifest.Hosts, tc.Hosts) {
				t.Errorf("VerifySigned() = digest %s, revision %d, hosts %v; want %s, %d, %v", got, s.Manifest.Revision, s.Manifest.Hosts, tc.RouteDigest, tc.Revision, tc.Hosts)
			}
			if _, err := verify(tc.Envelope, other); err == nil {
				t.Error("VerifySigned(other key) = nil, want error")
			}
		})
	}
	for _, tc := range v.Invalid {
		t.Run(tc.Name, func(t *testing.T) {
			if _, err := verify(tc.Envelope, keys); err == nil {
				t.Error("VerifySigned() = nil, want error")
			}
		})
	}
}

func TestParseEnvelopeRejects(t *testing.T) {
	for _, tc := range []struct{ name, input string }{
		{"unpadded", `{"manifest":"+/97fQ","token":"t"}`},
		{"URL-safe alphabet", `{"manifest":"-_97fQ==","token":"t"}`},
		{"embedded newline", `{"manifest":"+/97\nfQ==","token":"t"}`},
		{"non-canonical padding bits", `{"manifest":"+/97fR==","token":"t"}`},
		{"manifest as JSON", `{"manifest":{},"token":"t"}`},
		{"manifest null", `{"manifest":null,"token":"t"}`},
		{"token not a string", `{"manifest":"","token":1}`},
		{"missing token", `{"manifest":""}`},
		{"missing manifest", `{"token":"t"}`},
		{"unknown member", `{"manifest":"","token":"t","digest":""}`},
		{"duplicate member", `{"manifest":"","manifest":"","token":"t"}`},
		{"not an object", `[]`},
		{"null", `null`},
		{"trailing data", `{"manifest":"","token":"t"} {}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if env, err := ParseEnvelope([]byte(tc.input)); err == nil {
				t.Errorf("ParseEnvelope(%s) = %+v, nil; want error", tc.input, env)
			}
		})
	}
}

func TestVerifySigned(t *testing.T) {
	key, other := genKey(t, elliptic.P256()), genKey(t, elliptic.P256())
	p384 := genKey(t, elliptic.P384())
	keys := []*ecdsa.PublicKey{&key.PublicKey, &p384.PublicKey}
	body := readExample(t)
	invalid := []byte(`{"schema":"c8s.routes/v1"}`)
	token := mint(t, key, "ES256", body, nil)
	parts := strings.Split(token, ".")
	sum := sha256.Sum256(body)
	claimsJSON := `{"iat":1,"exp":61,"htm":"PUT","htu":"/routes","pbh":"` + base64.RawURLEncoding.EncodeToString(sum[:]) + `"}`
	withHeader := func(header string) string {
		return base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + parts[1] + "." + parts[2]
	}
	for _, tc := range []struct {
		name    string
		env     Envelope
		wantErr string // empty: must verify
	}{
		{name: "ES256", env: Envelope{body, token}},
		{name: "ES384", env: Envelope{body, mint(t, p384, "ES384", body, nil)}},
		{name: "expired token", env: Envelope{body, mint(t, key, "ES256", body, func(c map[string]any) {
			c["iat"] = time.Now().Add(-90 * 24 * time.Hour).Unix()
			c["exp"] = time.Now().Add(-90*24*time.Hour + time.Minute).Unix()
		})}},
		{name: "validity at the bound", env: Envelope{body, mint(t, key, "ES256", body, func(c map[string]any) {
			c["iat"], c["exp"] = 1000, 1000+int(MaxTokenValidity.Seconds())
		})}},
		{name: "validity beyond the bound", env: Envelope{body, mint(t, key, "ES256", body, func(c map[string]any) {
			c["iat"], c["exp"] = 1000, 1001+int(MaxTokenValidity.Seconds())
		})}, wantErr: "validity"},
		{name: "exp before iat", env: Envelope{body, mint(t, key, "ES256", body, func(c map[string]any) { c["exp"] = c["iat"] })}, wantErr: "validity"},
		{name: "missing iat", env: Envelope{body, mint(t, key, "ES256", body, func(c map[string]any) { delete(c, "iat") })}, wantErr: "numeric dates"},
		{name: "missing exp", env: Envelope{body, mint(t, key, "ES256", body, func(c map[string]any) { delete(c, "exp") })}, wantErr: "numeric dates"},
		{name: "string iat", env: Envelope{body, mint(t, key, "ES256", body, func(c map[string]any) { c["iat"] = "1000" })}, wantErr: "numeric dates"},
		{name: "untrusted key", env: Envelope{body, mint(t, other, "ES256", body, nil)}, wantErr: "not signed by any pinned operator key"},
		{name: "algorithm none", env: Envelope{body, withHeader(`{"alg":"none"}`)}, wantErr: `algorithm "none"`},
		{name: "algorithm HS256", env: Envelope{body, withHeader(`{"alg":"HS256"}`)}, wantErr: `algorithm "HS256"`},
		{name: "algorithm of another curve", env: Envelope{body, withHeader(`{"alg":"ES384"}`)}, wantErr: "signature is malformed"},
		{name: "Bearer prefix", env: Envelope{body, "Bearer " + token}, wantErr: "header is malformed"},
		{name: "two segments", env: Envelope{body, parts[0] + "." + parts[1]}, wantErr: "not a compact JWS"},
		{name: "flipped signature", env: Envelope{body, parts[0] + "." + parts[1] + "." + flip(parts[2])}, wantErr: "not signed by any pinned operator key"},
		{name: "crit header", env: Envelope{body, mintRaw(t, key, []byte(`{"alg":"ES256","crit":["exp"],"exp":1}`), []byte(claimsJSON))}, wantErr: "crit"},
		{name: "duplicate header member", env: Envelope{body, mintRaw(t, key, []byte(`{"alg":"ES256","alg":"ES256"}`), []byte(claimsJSON))}, wantErr: "header is malformed"},
		{name: "alg member in other case", env: Envelope{body, mintRaw(t, key, []byte(`{"ALG":"ES256"}`), []byte(claimsJSON))}, wantErr: `algorithm ""`},
		{name: "duplicate claim", env: Envelope{body, mintRaw(t, key, []byte(`{"alg":"ES256"}`), []byte(strings.Replace(claimsJSON, `{`, `{"htm":"GET",`, 1)))}, wantErr: "claims are malformed"},
		{name: "unpaired surrogate in a claim", env: Envelope{body, mintRaw(t, key, []byte(`{"alg":"ES256"}`), []byte(strings.Replace(claimsJSON, `{`, `{"x":"\ud800",`, 1)))}, wantErr: "claims are malformed"},
		{name: "raw header and claims", env: Envelope{body, mintRaw(t, key, []byte(`{"alg":"ES256"}`), []byte(claimsJSON))}},
		{name: "wrong htm", env: Envelope{body, mint(t, key, "ES256", body, func(c map[string]any) { c["htm"] = "POST" })}, wantErr: "htm"},
		{name: "wrong htu", env: Envelope{body, mint(t, key, "ES256", body, func(c map[string]any) { c["htu"] = "/allowlist" })}, wantErr: "htu"},
		{name: "htm in other case", env: Envelope{body, mint(t, key, "ES256", body, func(c map[string]any) { c["HTM"] = c["htm"]; delete(c, "htm") })}, wantErr: "htm"},
		{name: "missing pbh", env: Envelope{body, mint(t, key, "ES256", body, func(c map[string]any) { delete(c, "pbh") })}, wantErr: "pbh"},
		{name: "other body", env: Envelope{append([]byte(" "), body...), token}, wantErr: "pbh"},
		{name: "invalid manifest", env: Envelope{invalid, mint(t, key, "ES256", invalid, nil)}, wantErr: "route manifest"},
		{name: "signature before bindings", env: Envelope{invalid, mint(t, other, "ES256", body, func(c map[string]any) { c["htm"] = "GET" })}, wantErr: "not signed"},
		{name: "pbh before manifest", env: Envelope{invalid, token}, wantErr: "pbh"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := VerifySigned(tc.env, keys)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("VerifySigned() = %v, want error containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("VerifySigned() = %v, want nil", err)
			}
			if s.Digest != sha256.Sum256(tc.env.Manifest) || s.Manifest.Revision != 12 {
				t.Errorf("VerifySigned() = %+v, want the manifest's digest and revision 12", s)
			}
		})
	}
}

// flip changes the first character of a base64url segment.
func flip(s string) string {
	if s[0] == 'A' {
		return "B" + s[1:]
	}
	return "A" + s[1:]
}

func TestParsePublicKeys(t *testing.T) {
	p256, p384 := genKey(t, elliptic.P256()), genKey(t, elliptic.P384())
	two := pubPEM(t, &p256.PublicKey) + "\n" + pubPEM(t, &p384.PublicKey)
	if keys, err := ParsePublicKeys([]byte(two)); err != nil || len(keys) != 2 {
		t.Fatalf("ParsePublicKeys(two keys) = %d keys, %v; want 2, nil", len(keys), err)
	}
	priv, err := x509.MarshalPKCS8PrivateKey(p256)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, input, wantErr string }{
		{"empty", "", "no PEM PUBLIC KEY"},
		{"private key", string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: priv})), "not a PUBLIC KEY"},
		{"leading text", "key:\n" + two, "outside PEM blocks"},
		{"trailing text", two + "garbage", "outside PEM blocks"},
		{"malformed block before a good one", "-----BEGIN PUBLIC KEY-----\n!!\n" + two, "malformed PEM block"},
		{"bad DER", "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n", "parse operator public key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParsePublicKeys([]byte(tc.input)); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("ParsePublicKeys() = %v, want error containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestFloor(t *testing.T) {
	d := func(b byte) [32]byte { return [32]byte{b} }
	signed := func(revision uint64, digest [32]byte) *Signed {
		return &Signed{Manifest: &Manifest{Revision: revision}, Digest: digest}
	}
	for _, tc := range []struct {
		name  string
		floor *Signed // accepted first; nil for none
		s     *Signed
		want  error
	}{
		{"nothing accepted yet", nil, signed(5, d(1)), nil},
		{"higher revision", signed(4, d(9)), signed(5, d(1)), nil},
		{"equal revision, equal digest", signed(5, d(1)), signed(5, d(1)), nil},
		{"equal revision, other digest", signed(5, d(2)), signed(5, d(1)), ErrRevisionConflict},
		{"lower revision", signed(6, d(9)), signed(5, d(1)), ErrRollback},
		{"lower revision, equal digest", signed(6, d(1)), signed(5, d(1)), ErrRollback},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var f Floor
			if tc.floor != nil {
				if err := f.Accept(tc.floor); err != nil {
					t.Fatal(err)
				}
			}
			err := f.Accept(tc.s)
			if !errors.Is(err, tc.want) || (tc.want == nil) != (err == nil) {
				t.Errorf("Accept(%d) = %v, want %v", tc.s.Manifest.Revision, err, tc.want)
			}
			// A refused manifest leaves the floor where it was.
			want := tc.s
			if err != nil {
				want = tc.floor
			}
			if f.revision != want.Manifest.Revision || f.digest != want.Digest {
				t.Errorf("floor = %d/%x, want %d/%x", f.revision, f.digest[:1], want.Manifest.Revision, want.Digest[:1])
			}
		})
	}
}
