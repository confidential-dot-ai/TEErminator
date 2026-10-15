package routes

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

// The parser tests follow the c8s pkg/routes tests case for case, so a
// manifest c8s accepts or rejects is accepted or rejected here.

// goldenDigest is the SHA-256 of testdata/example.json, the c8s example manifest
// with a real certificate as its ca.
const goldenDigest = "f1790658f7afc5f54fcc533df858aec46930130c0456e6f16737ac1cc6e5b45a"

func readExample(t testing.TB) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/example.json")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// newCA returns a self-signed CA certificate for key, or for a fresh key
// when key is nil.
func newCA(t testing.TB, key *ecdsa.PrivateKey) (string, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	if key == nil {
		var err error
		if key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
			t.Fatal(err)
		}
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), cert, key
}

// baseManifest returns a valid manifest as a JSON tree that tests edit.
func baseManifest(ca string) map[string]any {
	return map[string]any{
		"schema":        Schema,
		"revision":      12,
		"notBefore":     "2026-09-01T00:00:00Z",
		"maxAgeSeconds": 86400,
		"hosts": map[string]any{
			"app.example": map[string]any{
				"routes": []any{
					map[string]any{"path": "/", "match": "prefix", "backend": map[string]any{
						"address": "vllm.ai.svc.cluster.local:8443", "workload": "vllm",
					}},
					map[string]any{"path": "/admin", "match": "prefix", "backend": map[string]any{
						"address": "admin.ops.svc.cluster.local:8443", "serverName": "admin.ops.svc", "ca": ca,
					}},
				},
			},
		},
	}
}

func encode(t testing.TB, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func hostOf(m map[string]any) map[string]any {
	return m["hosts"].(map[string]any)["app.example"].(map[string]any)
}

func routeOf(m map[string]any, i int) map[string]any {
	return hostOf(m)["routes"].([]any)[i].(map[string]any)
}

func backendOf(m map[string]any, i int) map[string]any {
	return routeOf(m, i)["backend"].(map[string]any)
}

func TestParseExample(t *testing.T) {
	m, err := Parse(readExample(t))
	if err != nil {
		t.Fatalf("Parse(example) = %v, want nil", err)
	}
	if m.Revision != 12 || !slices.Equal(m.Hosts, []string{"app.example"}) {
		t.Errorf("Parse(example) = %+v, want revision 12 routing app.example", m)
	}
	for host, want := range map[string]bool{"app.example": true, "APP.example:443": true, "app.example.": false, "other.example": false} {
		if got := m.Routes(host); got != want {
			t.Errorf("Routes(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestDigestGolden(t *testing.T) {
	d := Digest(readExample(t))
	if got := hex.EncodeToString(d[:]); got != goldenDigest {
		t.Errorf("Digest(example) = %s, want %s", got, goldenDigest)
	}
}

// TestDigestExactBytes checks that two encodings of one manifest have
// different digests: the digest covers bytes, not meaning.
func TestDigestExactBytes(t *testing.T) {
	b := readExample(t)
	spaced := append([]byte(" "), b...)
	if _, err := Parse(spaced); err != nil {
		t.Fatalf("Parse(spaced example) = %v, want nil", err)
	}
	if Digest(spaced) == Digest(b) {
		t.Errorf("Digest(spaced example) = Digest(example), want different")
	}
}

func TestParseAccepts(t *testing.T) {
	ca, _, _ := newCA(t, nil)
	tests := []struct {
		name string
		edit func(m map[string]any)
	}{
		{"maximum revision", func(m map[string]any) { m["revision"] = 1<<53 - 1 }},
		{"revision 1", func(m map[string]any) { m["revision"] = 1 }},
		{"offset timestamp", func(m map[string]any) { m["notBefore"] = "2026-09-01T02:00:00.5+02:00" }},
		{"maximum maxAgeSeconds", func(m map[string]any) { m["maxAgeSeconds"] = 1<<31 - 1 }},
		{"empty hosts", func(m map[string]any) { m["hosts"] = map[string]any{} }},
		{"A-label host", func(m map[string]any) {
			m["hosts"] = map[string]any{"xn--bcher-kva.example": hostOf(m)}
		}},
		{"lower-case t and z", func(m map[string]any) { m["notBefore"] = "2026-09-01t00:00:00z" }},
		{"leap second", func(m map[string]any) { m["notBefore"] = "2016-12-31T23:59:60Z" }},
		{"unknown local offset", func(m map[string]any) { m["notBefore"] = "2026-09-01T00:00:00-00:00" }},
		{"0x label that is not hex", func(m map[string]any) { m["hosts"] = map[string]any{"0xrouter": hostOf(m)} }},
		{"0x final label that is not hex", func(m map[string]any) { m["hosts"] = map[string]any{"app.0xg": hostOf(m)} }},
		{"0x serverName that is not hex", func(m map[string]any) { backendOf(m, 1)["serverName"] = "admin.0xrouter" }},
		{"single-label host", func(m map[string]any) { m["hosts"] = map[string]any{"localhost": hostOf(m)} }},
		{"numeric non-final label", func(m map[string]any) { m["hosts"] = map[string]any{"1.example": hostOf(m)} }},
		{"dots inside a segment", func(m map[string]any) { routeOf(m, 1)["path"] = "/a.b/..c/.d" }},
		{"trailing slash", func(m map[string]any) { routeOf(m, 1)["path"] = "/admin/" }},
		{"sub-delims, colon and at", func(m map[string]any) { routeOf(m, 1)["path"] = "/a:b@c!$&'()*+,;=~" }},
		{"IPv4 address", func(m map[string]any) { backendOf(m, 0)["address"] = "10.0.0.5:8443" }},
		{"IPv6 address", func(m map[string]any) { backendOf(m, 0)["address"] = "[fd00::1]:443" }},
		{"mixed-case server name", func(m map[string]any) { backendOf(m, 1)["serverName"] = "Admin.Ops.svc" }},
		{"two anchors", func(m map[string]any) {
			other, _, _ := newCA(t, nil)
			backendOf(m, 1)["ca"] = ca + "\n" + other + "\n"
		}},
		{"same path, other match", func(m map[string]any) {
			hostOf(m)["routes"] = append(hostOf(m)["routes"].([]any), map[string]any{
				"path": "/admin", "match": "exact", "backend": map[string]any{"address": "a:1", "workload": "w"},
			})
		}},
		{"same route on two hosts", func(m map[string]any) {
			m["hosts"].(map[string]any)["other.example"] = hostOf(m)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := baseManifest(ca)
			tt.edit(m)
			b := encode(t, m)
			if _, err := Parse(b); err != nil {
				t.Errorf("Parse(%s) = %v, want nil", b, err)
			}
		})
	}
}

func TestParseRejects(t *testing.T) {
	ca, _, _ := newCA(t, nil)
	certBody := strings.TrimSuffix(strings.TrimPrefix(ca, "-----BEGIN CERTIFICATE-----\n"), "-----END CERTIFICATE-----\n")
	setHost := func(name string) func(m map[string]any) {
		return func(m map[string]any) { m["hosts"] = map[string]any{name: hostOf(m)} }
	}
	tests := []struct {
		name    string
		edit    func(m map[string]any)
		raw     string // replaces the encoded manifest when set
		wantErr string
	}{
		{name: "not an object", raw: `[]`, wantErr: "must be an object"},
		{name: "null", raw: `null`, wantErr: "must be an object"},
		{name: "empty", raw: ``, wantErr: "route manifest: JSON document is empty or truncated"},
		{name: "lone low surrogate", raw: `{"schema":"\udc00"}`, wantErr: "unpaired Unicode surrogate"},
		{name: "high surrogate before a non-surrogate", raw: `{"schema":"\ud800\u0041"}`, wantErr: "unpaired Unicode surrogate"},
		{name: "high surrogate at the end of a string", raw: `{"schema":"\ud800"}`, wantErr: "unpaired Unicode surrogate"},
		{name: "nesting beyond the limit", raw: strings.Repeat("[", maxDepth+1) + strings.Repeat("]", maxDepth+1), wantErr: "nesting depth"},
		{name: "truncated", raw: `{"schema": `, wantErr: "route manifest: JSON document is empty or truncated"},
		{name: "trailing data", raw: `{} {}`, wantErr: "exactly one JSON document"},
		{name: "duplicate key", raw: `{"schema":"c8s.routes/v1","schema":"c8s.routes/v1","revision":1,"notBefore":"2026-09-01T00:00:00Z","maxAgeSeconds":1,"hosts":{}}`, wantErr: "duplicate"},
		{name: "duplicate key written with an escape", raw: `{"schema":"c8s.routes/v1","sch\u0065ma":"c8s.routes/v1","revision":1,"notBefore":"2026-09-01T00:00:00Z","maxAgeSeconds":1,"hosts":{}}`, wantErr: "duplicate"},
		{name: "duplicate route key", raw: `{"schema":"c8s.routes/v1","revision":1,"notBefore":"2026-09-01T00:00:00Z","maxAgeSeconds":1,"hosts":{"a.example":{"routes":[{"path":"/","path":"/","match":"exact","backend":{"address":"a:1","workload":"w"}}]}}}`, wantErr: "duplicate"},
		{name: "duplicate backend key", raw: `{"schema":"c8s.routes/v1","revision":1,"notBefore":"2026-09-01T00:00:00Z","maxAgeSeconds":1,"hosts":{"a.example":{"routes":[{"path":"/","match":"exact","backend":{"address":"a:1","workload":"w","workload":"v"}}]}}}`, wantErr: "duplicate"},
		{name: "nested duplicate key", raw: `{"schema":"c8s.routes/v1","revision":1,"notBefore":"2026-09-01T00:00:00Z","maxAgeSeconds":1,"hosts":{"a.example":{"routes":[],"routes":[]}}}`, wantErr: "duplicate"},
		{name: "missing schema", edit: func(m map[string]any) { delete(m, "schema") }, wantErr: `missing member "schema"`},
		{name: "wrong schema", edit: func(m map[string]any) { m["schema"] = "c8s.routes/v2" }, wantErr: "schema"},
		{name: "schema not a string", edit: func(m map[string]any) { m["schema"] = 1 }, wantErr: "schema: must be a string"},
		{name: "schema null", edit: func(m map[string]any) { m["schema"] = nil }, wantErr: "schema: must be a string"},
		{name: "unknown top-level member", edit: func(m map[string]any) { m["comment"] = "x" }, wantErr: `unknown member "comment"`},
		{name: "member name in other case", edit: func(m map[string]any) { m["Revision"] = m["revision"]; delete(m, "revision") }, wantErr: `missing member "revision"`},
		{name: "unknown host member", edit: func(m map[string]any) { hostOf(m)["cors"] = false }, wantErr: `unknown member "cors"`},
		{name: "unknown route member", edit: func(m map[string]any) { routeOf(m, 0)["priority"] = 1 }, wantErr: `unknown member "priority"`},
		{name: "unknown backend member", edit: func(m map[string]any) { backendOf(m, 0)["timeout"] = 1 }, wantErr: `unknown member "timeout"`},
		{name: "revision 0", edit: func(m map[string]any) { m["revision"] = 0 }, wantErr: "revision"},
		{name: "negative revision", edit: func(m map[string]any) { m["revision"] = -1 }, wantErr: "revision"},
		{name: "revision 2^53", edit: func(m map[string]any) { m["revision"] = 1 << 53 }, wantErr: "revision"},
		{name: "fractional revision", edit: func(m map[string]any) { m["revision"] = 1.5 }, wantErr: "revision"},
		{name: "revision 1.0", raw: `{"schema":"c8s.routes/v1","revision":1.0,"notBefore":"2026-09-01T00:00:00Z","maxAgeSeconds":1,"hosts":{}}`, wantErr: "revision"},
		{name: "revision 1e3", raw: `{"schema":"c8s.routes/v1","revision":1e3,"notBefore":"2026-09-01T00:00:00Z","maxAgeSeconds":1,"hosts":{}}`, wantErr: "revision"},
		{name: "revision with leading zero", raw: `{"schema":"c8s.routes/v1","revision":01,"notBefore":"2026-09-01T00:00:00Z","maxAgeSeconds":1,"hosts":{}}`, wantErr: "invalid character"},
		{name: "revision as string", edit: func(m map[string]any) { m["revision"] = "12" }, wantErr: "revision"},
		{name: "revision null", edit: func(m map[string]any) { m["revision"] = nil }, wantErr: "revision"},
		{name: "date only", edit: func(m map[string]any) { m["notBefore"] = "2026-09-01" }, wantErr: "notBefore"},
		{name: "not a timestamp", edit: func(m map[string]any) { m["notBefore"] = "yesterday" }, wantErr: "notBefore"},
		{name: "comma before fraction", edit: func(m map[string]any) { m["notBefore"] = "2026-09-01T00:00:00,5Z" }, wantErr: "notBefore"},
		{name: "one-digit hour", edit: func(m map[string]any) { m["notBefore"] = "2026-09-01T0:00:00Z" }, wantErr: "notBefore"},
		{name: "offset hour 24", edit: func(m map[string]any) { m["notBefore"] = "2026-09-01T00:00:00+24:00" }, wantErr: "notBefore"},
		{name: "offset minute 60", edit: func(m map[string]any) { m["notBefore"] = "2026-09-01T00:00:00+00:60" }, wantErr: "notBefore"},
		{name: "offset without colon", edit: func(m map[string]any) { m["notBefore"] = "2026-09-01T00:00:00+0000" }, wantErr: "notBefore"},
		{name: "empty fraction", edit: func(m map[string]any) { m["notBefore"] = "2026-09-01T00:00:00.Z" }, wantErr: "notBefore"},
		{name: "space separator", edit: func(m map[string]any) { m["notBefore"] = "2026-09-01 00:00:00Z" }, wantErr: "notBefore"},
		{name: "February 30", edit: func(m map[string]any) { m["notBefore"] = "2026-02-30T00:00:00Z" }, wantErr: "notBefore: parsing time \"2026-02-30T00:00:00Z\": day out of range"},
		{name: "non-ASCII digit", edit: func(m map[string]any) { m["notBefore"] = "2026-09-01T00:00:0\u0661Z" }, wantErr: "notBefore"},
		{name: "number", edit: func(m map[string]any) { m["notBefore"] = 1756684800 }, wantErr: "notBefore"},
		{name: "zero", edit: func(m map[string]any) { m["maxAgeSeconds"] = 0 }, wantErr: "maxAgeSeconds"},
		{name: "2^31", edit: func(m map[string]any) { m["maxAgeSeconds"] = 1 << 31 }, wantErr: "maxAgeSeconds"},
		{name: "fractional", edit: func(m map[string]any) { m["maxAgeSeconds"] = 0.5 }, wantErr: "maxAgeSeconds"},
		{name: "hosts not an object", edit: func(m map[string]any) { m["hosts"] = []any{} }, wantErr: "hosts: must be an object"},
		{name: "hosts null", edit: func(m map[string]any) { m["hosts"] = nil }, wantErr: "hosts: must be an object"},
		{name: "upper-case host", edit: setHost("App.example"), wantErr: "lower-case DNS host name"},
		{name: "host with port", edit: setHost("app.example:443"), wantErr: "lower-case DNS host name"},
		{name: "trailing dot", edit: setHost("app.example."), wantErr: "lower-case DNS host name"},
		{name: "IPv4 literal", edit: setHost("10.0.0.1"), wantErr: "must not be an IP literal"},
		{name: "IPv6 literal", edit: setHost("[::1]"), wantErr: "lower-case DNS host name"},
		{name: "bare IPv6 literal", edit: setHost("::1"), wantErr: "must not be an IP literal"},
		{name: "numeric final label", edit: setHost("app.123"), wantErr: "final label must not be numeric"},
		{name: "hex final label", edit: setHost("app.0x7f"), wantErr: "final label must not be numeric"},
		{name: "bare 0x final label", edit: setHost("app.0x"), wantErr: "final label must not be numeric"},
		{name: "U-label", edit: setHost("bücher.example"), wantErr: "lower-case DNS host name"},
		{name: "wildcard", edit: setHost("*.example"), wantErr: "lower-case DNS host name"},
		{name: "underscore", edit: setHost("a_b.example"), wantErr: "lower-case DNS host name"},
		{name: "leading hyphen", edit: setHost("-a.example"), wantErr: "lower-case DNS host name"},
		{name: "empty label", edit: setHost("a..example"), wantErr: "lower-case DNS host name"},
		{name: "label over 63 octets", edit: setHost(strings.Repeat("a", 64) + ".example"), wantErr: "lower-case DNS host name"},
		{name: "name over 253 octets", edit: setHost(strings.Repeat("a.", 127) + "ab"), wantErr: "lower-case DNS host name"},
		{name: "empty host name", edit: setHost(""), wantErr: "lower-case DNS host name"},
		{name: "empty routes", edit: func(m map[string]any) { hostOf(m)["routes"] = []any{} }, wantErr: "must not be empty"},
		{name: "routes missing", edit: func(m map[string]any) { delete(hostOf(m), "routes") }, wantErr: `missing member "routes"`},
		{name: "routes null", edit: func(m map[string]any) { hostOf(m)["routes"] = nil }, wantErr: "must be a list"},
		{name: "host not an object", edit: func(m map[string]any) { m["hosts"] = map[string]any{"a.example": []any{}} }, wantErr: "must be an object"},
		{name: "relative path", edit: func(m map[string]any) { routeOf(m, 1)["path"] = "admin" }, wantErr: `must begin with "/"`},
		{name: "empty path", edit: func(m map[string]any) { routeOf(m, 1)["path"] = "" }, wantErr: `must begin with "/"`},
		{name: "query", edit: func(m map[string]any) { routeOf(m, 1)["path"] = "/a?b" }, wantErr: "percent-encoding"},
		{name: "fragment", edit: func(m map[string]any) { routeOf(m, 1)["path"] = "/a#b" }, wantErr: "percent-encoding"},
		{name: "percent-encoding", edit: func(m map[string]any) { routeOf(m, 1)["path"] = "/a%20b" }, wantErr: "percent-encoding"},
		{name: "empty segment", edit: func(m map[string]any) { routeOf(m, 1)["path"] = "/a//b" }, wantErr: `"//"`},
		{name: "dot segment", edit: func(m map[string]any) { routeOf(m, 1)["path"] = "/a/./b" }, wantErr: "segment"},
		{name: "trailing dot segment", edit: func(m map[string]any) { routeOf(m, 1)["path"] = "/a/." }, wantErr: "segment"},
		{name: "dot-dot segment", edit: func(m map[string]any) { routeOf(m, 1)["path"] = "/a/../b" }, wantErr: "segment"},
		{name: "root dot-dot", edit: func(m map[string]any) { routeOf(m, 1)["path"] = "/.." }, wantErr: "segment"},
		{name: "space", edit: func(m map[string]any) { routeOf(m, 1)["path"] = "/a b" }, wantErr: "not allowed in a URI path"},
		{name: "raw non-ASCII", edit: func(m map[string]any) { routeOf(m, 1)["path"] = "/caf\u00e9" }, wantErr: "not allowed in a URI path"},
		{name: "backslash", edit: func(m map[string]any) { routeOf(m, 1)["path"] = `/a\b` }, wantErr: "not allowed in a URI path"},
		{name: "control byte", edit: func(m map[string]any) { routeOf(m, 1)["path"] = "/a\tb" }, wantErr: "not allowed in a URI path"},
		{name: "unknown match", edit: func(m map[string]any) { routeOf(m, 1)["match"] = "regex" }, wantErr: "match"},
		{name: "upper-case match", edit: func(m map[string]any) { routeOf(m, 1)["match"] = "Prefix" }, wantErr: "match"},
		{name: "missing match", edit: func(m map[string]any) { delete(routeOf(m, 1), "match") }, wantErr: `missing member "match"`},
		{name: "missing path", edit: func(m map[string]any) { delete(routeOf(m, 1), "path") }, wantErr: `missing member "path"`},
		{name: "missing backend", edit: func(m map[string]any) { delete(routeOf(m, 1), "backend") }, wantErr: `missing member "backend"`},
		{name: "missing address", edit: func(m map[string]any) { delete(backendOf(m, 0), "address") }, wantErr: `missing member "address"`},
		{name: "address without port", edit: func(m map[string]any) { backendOf(m, 0)["address"] = "vllm.ai.svc" }, wantErr: "host:port"},
		{name: "address with empty host", edit: func(m map[string]any) { backendOf(m, 0)["address"] = ":8443" }, wantErr: "address"},
		{name: "address with URL scheme", edit: func(m map[string]any) { backendOf(m, 0)["address"] = "https://vllm:8443" }, wantErr: "address"},
		{name: "port 0", edit: func(m map[string]any) { backendOf(m, 0)["address"] = "vllm:0" }, wantErr: "port"},
		{name: "port 65536", edit: func(m map[string]any) { backendOf(m, 0)["address"] = "vllm:65536" }, wantErr: "port"},
		{name: "port with leading zero", edit: func(m map[string]any) { backendOf(m, 0)["address"] = "vllm:08443" }, wantErr: "port"},
		{name: "named port", edit: func(m map[string]any) { backendOf(m, 0)["address"] = "vllm:https" }, wantErr: "port"},
		{name: "IPv6 zone", edit: func(m map[string]any) { backendOf(m, 0)["address"] = "[fe80::1%eth0]:443" }, wantErr: "address"},
		{name: "invalid workload name", edit: func(m map[string]any) { backendOf(m, 0)["workload"] = "a/b" }, wantErr: "workload name"},
		{name: "empty workload name", edit: func(m map[string]any) { backendOf(m, 0)["workload"] = "" }, wantErr: "workload name"},
		{name: "workload not a string", edit: func(m map[string]any) { backendOf(m, 0)["workload"] = 1 }, wantErr: "workload: must be a string"},
		{name: "workload and address backend", edit: func(m map[string]any) { backendOf(m, 1)["workload"] = "vllm" }, wantErr: "exactly one"},
		{name: "serverName without ca", edit: func(m map[string]any) { delete(backendOf(m, 1), "ca") }, wantErr: "exactly one"},
		{name: "ca without serverName", edit: func(m map[string]any) { delete(backendOf(m, 1), "serverName") }, wantErr: "exactly one"},
		{name: "workload with ca", edit: func(m map[string]any) { backendOf(m, 0)["ca"] = ca }, wantErr: "exactly one"},
		{name: "invalid serverName", edit: func(m map[string]any) { backendOf(m, 1)["serverName"] = "admin_ops" }, wantErr: "serverName"},
		{name: "upper-case hex final label serverName", edit: func(m map[string]any) { backendOf(m, 1)["serverName"] = "admin.0X7F" }, wantErr: "serverName: final label must not be numeric"},
		{name: "IP serverName", edit: func(m map[string]any) { backendOf(m, 1)["serverName"] = "10.0.0.1" }, wantErr: "serverName"},
		{name: "empty ca", edit: func(m map[string]any) { backendOf(m, 1)["ca"] = "" }, wantErr: "at least one CERTIFICATE"},
		{name: "whitespace ca", edit: func(m map[string]any) { backendOf(m, 1)["ca"] = " \n" }, wantErr: "at least one CERTIFICATE"},
		{name: "ca with private key block", edit: func(m map[string]any) {
			backendOf(m, 1)["ca"] = ca + "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"
		}, wantErr: "not a CERTIFICATE"},
		{name: "ca with leading text", edit: func(m map[string]any) { backendOf(m, 1)["ca"] = "subject=test\n" + ca }, wantErr: "outside PEM blocks"},
		{name: "ca with trailing text", edit: func(m map[string]any) { backendOf(m, 1)["ca"] = ca + "garbage" }, wantErr: "outside PEM blocks"},
		{name: "ca with malformed block before a good one", edit: func(m map[string]any) {
			backendOf(m, 1)["ca"] = "-----BEGIN CERTIFICATE-----\n!!\n" + ca
		}, wantErr: "malformed PEM block"},
		{name: "ca with PEM headers", edit: func(m map[string]any) {
			backendOf(m, 1)["ca"] = "-----BEGIN CERTIFICATE-----\nProc-Type: 4,ENCRYPTED\n\n" + certBody + "-----END CERTIFICATE-----\n"
		}, wantErr: "headers"},
		{name: "ca with invalid DER", edit: func(m map[string]any) {
			backendOf(m, 1)["ca"] = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
		}, wantErr: "certificate 0"},
		{name: "ca not a string", edit: func(m map[string]any) { backendOf(m, 1)["ca"] = []any{ca} }, wantErr: "ca: must be a string"},
		{name: "duplicate path and match", edit: func(m map[string]any) {
			hostOf(m)["routes"] = append(hostOf(m)["routes"].([]any), map[string]any{
				"path": "/admin", "match": "prefix", "backend": map[string]any{"address": "a:1", "workload": "w"},
			})
		}, wantErr: `another route has path "/admin"`},
		{name: "plaintext protocol", edit: func(m map[string]any) { backendOf(m, 0)["protocol"] = "http" }, wantErr: `unknown member "protocol"`},
		{name: "backend without peer verification", edit: func(m map[string]any) { delete(backendOf(m, 0), "workload") }, wantErr: "exactly one"},
		{name: "insecure skip verify", edit: func(m map[string]any) {
			delete(backendOf(m, 1), "ca")
			backendOf(m, 1)["insecureSkipVerify"] = true
		}, wantErr: `unknown member "insecureSkipVerify"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := []byte(tt.raw)
			if tt.edit != nil {
				m := baseManifest(ca)
				tt.edit(m)
				b = encode(t, m)
			}
			_, err := Parse(b)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Parse(%.200s) = %v, want error containing %q", b, err, tt.wantErr)
			}
		})
	}
}

func TestValidateJSONAccepts(t *testing.T) {
	for _, in := range []string{`"😀"`, `"\\u"`, `"\\ud800"`, `{"a":[{"a":1},{"a":2}]}`} {
		if err := validateJSON([]byte(in)); err != nil {
			t.Errorf("validateJSON(%s) = %v, want nil", in, err)
		}
	}
}
