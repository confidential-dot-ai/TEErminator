package verifier

import (
	"bytes"
	"context"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// componentSetVectors is testdata/componentsets/vectors.json, generated with
// C8s from authored.json (see generate.go there).
type componentSetVectors struct {
	AllowlistSHA256 string `json:"allowlist_sha256"`
	Sets            map[string]struct {
		Digest       string `json:"digest"`
		ExtensionDER string `json:"extension_der"`
	} `json:"sets"`
}

func loadComponentSetFixture(t *testing.T) ([]byte, componentSetVectors) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "componentsets", "allowlist.json"))
	if err != nil {
		t.Fatal(err)
	}
	vectorsRaw, err := os.ReadFile(filepath.Join("testdata", "componentsets", "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors componentSetVectors
	if err := json.Unmarshal(vectorsRaw, &vectors); err != nil {
		t.Fatal(err)
	}
	if got := hexOf(sha256Of(raw)); got != vectors.AllowlistSHA256 {
		t.Fatalf("SHA-256(allowlist.json) = %s, want %s", got, vectors.AllowlistSHA256)
	}
	return raw, vectors
}

// fixtureSet is the leaf-side component set C8s stamps for version.
func fixtureSet(t *testing.T, vectors componentSetVectors, version string) *ComponentSet {
	t.Helper()
	digest, err := hex.DecodeString(strings.TrimPrefix(vectors.Sets[version].Digest, "sha256:"))
	if err != nil {
		t.Fatal(err)
	}
	return &ComponentSet{Version: version, Digest: digest}
}

func componentSetExt(t *testing.T, version string, digest []byte) pkix.Extension {
	t.Helper()
	value, err := asn1.Marshal(componentSetASN1{Version: version, Digest: digest})
	if err != nil {
		t.Fatal(err)
	}
	return pkix.Extension{Id: oidComponentSet, Value: value}
}

func TestUnmarshalComponentSetC8sVectors(t *testing.T) {
	_, vectors := loadComponentSetFixture(t)
	for version, v := range vectors.Sets {
		der, err := hex.DecodeString(v.ExtensionDER)
		if err != nil {
			t.Fatal(err)
		}
		got, err := unmarshalComponentSet(der)
		if err != nil {
			t.Fatalf("unmarshalComponentSet(%s) = %v, want the C8s vector to parse", v.ExtensionDER, err)
		}
		if want := version + " " + v.Digest; got.String() != want {
			t.Errorf("unmarshalComponentSet(%s) = %s, want %s", v.ExtensionDER, got, want)
		}
	}
}

func TestUnmarshalComponentSetRejects(t *testing.T) {
	digest := bytes.Repeat([]byte{0x63}, 32)
	marshal := func(v any) []byte {
		der, err := asn1.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	valid := marshal(componentSetASN1{Version: "0.43.0", Digest: digest})
	// The same SEQUENCE with its length in long form: DER, but not minimal.
	longForm := append([]byte{0x30, 0x81, valid[1]}, valid[2:]...)
	for _, tc := range []struct {
		name    string
		der     []byte
		wantErr string
	}{
		{"short digest", marshal(componentSetASN1{Version: "0.43.0", Digest: digest[:31]}), "must be 32 bytes"},
		{"long digest", marshal(componentSetASN1{Version: "0.43.0", Digest: append(digest, 0)}), "must be 32 bytes"},
		{"two-part version", marshal(componentSetASN1{Version: "0.43", Digest: digest}), "not MAJOR.MINOR.PATCH"},
		{"leading zero", marshal(componentSetASN1{Version: "0.043.0", Digest: digest}), "not MAJOR.MINOR.PATCH"},
		{"pre-release", marshal(componentSetASN1{Version: "0.43.0-rc.1", Digest: digest}), "not MAJOR.MINOR.PATCH"},
		{"trailing bytes", append(bytes.Clone(valid), 0x00), "trailing bytes"},
		{"long-form length", longForm, "non-minimal length"},
		{"printable string version", marshal(struct {
			Version string `asn1:"printable"`
			Digest  []byte
		}{"0.43.0", digest}), "not the canonical encoding"},
		{"extra field", marshal(struct {
			Version string `asn1:"utf8"`
			Digest  []byte
			Extra   int
		}{"0.43.0", digest, 1}), "not the canonical encoding"},
		{"not a sequence", marshal("0.43.0"), "unmarshal component set"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := unmarshalComponentSet(tc.der)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("unmarshalComponentSet(%x) = %v, %v, want an error containing %q", tc.der, got, err, tc.wantErr)
			}
		})
	}
}

func TestComponentSetDigestMatchesC8s(t *testing.T) {
	raw, vectors := loadComponentSetFixture(t)
	var indented bytes.Buffer
	if err := json.Indent(&indented, raw, "", "  "); err != nil {
		t.Fatal(err)
	}
	for name, doc := range map[string][]byte{"canonical": raw, "indented": indented.Bytes()} {
		parsed, err := ParsePinnedAllowlist(doc)
		if err != nil {
			t.Fatal(err)
		}
		for version, v := range vectors.Sets {
			digest, err := parsed.Components[version].digest()
			if err != nil {
				t.Fatal(err)
			}
			if got := "sha256:" + hexOf(digest[:]); got != v.Digest {
				t.Errorf("%s document: set %s digest = %s, want %s", name, version, got, v.Digest)
			}
		}
	}
}

func TestPinnedAllowlistResolves(t *testing.T) {
	raw, _ := loadComponentSetFixture(t)
	withComponents, err := ParsePinnedAllowlist(raw)
	if err != nil {
		t.Fatal(err)
	}
	without, err := ParsePinnedAllowlist(defaultAllowlistRaw)
	if err != nil {
		t.Fatal(err)
	}
	unreadable, err := ParsePinnedAllowlist([]byte(`{"schema":"c8s.allowlist/v1","workloads":{},"components":{` +
		`"0.1.0":{"entries":{"bad-deadline":{}},"retire":{"deadline":"2026-12-01T00:00:00.5Z"}},` +
		`"0.2.0":{"entries":{"unknown-field":{}},"extra":true},` +
		`"1.0.0":{"entries":{"other-major":{}}}}}`))
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name string
		doc  *PinnedAllowlist
		at   time.Time
		want bool
	}{
		{"tenant-api", withComponents, deadline, true},
		{"c8s-router", withComponents, deadline, true},
		{"volumed", withComponents, deadline, true},
		{"c8s-router-old", withComponents, deadline.Add(-time.Second), true},
		{"c8s-router-old", withComponents, deadline, false},
		{"unknown", withComponents, deadline, false},
		{"api", without, deadline, true},
		{"c8s-router", without, deadline, false},
		{"bad-deadline", unreadable, deadline.Add(-time.Hour), false},
		{"unknown-field", unreadable, deadline, false},
		{"other-major", unreadable, deadline, false},
	} {
		if got := tc.doc.Resolves(tc.name, tc.at); got != tc.want {
			t.Errorf("Resolves(%q, %s) = %v, want %v", tc.name, tc.at.Format(time.RFC3339), got, tc.want)
		}
	}
}

func TestComponentSetMismatch(t *testing.T) {
	raw, vectors := loadComponentSetFixture(t)
	doc, err := ParsePinnedAllowlist(raw)
	if err != nil {
		t.Fatal(err)
	}
	without, err := ParsePinnedAllowlist(defaultAllowlistRaw)
	if err != nil {
		t.Fatal(err)
	}
	current := fixtureSet(t, vectors, "0.43.0")
	for _, tc := range []struct {
		name    string
		doc     *PinnedAllowlist
		leaf    *ComponentSet
		wantErr string
	}{
		{"no leaf set", doc, nil, ""},
		{"document without components", without, current, ""},
		{"current set", doc, current, ""},
		{"retiring set", doc, fixtureSet(t, vectors, "0.42.1"), ""},
		{"other digest", doc, &ComponentSet{Version: "0.43.0", Digest: fixtureSet(t, vectors, "0.42.1").Digest}, "has digest " + vectors.Sets["0.43.0"].Digest},
		{"unknown version", doc, &ComponentSet{Version: "0.44.0", Digest: current.Digest}, "holds no set 0.44.0 (it holds 0.42.1, 0.43.0)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.doc.componentSetMismatch(tc.leaf)
			if tc.wantErr == "" && err != nil || tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("componentSetMismatch(%v) = %v, want error containing %q", tc.leaf, err, tc.wantErr)
			}
		})
	}
}

func TestPinnedPolicyDigestAcceptsComponents(t *testing.T) {
	_, vectors := loadComponentSetFixture(t)
	got, err := PinnedPolicyDigest(filepath.Join("testdata", "componentsets", "allowlist.json"))
	if err != nil {
		t.Fatalf("PinnedPolicyDigest(allowlist.json) = %v, want a document with components accepted", err)
	}
	if want := "sha256:" + vectors.AllowlistSHA256; got != want {
		t.Errorf("PinnedPolicyDigest(allowlist.json) = %s, want %s", got, want)
	}
}

func TestAttestLBComponentSet(t *testing.T) {
	raw, vectors := loadComponentSetFixture(t)
	current := fixtureSet(t, vectors, "0.43.0")
	dir := t.TempDir()
	allowlistPath := filepath.Join(dir, "allowlist.json")
	if err := os.WriteFile(allowlistPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	routerStamp := func(t *testing.T) pkix.Extension { return stampExt(t, "c8s-router", "7", sha256Of(raw)) }
	digestPin := "0.43.0@" + vectors.Sets["0.43.0"].Digest
	otherDigestPin := "0.43.0@" + vectors.Sets["0.42.1"].Digest
	for _, tc := range []struct {
		name      string
		set       *ComponentSet // nil: the leaf carries none
		rawExt    []byte        // a malformed extension value instead of set
		pins      []string
		allowlist bool
		want      string
		wantErr   string
	}{
		{name: "absent unpinned"},
		{name: "reported unpinned", set: current, want: current.String()},
		{name: "version pin", set: current, pins: []string{"0.43.0"}, want: current.String()},
		{name: "digest pin", set: current, pins: []string{digestPin}, want: current.String()},
		{name: "any pin matches", set: current, pins: []string{"0.42.1", digestPin}, want: current.String()},
		{name: "version mismatch", set: current, pins: []string{"0.42.1"}, wantErr: "mesh leaf component set " + current.String() + " does not match the pinned 0.42.1"},
		{name: "digest mismatch", set: current, pins: []string{otherDigestPin}, wantErr: "does not match the pinned " + otherDigestPin},
		{name: "pin without the extension", pins: []string{"0.43.0"}, wantErr: "carries no component set"},
		{name: "malformed fails unpinned", rawExt: []byte{0x30, 0x00}, wantErr: "component set"},
		{name: "allowlist holds the set", set: current, allowlist: true, want: current.String()},
		{name: "allowlist lacks the set", set: &ComponentSet{Version: "0.44.0", Digest: current.Digest}, allowlist: true, wantErr: "holds no set 0.44.0"},
		{name: "allowlist set has another digest", set: &ComponentSet{Version: "0.43.0", Digest: fixtureSet(t, vectors, "0.42.1").Digest}, allowlist: true, wantErr: "has digest " + vectors.Sets["0.43.0"].Digest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stubEvidence(t)
			exts := []pkix.Extension{routerStamp(t)}
			switch {
			case tc.rawExt != nil:
				exts = append(exts, pkix.Extension{Id: oidComponentSet, Value: tc.rawExt})
			case tc.set != nil:
				exts = append(exts, componentSetExt(t, tc.set.Version, tc.set.Digest))
			}
			f := newLBFixture(t, fixtureOpts{allowlistRaw: raw, stampExts: exts})
			ts := f.newServer(t, bundleSpec{})
			r := measuredRemote()
			r.ComponentSets = tc.pins
			if tc.allowlist {
				r.AllowlistPath = allowlistPath
			}
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
			got := ""
			if v.ComponentSet != nil {
				got = v.ComponentSet.String()
			}
			if got != tc.want {
				t.Errorf("ComponentSet = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestFetchAllowlistReportsComponentSetMismatch(t *testing.T) {
	raw, vectors := loadComponentSetFixture(t)
	current := fixtureSet(t, vectors, "0.43.0")
	for _, tc := range []struct {
		name    string
		set     *ComponentSet
		wantErr string
	}{
		{"matching set", current, ""},
		{"set the document lacks", &ComponentSet{Version: "0.44.0", Digest: current.Digest}, "holds no set 0.44.0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stubEvidence(t)
			exts := []pkix.Extension{
				stampExt(t, "c8s-router", "7", sha256Of(raw)),
				componentSetExt(t, tc.set.Version, tc.set.Digest),
			}
			f := newLBFixture(t, fixtureOpts{allowlistRaw: raw, stampExts: exts})
			doc, err := attestAndFetch(t, f, bundleSpec{allowlist: serveAllowlist(raw, "7")})
			if err != nil {
				t.Fatalf("FetchAllowlist() = %v, want the document returned", err)
			}
			got := doc.ComponentSetMismatch
			if tc.wantErr == "" && got != nil || tc.wantErr != "" && (got == nil || !strings.Contains(got.Error(), tc.wantErr)) {
				t.Fatalf("ComponentSetMismatch = %v, want error containing %q", got, tc.wantErr)
			}
		})
	}
}
