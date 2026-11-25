package release

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	trustedRoot = "testdata/trusted_root.json"
	// tdxSeedSHA256 is allowlistSeeds.tdx.sha256 of v0.108.0.
	tdxSeedSHA256 = "894ea078448423e53fb659513b214486dedb527394cec373bb55985e277066c3"
)

// release copies the files of testdata/<tag> into a temporary directory and
// applies edit, so a case can tamper with one of them.
func release(t *testing.T, tag string, edit func(dir string)) string {
	t.Helper()
	dir := t.TempDir()
	entries, err := os.ReadDir(filepath.Join("testdata", tag))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		raw, err := os.ReadFile(filepath.Join("testdata", tag, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, e.Name()), raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if edit != nil {
		edit(dir)
	}
	return filepath.Join(dir, "release-statement.json")
}

func rewrite(t *testing.T, path, old, replacement string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(old)) {
		t.Fatalf("%s holds no %q", path, old)
	}
	if err := os.WriteFile(path, bytes.Replace(raw, []byte(old), []byte(replacement), 1), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestVerifySeed(t *testing.T) {
	tests := []struct {
		name     string
		tag      string
		platform string
		edit     func(t *testing.T, dir string)
		root     string
		wantErr  string
	}{
		{name: "good seed", tag: "v0.108.0", platform: "tdx"},
		{
			name: "tampered seed", tag: "v0.108.0", platform: "tdx",
			edit: func(t *testing.T, dir string) {
				rewrite(t, filepath.Join(dir, "allowlist-seed-tdx.json"), "armtls-mesh", "armtls-mesx")
			},
			wantErr: "lists " + tdxSeedSHA256,
		},
		{
			name: "wrong platform", tag: "v0.108.0", platform: "sev-snp",
			edit: func(t *testing.T, dir string) {
				raw, err := os.ReadFile(filepath.Join(dir, "allowlist-seed-tdx.json"))
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "allowlist-seed-sev-snp.json"), raw, 0o644); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: "lists be668d069c28c4a534e33ad0e5d1d7772db20be4683ad9f4952b4ec2898f49d4",
		},
		{name: "seed file missing", tag: "v0.108.0", platform: "sev-snp", wantErr: "read allowlist seed"},
		{name: "statement without allowlistSeeds", tag: "v0.100.0", platform: "tdx", wantErr: "lists no allowlistSeeds"},
		{
			name: "bad signature", tag: "v0.108.0", platform: "tdx",
			edit: func(t *testing.T, dir string) {
				rewrite(t, filepath.Join(dir, "release-statement.json"), tdxSeedSHA256, strings.Repeat("0", 64))
			},
			wantErr: "signature of",
		},
		{
			name: "repository renamed in the statement", tag: "v0.108.0", platform: "tdx",
			edit: func(t *testing.T, dir string) {
				rewrite(t, filepath.Join(dir, "release-statement.json"), `"confidential-dot-ai/confidential-kubernetes"`, `"confidential-dot-ai/C8s"`)
			},
			wantErr: "signature of",
		},
		{
			name: "foreign repository", tag: "v0.108.0", platform: "tdx",
			edit: func(t *testing.T, dir string) {
				rewrite(t, filepath.Join(dir, "release-statement.json"), `"confidential-dot-ai/confidential-kubernetes"`, `"example/fork"`)
			},
			wantErr: `repository "example/fork" is not one of`,
		},
		{
			name: "bundle missing", tag: "v0.108.0", platform: "tdx",
			edit: func(t *testing.T, dir string) {
				if err := os.Remove(filepath.Join(dir, "release-statement.sigstore.json")); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: "sigstore bundle",
		},
		{name: "trusted root missing", tag: "v0.108.0", platform: "tdx", root: "testdata/none.json", wantErr: "sigstore trusted root"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var edit func(string)
			if tt.edit != nil {
				edit = func(dir string) { tt.edit(t, dir) }
			}
			pin := SeedPin{Statement: release(t, tt.tag, edit), Platform: tt.platform}
			root := tt.root
			if root == "" {
				root = trustedRoot
			}
			got, err := VerifySeed(pin, root)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("VerifySeed(%s) error = %v, want one containing %q", tt.name, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("VerifySeed(%s) error = %v", tt.name, err)
			}
			sum := sha256.Sum256(got)
			if hex.EncodeToString(sum[:]) != tdxSeedSHA256 {
				t.Errorf("VerifySeed(%s) sha256 = %x, want %s", tt.name, sum, tdxSeedSHA256)
			}
		})
	}
}

func TestVerifySeedPreRenameRepository(t *testing.T) {
	// v0.100.0 has no seeds, so reaching the allowlistSeeds check proves its
	// C8s-named signature verified.
	pin := SeedPin{Statement: release(t, "v0.100.0", nil), Platform: "tdx"}
	_, err := VerifySeed(pin, trustedRoot)
	if err == nil || !strings.Contains(err.Error(), "lists no allowlistSeeds") {
		t.Fatalf("VerifySeed(v0.100.0) error = %v, want the missing allowlistSeeds", err)
	}
}

func TestParseSeedPin(t *testing.T) {
	tests := []struct {
		entry   string
		want    SeedPin
		wantOK  bool
		wantErr bool
	}{
		{entry: "seed:/r/release-statement.json:tdx", want: SeedPin{"/r/release-statement.json", "tdx"}, wantOK: true},
		{entry: "seed:C:/r/s.json:sev-snp", want: SeedPin{"C:/r/s.json", "sev-snp"}, wantOK: true},
		{entry: "seed:/r/release-statement.json:snp", wantOK: true, wantErr: true},
		{entry: "seed:/r/release-statement.json", wantOK: true, wantErr: true},
		{entry: "seed::tdx", wantOK: true, wantErr: true},
		{entry: "./allowlist.json"},
		{entry: "sha256:" + tdxSeedSHA256},
	}
	for _, tt := range tests {
		got, ok, err := ParseSeedPin(tt.entry)
		if ok != tt.wantOK || (err != nil) != tt.wantErr || (err == nil && got != tt.want) {
			t.Errorf("ParseSeedPin(%q) = %+v, %v, %v, want %+v, %v, error %v", tt.entry, got, ok, err, tt.want, tt.wantOK, tt.wantErr)
		}
	}
}

func TestSeedPinBundle(t *testing.T) {
	if got, want := (SeedPin{Statement: "/r/release-statement.json"}).Bundle(), "/r/release-statement.sigstore.json"; got != want {
		t.Errorf("Bundle() = %q, want %q", got, want)
	}
}
