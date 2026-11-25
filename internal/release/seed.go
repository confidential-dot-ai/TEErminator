// Package release verifies the allowlist seeds a C8s release publishes: the
// signed release statement lists each seed's SHA-256 by CPU TEE
// (docs/releases.md in confidential-kubernetes).
package release

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// SeedPrefix marks a pinned_policies entry naming a release seed.
const SeedPrefix = "seed:"

// signerIssuer is the OIDC issuer of the release workflow's certificate.
const signerIssuer = "https://token.actions.githubusercontent.com"

// signerRepositoryID is GitHub's numeric ID of confidential-kubernetes, which
// Fulcio certifies as the source repository identifier. It survives the rename
// from C8s, and a repository later created under either name does not get it.
const signerRepositoryID = "1040957973"

// signerRepositories are the names releases were signed under: the
// repository was C8s before it became confidential-kubernetes.
var signerRepositories = []string{
	"confidential-dot-ai/confidential-kubernetes",
	"confidential-dot-ai/C8s",
}

// Platforms are the CPU TEEs a statement lists seeds for.
var Platforms = []string{"tdx", "sev-snp"}

var hexSHA256 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// SeedPin is a parsed "seed:<statement>:<platform>" entry.
type SeedPin struct {
	// Statement is the path of release-statement.json.
	Statement string
	// Platform is "tdx" or "sev-snp".
	Platform string
}

// Bundle is the path of the statement's Sigstore bundle, named as cosign
// and the release do: release-statement.sigstore.json beside it.
func (p SeedPin) Bundle() string {
	return strings.TrimSuffix(p.Statement, ".json") + ".sigstore.json"
}

// ParseSeedPin parses a "seed:<statement>:<platform>" entry. ok is false
// when entry does not start with SeedPrefix.
func ParseSeedPin(entry string) (pin SeedPin, ok bool, err error) {
	rest, ok := strings.CutPrefix(entry, SeedPrefix)
	if !ok {
		return SeedPin{}, false, nil
	}
	i := strings.LastIndexByte(rest, ':')
	if i <= 0 {
		return SeedPin{}, true, fmt.Errorf("seed pin %q is not seed:<release-statement.json>:<platform>", entry)
	}
	pin = SeedPin{Statement: rest[:i], Platform: rest[i+1:]}
	if !slices.Contains(Platforms, pin.Platform) {
		return SeedPin{}, true, fmt.Errorf("seed pin %q: platform %q is not one of %s", entry, pin.Platform, strings.Join(Platforms, ", "))
	}
	return pin, true, nil
}

type statement struct {
	Repository     string                `json:"repository"`
	Tag            string                `json:"tag"`
	AllowlistSeeds map[string]statedFile `json:"allowlistSeeds"`
}

type statedFile struct {
	Asset  string `json:"asset"`
	SHA256 string `json:"sha256"`
}

// VerifySeed returns the seed document, exactly as read. It reads the statement, its bundle and the seed it lists for
// p.Platform, which sits beside the statement under its asset name. The
// bundle must verify offline under trustedRoot (a Sigstore trusted_root.json)
// as signed by the release workflow, semver-tag.yml on main, of the
// repository the statement names; the seed must hash to the listed SHA-256.
func VerifySeed(p SeedPin, trustedRoot string) ([]byte, error) {
	raw, err := os.ReadFile(p.Statement)
	if err != nil {
		return nil, fmt.Errorf("read release statement: %w", err)
	}
	var st statement
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, fmt.Errorf("release statement %s: %w", p.Statement, err)
	}
	if err := verifyStatement(raw, st.Repository, signerRepositoryID, p.Bundle(), trustedRoot); err != nil {
		return nil, fmt.Errorf("release statement %s: %w", p.Statement, err)
	}
	if st.AllowlistSeeds == nil {
		return nil, fmt.Errorf("release statement %s (%s) lists no allowlistSeeds: the release predates published seeds", p.Statement, st.Tag)
	}
	listed, ok := st.AllowlistSeeds[p.Platform]
	if !ok {
		return nil, fmt.Errorf("release statement %s (%s) lists no allowlist seed for %s", p.Statement, st.Tag, p.Platform)
	}
	if !hexSHA256.MatchString(listed.SHA256) {
		return nil, fmt.Errorf("release statement %s: allowlist seed %s sha256 %q is not 64 lowercase hex", p.Statement, p.Platform, listed.SHA256)
	}
	if listed.Asset == "" || filepath.Base(listed.Asset) != listed.Asset || listed.Asset == "." || listed.Asset == ".." {
		return nil, fmt.Errorf("release statement %s: allowlist seed asset %q is not a file name", p.Statement, listed.Asset)
	}
	seedPath := filepath.Join(filepath.Dir(p.Statement), listed.Asset)
	seed, err := os.ReadFile(seedPath)
	if err != nil {
		return nil, fmt.Errorf("read allowlist seed: %w", err)
	}
	sum := sha256.Sum256(seed)
	if got := hex.EncodeToString(sum[:]); got != listed.SHA256 {
		return nil, fmt.Errorf("allowlist seed %s has sha256 %s, release statement %s (%s) lists %s", seedPath, got, p.Statement, st.Tag, listed.SHA256)
	}
	return seed, nil
}

// verifyStatement checks the bundle signs raw under the release workflow
// identity of repository, the statement's own field, so the field is bound
// to the signer, from the repository whose GitHub ID is repositoryID.
func verifyStatement(raw []byte, repository, repositoryID, bundlePath, trustedRoot string) error {
	if !slices.Contains(signerRepositories, repository) {
		return fmt.Errorf("repository %q is not one of %s", repository, strings.Join(signerRepositories, ", "))
	}
	tr, err := root.NewTrustedRootFromPath(trustedRoot)
	if err != nil {
		return fmt.Errorf("sigstore trusted root: %w", err)
	}
	b, err := bundle.LoadJSONFromPath(bundlePath)
	if err != nil {
		return fmt.Errorf("sigstore bundle: %w", err)
	}
	v, err := verify.NewVerifier(tr,
		verify.WithSignedCertificateTimestamps(1),
		verify.WithTransparencyLog(1),
		verify.WithObserverTimestamps(1))
	if err != nil {
		return err
	}
	san, err := verify.NewSANMatcher(signerIdentity(repository), "")
	if err != nil {
		return err
	}
	issuer, err := verify.NewIssuerMatcher(signerIssuer, "")
	if err != nil {
		return err
	}
	identity, err := verify.NewCertificateIdentity(san, issuer, certificate.Extensions{SourceRepositoryIdentifier: repositoryID})
	if err != nil {
		return err
	}
	if _, err := v.Verify(b, verify.NewPolicy(verify.WithArtifact(bytes.NewReader(raw)), verify.WithCertificateIdentity(identity))); err != nil {
		return fmt.Errorf("signature of %s: %w", bundlePath, err)
	}
	return nil
}

// signerIdentity is the certificate identity that signs repository's
// release statements (RELEASE_SIGNER_IDENTITY in semver-tag.yml).
func signerIdentity(repository string) string {
	return "https://github.com/" + repository + "/.github/workflows/semver-tag.yml@refs/heads/main"
}
