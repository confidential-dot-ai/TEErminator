// Package release fetches a signed GitHub release's verification pins: the
// Sigstore-signed release-bundle.json and the assets it names by digest.
package release

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

const (
	bundleName    = "release-bundle.json"
	signatureName = "release-bundle.sigstore.json"
	githubIssuer  = "https://token.actions.githubusercontent.com"
	maxAssetBytes = 16 << 20
)

// Source is one GitHub release.
type Source struct{ Owner, Repo, Tag string }

func (s Source) String() string { return s.Owner + "/" + s.Repo + "@" + s.Tag }

// releaseURL matches https://github.com/<owner>/<repo>/releases/{tag,download}/<tag>.
var releaseURL = regexp.MustCompile(`^https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/releases/(?:tag|download)/([^/]+)/?$`)

// ParseURL reads a GitHub release page or asset-download URL.
func ParseURL(s string) (Source, error) {
	m := releaseURL.FindStringSubmatch(s)
	if m == nil {
		return Source{}, fmt.Errorf("release %q: want https://github.com/<owner>/<repo>/releases/tag/<tag>", s)
	}
	tag, err := url.PathUnescape(m[3])
	if err != nil {
		return Source{}, fmt.Errorf("release %q: %w", s, err)
	}
	return Source{Owner: m[1], Repo: m[2], Tag: tag}, nil
}

// Pins are the verified files a remote pins, written under one directory.
type Pins struct {
	// ImageManifest is release-bundle.json itself: it carries the image
	// registers under tdx, as the confos build writes them.
	ImageManifest string
	Allowlist     string
	// OperatorKey is "" when the release publishes no operator key.
	OperatorKey string
}

// asset is a file release-bundle.json names by SHA-256.
type asset struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type releaseBundle struct {
	Allowlist   *asset `json:"allowlist"`
	OperatorKey *asset `json:"operatorKey"`
}

// Fetcher downloads and checks a release.
type Fetcher struct {
	Client *http.Client
	// BaseURL is the asset download root, https://github.com by default.
	BaseURL string
	// Trusted is the Sigstore trust root; nil fetches the public-good root
	// over TUF.
	Trusted root.TrustedMaterial
}

// Fetch verifies src's release-bundle.json against its Sigstore bundle — a
// GitHub Actions workflow of src's repository, run at src's tag, signed it —
// then downloads the assets it names, checks each digest, and writes the
// files to dir. Nothing is written unless every check passes.
func (f *Fetcher) Fetch(ctx context.Context, src Source, dir string) (*Pins, error) {
	rb, err := f.get(ctx, src, bundleName)
	if err != nil {
		return nil, err
	}
	sig, err := f.get(ctx, src, signatureName)
	if err != nil {
		return nil, err
	}
	trusted := f.Trusted
	if trusted == nil {
		if trusted, err = root.FetchTrustedRoot(); err != nil {
			return nil, fmt.Errorf("fetching the Sigstore trusted root: %w", err)
		}
	}
	if err := VerifySignature(trusted, sig, rb, src); err != nil {
		return nil, err
	}

	var doc releaseBundle
	if err := json.Unmarshal(rb, &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", bundleName, err)
	}
	if doc.Allowlist == nil {
		return nil, fmt.Errorf("%s names no allowlist", bundleName)
	}
	files := map[string][]byte{bundleName: rb}
	pins := &Pins{ImageManifest: filepath.Join(dir, bundleName)}
	for _, a := range []struct {
		field string
		asset *asset
		pin   *string
	}{
		{"allowlist", doc.Allowlist, &pins.Allowlist},
		{"operatorKey", doc.OperatorKey, &pins.OperatorKey},
	} {
		if a.asset == nil {
			continue
		}
		name := path.Base(a.asset.Path)
		if name == "." || name == "/" || name == bundleName {
			return nil, fmt.Errorf("%s %s: invalid path %q", bundleName, a.field, a.asset.Path)
		}
		body, err := f.get(ctx, src, name)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(body)
		if got := "sha256:" + hex.EncodeToString(sum[:]); got != a.asset.SHA256 {
			return nil, fmt.Errorf("%s: digest %s, the signed %s names %s", name, got, bundleName, a.asset.SHA256)
		}
		files[name] = body
		*a.pin = filepath.Join(dir, name)
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
			return nil, err
		}
	}
	return pins, nil
}

// VerifySignature checks that sig is a Sigstore bundle over artifact, logged
// in the transparency log, from a certificate GitHub Actions issued to a
// workflow of src's repository running at src's tag.
func VerifySignature(trusted root.TrustedMaterial, sig, artifact []byte, src Source) error {
	var b bundle.Bundle
	if err := b.UnmarshalJSON(sig); err != nil {
		return fmt.Errorf("%s: %w", signatureName, err)
	}
	v, err := verify.NewVerifier(trusted,
		verify.WithSignedCertificateTimestamps(1),
		verify.WithTransparencyLog(1),
		verify.WithObserverTimestamps(1))
	if err != nil {
		return err
	}
	san := fmt.Sprintf(`^https://github\.com/%s/%s/\.github/workflows/[^@]+@refs/tags/%s$`,
		regexp.QuoteMeta(src.Owner), regexp.QuoteMeta(src.Repo), regexp.QuoteMeta(src.Tag))
	id, err := verify.NewShortCertificateIdentity(githubIssuer, "", "", san)
	if err != nil {
		return err
	}
	if _, err := v.Verify(&b, verify.NewPolicy(verify.WithArtifact(bytes.NewReader(artifact)), verify.WithCertificateIdentity(id))); err != nil {
		return fmt.Errorf("%s does not verify %s as signed by a %s/%s workflow at tag %s: %w", signatureName, bundleName, src.Owner, src.Repo, src.Tag, err)
	}
	return nil
}

func (f *Fetcher) get(ctx context.Context, src Source, name string) ([]byte, error) {
	base := f.BaseURL
	if base == "" {
		base = "https://github.com"
	}
	u := strings.Join([]string{base, src.Owner, src.Repo, "releases/download", url.PathEscape(src.Tag), name}, "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := f.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", name, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching %s: %s", u, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAssetBytes+1))
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", name, err)
	}
	if len(body) > maxAssetBytes {
		return nil, errors.New("fetching " + name + ": larger than 16 MiB")
	}
	return body, nil
}
