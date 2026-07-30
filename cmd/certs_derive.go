package cmd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/confidential-dot-ai/TEErminator/internal/config"
	"github.com/confidential-dot-ai/TEErminator/internal/verifier"
	"github.com/spf13/cobra"
)

// newCertsDeriveCmd builds `certs derive`, the attested alternative to
// `certs add`.
//
// `certs add` trusts a file because someone sent it to you. This command
// derives the same CA from hardware evidence: it fetches CDS's own RA-TLS
// certificate from the front door's discovery document, verifies its
// attestation, and accepts the served mesh CA only if it matches the digest
// those verified claims commit to. Same end state — a CA in the trust store —
// but reached by verification rather than by trusting a courier.
func newCertsDeriveCmd() *cobra.Command {
	var (
		measurements  []string
		expectedRTMR3 string
		discoveryPath string
		meshCAPath    string
		allowlistPath string
		timeout       time.Duration
		insecure      bool
		allowRollback bool
	)

	cmd := &cobra.Command{
		Use:   "derive <front-door-base-url>",
		Short: "Derive the mesh CA by attesting CDS, instead of trusting a PEM file",
		Long: `Derive the mesh CA from a verified CDS attestation.

Fetches CDS's own RA-TLS certificate from <base-url>` + defaultDiscoveryPath + `,
verifies its hardware evidence and config-claims, then fetches the served mesh
CA and accepts it only if its digest matches what the verified claims commit to.

Without --measurements any genuine TEE is accepted, which is UNSAFE outside
development: it proves the CA came from real confidential hardware, but not
from YOUR cluster. Pin --measurements (and --expected-rtmr3 on TDX) to bind it
to a specific image and deployment.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			base := strings.TrimRight(args[0], "/")

			client := &http.Client{Timeout: timeout}
			if insecure {
				// The transport is deliberately not the trust anchor here: the
				// CDS certificate is self-authenticating and the mesh CA is
				// checked against an attested digest. Skipping transport
				// verification cannot weaken either check — it only allows
				// bootstrapping from a front door whose own chain is not yet
				// trusted, which is the normal case before the CA is installed.
				client.Transport = &http.Transport{
					TLSClientConfig: insecureTLSConfig(),
				}
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
			defer cancel()

			if len(measurements) == 0 {
				fmt.Println("WARNING: no --measurements pinned — any genuine TEE is accepted (UNSAFE outside development)")
			}

			// Config is loaded up front because the cached attestation verdict
			// for this target feeds the verification step itself: a fingerprint
			// match skips the quote verification, a mismatch triggers the
			// rollback check against the cached NotBefore.
			cfg, err := config.Load()
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}
			cached := cfg.FindCDSIdentity(base)

			attestor := &verifier.CachedAttestor{AllowRollback: allowRollback}
			caPEM, id, entry, hit, err := attestor.DeriveMeshCAWithCache(ctx, client,
				base+discoveryPath, base+meshCAPath,
				verifier.CDSPolicy{Measurements: measurements, ExpectedRTMR3: expectedRTMR3},
				cached)
			if err != nil {
				return err
			}
			if hit {
				fmt.Printf("CDS attestation cache hit (%.12s…): certificate unchanged since last full verification at %s — quote verification skipped\n",
					entry.Fingerprint, entry.VerifiedAt.Format(time.RFC3339))
			}

			// Check the allowlist the endpoint serves RIGHT NOW against the
			// digest the certificate attests, before anything is written to
			// the trust store.
			//
			// Printing the attested digest without this check was misleading in
			// exactly the case that matters. CDS re-issues its serving
			// certificate within seconds of an allowlist change, but the
			// certificate republished in the discovery document is a copy
			// recorded when get-cert last ran, so it can lag arbitrarily. A
			// stale copy still verifies — its evidence is self-consistent — and
			// the digest it carries then describes a policy that is no longer
			// in force. Comparing against the served bytes is what turns
			// "this certificate says X" into "X is what this endpoint enforces".
			if hasAttestedAllowlist(id) {
				raw, err := fetchAllowlist(ctx, client, base+allowlistPath)
				if err != nil {
					return fmt.Errorf("fetch %s: %w", base+allowlistPath, err)
				}
				if err := id.VerifyAllowlist(raw); err != nil {
					return fmt.Errorf("%w\n\nThe attested certificate and the served allowlist disagree. Either the "+
						"allowlist changed and the discovery document still publishes an older CDS certificate, "+
						"or the endpoint is serving a policy it cannot attest", err)
				}
			}

			block, _ := pem.Decode(caPEM)
			if block == nil {
				return fmt.Errorf("derived mesh CA is not PEM")
			}
			ca, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return fmt.Errorf("parse derived mesh CA: %w", err)
			}
			commonName := ca.Subject.CommonName
			if commonName == "" {
				return fmt.Errorf("derived mesh CA has no common name")
			}

			// Replace rather than duplicate: the mesh CA regenerates whenever
			// CDS restarts, so re-deriving is routine and must converge on one
			// entry instead of accumulating stale anchors.
			cfg.RemoveCert(commonName)
			if err := cfg.AddCert(config.Cert{CommonName: commonName, PEM: string(caPEM)}); err != nil {
				return err
			}
			// The cache entry exists only because full verification (or a
			// still-valid cached verdict) succeeded above; persisting it here —
			// after every check has passed and alongside the CA it vouches for
			// — is what makes the write ordering safe.
			entry.Target = base
			cfg.UpsertCDSIdentity(*entry)
			if err := cfg.Save(); err != nil {
				return fmt.Errorf("saving config: %w", err)
			}

			fmt.Printf("Derived mesh CA %q from a verified CDS attestation\n", commonName)
			fmt.Printf("  CDS launch digest   %s\n", id.LaunchDigest)
			fmt.Printf("  CDS cert SHA-256    %s\n", id.FingerprintHex())
			fmt.Printf("  mesh CA digest      %s (attested)\n", hex.EncodeToString(id.MeshCADigest))
			if hasAttestedAllowlist(id) {
				fmt.Printf("  live allowlist      %s (matches the bytes served now)\n", hex.EncodeToString(id.AllowlistDigest))
			}
			fmt.Printf("\nRe-run this when the CDS cert SHA-256 changes; CDS re-issues on every\n")
			fmt.Printf("allowlist change, so a changed fingerprint is exactly when to re-attest.\n")
			return nil
		},
	}

	f := cmd.Flags()
	f.StringSliceVar(&measurements, "measurements", nil, "accepted hex launch digest(s) for CDS (repeatable/comma-separated); empty accepts any genuine TEE (UNSAFE)")
	f.StringVar(&expectedRTMR3, "expected-rtmr3", "", "expected TDX RTMR[3] as 96 hex chars — pins the deployment (operator key), not just the image")
	f.StringVar(&discoveryPath, "discovery-path", defaultDiscoveryPath, "path of the discovery document on the front door")
	f.StringVar(&meshCAPath, "mesh-ca-path", defaultMeshCAPath, "path the front door serves the mesh CA PEM at")
	f.StringVar(&allowlistPath, "allowlist-path", defaultAllowlistPath, "path the front door serves the live allowlist at; its exact bytes are checked against the attested digest")
	f.DurationVar(&timeout, "timeout", 30*time.Second, "overall timeout")
	f.BoolVar(&insecure, "insecure-transport", false, "skip TLS verification of the front door itself; the CDS certificate and mesh CA are still fully verified (needed to bootstrap before the CA is installed)")
	f.BoolVar(&allowRollback, "allow-rollback", false, "accept a CDS certificate OLDER (by notBefore) than the last verified one; normally refused as a replayed (cert, allowlist) pair — use only for a deliberate re-bootstrap, e.g. against a restored cluster")
	return cmd
}

const (
	defaultDiscoveryPath = "/v1/discovery"
	defaultMeshCAPath    = "/.well-known/mesh-ca.pem"
	defaultAllowlistPath = "/allowlist"
)

func hasAttestedAllowlist(id *verifier.CDSIdentity) bool {
	for _, b := range id.AllowlistDigest {
		if b != 0 {
			return true
		}
	}
	return false
}

// insecureTLSConfig disables transport verification for the bootstrap fetch.
// Safe here only because neither trust decision rides on the transport: the CDS
// certificate carries its own hardware evidence, and the mesh CA is accepted
// solely on a digest match against those verified claims.
func insecureTLSConfig() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true} //nolint:gosec // see comment
}

// fetchAllowlist reads the allowlist response verbatim. The digest CDS attests
// is taken over the canonical bytes it serves, so the body must not be parsed
// and re-encoded on the way here: a semantically identical re-serialization
// hashes differently and the mismatch would read as an attack.
func fetchAllowlist(ctx context.Context, client *http.Client, rawURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck // read-only
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s returned %d", rawURL, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}
