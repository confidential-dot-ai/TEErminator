package cmd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
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
		timeout       time.Duration
		insecure      bool
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

			caPEM, id, err := verifier.DeriveMeshCA(ctx, client,
				base+discoveryPath, base+meshCAPath,
				verifier.CDSPolicy{Measurements: measurements, ExpectedRTMR3: expectedRTMR3})
			if err != nil {
				return err
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

			cfg, err := config.Load()
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}
			// Replace rather than duplicate: the mesh CA regenerates whenever
			// CDS restarts, so re-deriving is routine and must converge on one
			// entry instead of accumulating stale anchors.
			cfg.RemoveCert(commonName)
			if err := cfg.AddCert(config.Cert{CommonName: commonName, PEM: string(caPEM)}); err != nil {
				return err
			}
			if err := cfg.Save(); err != nil {
				return fmt.Errorf("saving config: %w", err)
			}

			fmt.Printf("Derived mesh CA %q from a verified CDS attestation\n", commonName)
			fmt.Printf("  CDS launch digest   %s\n", id.LaunchDigest)
			fmt.Printf("  CDS cert SHA-256    %s\n", id.FingerprintHex())
			fmt.Printf("  mesh CA digest      %s (attested)\n", hex.EncodeToString(id.MeshCADigest))
			if hasAttestedAllowlist(id) {
				fmt.Printf("  live allowlist      %s (attested)\n", hex.EncodeToString(id.AllowlistDigest))
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
	f.DurationVar(&timeout, "timeout", 30*time.Second, "overall timeout")
	f.BoolVar(&insecure, "insecure-transport", false, "skip TLS verification of the front door itself; the CDS certificate and mesh CA are still fully verified (needed to bootstrap before the CA is installed)")
	return cmd
}

const (
	defaultDiscoveryPath = "/v1/discovery"
	defaultMeshCAPath    = "/.well-known/mesh-ca.pem"
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
