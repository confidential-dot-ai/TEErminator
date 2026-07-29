package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

type AuthType string

const (
	AuthNone  AuthType = "None"
	AuthToken AuthType = "Token"
	AuthMTLS  AuthType = "mTLS"
)

type TrustStatus string

const (
	StatusUnknown   TrustStatus = "Unknown"
	StatusVerified  TrustStatus = "Verified"
	StatusUntrusted TrustStatus = "Untrusted"
	StatusFailed    TrustStatus = "Failed"
)

// AttestMode selects how a remote's TEE attestation is verified.
type AttestMode string

const (
	// AttestNone disables attestation verification (current default behaviour).
	AttestNone AttestMode = ""
	// AttestEndpoint fetches a fresh attestation from a dedicated endpoint at
	// session start and pins the session to the attested TLS leaf.
	AttestEndpoint AttestMode = "attest"
	// AttestCDSCert fetches and pins the CDS cert before trusting the
	// connection.
	AttestCDSCert AttestMode = "cds-cert"
)

// CertPin records a certificate pinned by a cds-cert bootstrap so later sessions
// trust the same cert without re-fetching.
type CertPin struct {
	SHA256   string `json:"sha256"`
	NotAfter string `json:"not_after,omitempty"`
	PEM      string `json:"pem,omitempty"`
}

type Remote struct {
	Local        string      `json:"local"`
	Remote       string      `json:"remote"`
	Auth         AuthType    `json:"auth"`
	Status       TrustStatus `json:"status"`
	Token        string      `json:"token,omitempty"`
	Mode         AttestMode  `json:"mode,omitempty"`
	DiscoveryURL string      `json:"discovery_url,omitempty"`
	// ServerName overrides the TLS SNI / certificate name the upstream is
	// validated against, for when the --remote host has no matching SAN — e.g.
	// a LoadBalancer reached by raw IP whose cert only carries an internal DNS
	// SAN (`c8s-tls-lb.c8s-system.svc`). The connection still dials the URL host;
	// only the certificate identity is checked against this name (like
	// `curl --resolve <name>:<port>:<ip>`). Pair with a `certs add <ca.pem>`
	// trust anchor so the chain also verifies.
	ServerName   string   `json:"server_name,omitempty"`
	Measurements []string `json:"measurements,omitempty"` // accepted hex launch digests
	// ExpectedRTMR3 pins the remote's TDX runtime measurement register as 96
	// hex chars. Empty = no pin.
	//
	// Measurements pin the *code* — but the image is open source and
	// reproducible, so a valid launch digest only proves "a genuine instance of
	// the audited build on real silicon", which an attacker can also stand up.
	// RTMR[3] carries what is unique to a deployment: the operator key bound at
	// launch, plus any per-workload extends. Pinning it is what makes the
	// verdict "this operator's cluster" rather than "some genuine cluster".
	//
	// TDX only — SNP has no runtime-extend register, and attestation-go
	// consults RTMR pins only on the TDX path, so a pin set for any other
	// platform would be silently ignored.
	ExpectedRTMR3 string   `json:"expected_rtmr3,omitempty"`
	Pin           *CertPin `json:"pin,omitempty"`
}

// ValidAttestMode reports whether s is a recognised attestation mode.
func ValidAttestMode(s string) bool {
	switch AttestMode(s) {
	case AttestNone, AttestEndpoint, AttestCDSCert:
		return true
	default:
		return false
	}
}

type Cert struct {
	CommonName string `json:"common_name"`
	PEM        string `json:"pem"`
}

// CDSIdentityCache is the persisted verdict of one CDS attestation, keyed by
// the derive target (the front-door base URL).
//
// The CDS RA-TLS certificate is immutable once issued, so its SHA-256
// fingerprint is both the cache key and the invalidation signal: as long as the
// freshly fetched certificate's fingerprint equals Fingerprint and the clock is
// inside [NotBefore, NotAfter], the previous quote verification still stands
// and can be skipped. A changed fingerprint means CDS re-issued (allowlist
// change or restart) and forces a full re-attestation.
//
// NotBefore is also the monotonic rollback floor: a re-issued certificate must
// not be older than the one last verified (see verifier.CachedAttestor).
type CDSIdentityCache struct {
	// Target is the front-door base URL the identity was derived from.
	Target string `json:"target"`
	// Fingerprint is hex SHA-256 of the verified certificate's DER.
	Fingerprint string `json:"fingerprint"`
	// NotBefore/NotAfter are the verified certificate's validity window. They
	// are trustworthy because AttestCDSIdentity verifies the certificate's
	// self-signature against its REPORTDATA-bound key, extending the hardware
	// binding to the whole tbsCertificate.
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	// VerifiedAt is when the full quote verification last ran (never updated
	// by a cache hit — a hit reuses this verdict, it does not mint a new one).
	VerifiedAt time.Time `json:"verified_at"`
	// LaunchDigest and RTMR3 are the signature-verified claims the policy was
	// evaluated against, kept so a cache hit can re-evaluate a *changed*
	// policy without re-running quote verification.
	LaunchDigest string `json:"launch_digest,omitempty"`
	RTMR3        string `json:"rtmr_3,omitempty"`
	// MeshCADigest and AllowlistDigest are the attested config-claims digests
	// (hex), exactly as returned by the verified attestation.
	MeshCADigest    string `json:"mesh_ca_digest"`
	AllowlistDigest string `json:"allowlist_digest,omitempty"`
}

type Config struct {
	Remotes []Remote `json:"remotes"`
	Certs   []Cert   `json:"certs,omitempty"`
	// CDSIdentities caches verified CDS attestations, one per derive target.
	CDSIdentities []CDSIdentityCache `json:"cds_identities,omitempty"`
}

func configPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "teerminator", "config.json"), nil
}

func Load() (*Config, error) {
	path, err := configPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &Config{}, nil
	}
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) Save() error {
	path, err := configPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func (c *Config) FindByLocal(local string) *Remote {
	for i := range c.Remotes {
		if c.Remotes[i].Local == local {
			return &c.Remotes[i]
		}
	}
	return nil
}

// FindByKey resolves a remote by either its 1-based index (as printed by
// `remote ls`) or its local address.
func (c *Config) FindByKey(key string) *Remote {
	if n, err := strconv.Atoi(key); err == nil {
		if n >= 1 && n <= len(c.Remotes) {
			return &c.Remotes[n-1]
		}
		return nil
	}
	return c.FindByLocal(key)
}

func (c *Config) AddRemote(r Remote) error {
	if c.FindByLocal(r.Local) != nil {
		return errors.New("a remote with that local address already exists")
	}
	c.Remotes = append(c.Remotes, r)
	return nil
}

func (c *Config) FindRemoteByName(name string) *Remote {
	for i := range c.Remotes {
		if c.Remotes[i].Local == name {
			return &c.Remotes[i]
		}
	}
	return nil
}

func (c *Config) RemoveRemote(local string) bool {
	for i, r := range c.Remotes {
		if r.Local == local {
			c.Remotes = append(c.Remotes[:i], c.Remotes[i+1:]...)
			return true
		}
	}
	return false
}

func (c *Config) FindCertByName(commonName string) *Cert {
	for i := range c.Certs {
		if c.Certs[i].CommonName == commonName {
			return &c.Certs[i]
		}
	}
	return nil
}

func (c *Config) AddCert(cert Cert) error {
	if c.FindCertByName(cert.CommonName) != nil {
		return errors.New("a certificate with that common name already exists")
	}
	c.Certs = append(c.Certs, cert)
	return nil
}

// FindCDSIdentity returns the cached CDS attestation for a derive target, or
// nil when none has been recorded.
func (c *Config) FindCDSIdentity(target string) *CDSIdentityCache {
	for i := range c.CDSIdentities {
		if c.CDSIdentities[i].Target == target {
			return &c.CDSIdentities[i]
		}
	}
	return nil
}

// UpsertCDSIdentity records a verified CDS attestation for its target,
// replacing any previous entry for the same target.
func (c *Config) UpsertCDSIdentity(entry CDSIdentityCache) {
	for i := range c.CDSIdentities {
		if c.CDSIdentities[i].Target == entry.Target {
			c.CDSIdentities[i] = entry
			return
		}
	}
	c.CDSIdentities = append(c.CDSIdentities, entry)
}

func (c *Config) RemoveCert(commonName string) bool {
	for i, cert := range c.Certs {
		if cert.CommonName == commonName {
			c.Certs = append(c.Certs[:i], c.Certs[i+1:]...)
			return true
		}
	}
	return false
}
