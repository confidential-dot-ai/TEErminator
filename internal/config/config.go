package config

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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
	// AttestEndpoint fetches a fresh attest-lb attestation per TLS handshake
	// and pins the session to the exact attested serving leaf. The value was
	// renamed from the legacy "attest" (the retired pq=false query selector);
	// legacy configs are normalized at load time.
	AttestEndpoint AttestMode = "attest-lb"
	// legacyAttestEndpoint is the pre-attest-lb spelling, still accepted on
	// input and normalized to AttestEndpoint.
	legacyAttestEndpoint AttestMode = "attest"
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

// TCBFloor is a component-wise minimum AMD SEV-SNP TCB (`remote add --min-tcb`).
// Each component of the verified reported TCB must be at least its floor value.
type TCBFloor struct {
	Bootloader uint8 `json:"bootloader"`
	TEE        uint8 `json:"tee"`
	SNP        uint8 `json:"snp"`
	Microcode  uint8 `json:"microcode"`
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
	// WorkloadName pins the matched-workload stamp (OID …66378.1.5) the
	// committed mesh leaf must carry in attest-lb mode.
	WorkloadName string `json:"workload_name,omitempty"`
	// AllowlistPath points at a pinned canonical-allowlist JSON file. It is
	// hashed exactly as read (SHA-256 over the raw file bytes, never
	// reserialized) against the stamp's digest, and the stamped name must be a
	// key of its workloads map.
	AllowlistPath string `json:"allowlist_path,omitempty"`
	// PinnedPolicies are the reviewed policy digests (sha256:<hex>) a c8s
	// router's attested rollout bound must stay within (attest-lb). Empty
	// follows the deployment: the bound is verified and reported, not limited.
	PinnedPolicies []string `json:"pinned_policies,omitempty"`
	// ImageManifestPath points at a TDX image-pin manifest (JSON object with
	// mrtd, rtmr1, rtmr2, each 96 lowercase hex chars). All three registers are
	// compared byte-exactly against the verified claims — the launch digest
	// against MRTD included — so the manifest replaces Measurements rather than
	// adding to it; setting both is a configuration error. TDX evidence only —
	// with SNP evidence this pin is a policy error, never silently ignored.
	ImageManifestPath string `json:"image_manifest_path,omitempty"`
	// ExpectedRTMR3 pins TDX RTMR[3] — the runtime operator-key/workload event
	// chain extended after boot — as 96 lowercase hex chars. A deployment
	// property, not a cluster identity: the host chooses which guest extends
	// the register, so this pin requires ImageManifestPath alongside it and is
	// a configuration error without one. TDX evidence only.
	ExpectedRTMR3 string `json:"expected_rtmr3,omitempty"`
	// MinTCB is the SNP TCB floor enforced on verified evidence. SNP evidence
	// only — with TDX evidence this pin is a policy error.
	MinTCB *TCBFloor `json:"min_tcb,omitempty"`
	// StaticAllowlist requires the hardware-committed mesh CA to be sealed: it
	// must carry the static-allowlist stamp (OID …66378.1.3) and RA-TLS
	// evidence over its own key that verifies under this remote's measurement
	// policy, the sealed digest must equal SHA-256 of the AllowlistPath file
	// when one is pinned, and the mesh leaf's stamp must have been decided
	// under the sealed digest. attest-lb only.
	StaticAllowlist bool `json:"static_allowlist,omitempty"`
	// InitData pins the sealed CA evidence's init-data claim (SNP HOST_DATA /
	// TDX MRCONFIGID) as the hex SHA-256 of the CDS pod's kata init-data
	// document — the pod-as-CVM binding of the seal. Requires StaticAllowlist.
	InitData string   `json:"init_data,omitempty"`
	Pin      *CertPin `json:"pin,omitempty"`
}

// ParseAttestMode parses an attestation-mode string, normalizing the legacy
// "attest" spelling to AttestEndpoint ("attest-lb"). normalized reports that
// the legacy spelling was used; ok reports whether s is recognised at all.
func ParseAttestMode(s string) (mode AttestMode, normalized, ok bool) {
	switch AttestMode(s) {
	case legacyAttestEndpoint:
		return AttestEndpoint, true, true
	case AttestNone, AttestEndpoint, AttestCDSCert:
		return AttestMode(s), false, true
	default:
		return "", false, false
	}
}

// Cert is a stored trust anchor, keyed by Fingerprint rather than CommonName:
// every c8s cluster's mesh CA carries the same subject (CN=c8s Mesh CA), so
// the store must hold any number of certificates sharing a common name.
type Cert struct {
	// Fingerprint is the lowercase hex SHA-256 of the certificate DER.
	// Configs written before fingerprint keying lack it; Load fills it in
	// from the PEM.
	Fingerprint string `json:"fingerprint,omitempty"`
	CommonName  string `json:"common_name"`
	PEM         string `json:"pem"`
}

// CertFingerprint returns the lowercase hex SHA-256 of the DER of the first
// certificate in pemData.
func CertFingerprint(pemData []byte) (string, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return "", errors.New("no PEM block found")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parsing certificate: %w", err)
	}
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:]), nil
}

// ShortFingerprint abbreviates a fingerprint for display.
func ShortFingerprint(fp string) string {
	if len(fp) > 16 {
		return fp[:16]
	}
	return fp
}

type Config struct {
	Remotes []Remote `json:"remotes"`
	Certs   []Cert   `json:"certs,omitempty"`
}

// Path returns the location of the config file.
func Path() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "teerminator", "config.json"), nil
}

func Load() (*Config, error) {
	path, err := Path()
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
	// Normalize the legacy "attest" mode spelling to "attest-lb" so configs
	// written before the endpoint split keep working.
	for i := range cfg.Remotes {
		if cfg.Remotes[i].Mode == legacyAttestEndpoint {
			cfg.Remotes[i].Mode = AttestEndpoint
		}
	}
	// Configs written before fingerprint keying store certs without one;
	// compute it from the PEM so lookup and dedup work. An unparseable PEM
	// keeps an empty fingerprint (and is flagged by `certs`) rather than
	// making the whole config unloadable.
	for i := range cfg.Certs {
		if cfg.Certs[i].Fingerprint != "" {
			continue
		}
		if fp, err := CertFingerprint([]byte(cfg.Certs[i].PEM)); err == nil {
			cfg.Certs[i].Fingerprint = fp
		}
	}
	return &cfg, nil
}

func (c *Config) Save() error {
	path, err := Path()
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

// AddCert stores a trust anchor. Certificates are keyed by fingerprint, so
// any number of them may share a common name; only an exact duplicate of an
// already-stored certificate is rejected. A missing fingerprint is computed
// from the PEM.
func (c *Config) AddCert(cert Cert) error {
	if cert.Fingerprint == "" {
		fp, err := CertFingerprint([]byte(cert.PEM))
		if err != nil {
			return err
		}
		cert.Fingerprint = fp
	}
	for _, existing := range c.Certs {
		if existing.Fingerprint == cert.Fingerprint {
			return fmt.Errorf("certificate %q is already stored (fingerprint %s)",
				cert.CommonName, ShortFingerprint(cert.Fingerprint))
		}
	}
	c.Certs = append(c.Certs, cert)
	return nil
}

// FindCerts returns the stored certificates selected by sel. A sel that is a
// case-insensitive prefix of at least one fingerprint selects those
// certificates; otherwise sel selects the certificates whose common name
// equals it exactly.
func (c *Config) FindCerts(sel string) []Cert {
	var byFingerprint, byName []Cert
	lower := strings.ToLower(sel)
	for _, cert := range c.Certs {
		if cert.Fingerprint != "" && strings.HasPrefix(cert.Fingerprint, lower) {
			byFingerprint = append(byFingerprint, cert)
		}
		if cert.CommonName == sel {
			byName = append(byName, cert)
		}
	}
	if len(byFingerprint) > 0 {
		return byFingerprint
	}
	return byName
}

// RemoveCert removes the certificate with exactly that fingerprint and
// reports whether one was stored.
func (c *Config) RemoveCert(fingerprint string) bool {
	for i, cert := range c.Certs {
		if cert.Fingerprint == fingerprint {
			c.Certs = append(c.Certs[:i], c.Certs[i+1:]...)
			return true
		}
	}
	return false
}
