package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
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
	// AttestTLSHeader (Flow A) verifies an Attestation-Report response header,
	// binding the client nonce, then reuses that verdict for the session.
	AttestTLSHeader AttestMode = "tls-header"
	// AttestEndpoint (Flow B) fetches a fresh attestation from a dedicated
	// endpoint at session start.
	AttestEndpoint AttestMode = "attest"
	// AttestCDSCert (Flow C) fetches and pins the CDS cert before trusting the
	// connection.
	AttestCDSCert AttestMode = "cds-cert"
)

// CertPin records a certificate pinned by a Flow C bootstrap so later sessions
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
	Measurements []string    `json:"measurements,omitempty"` // accepted hex launch digests
	Pin          *CertPin    `json:"pin,omitempty"`
}

// ValidAttestMode reports whether s is a recognised attestation mode.
func ValidAttestMode(s string) bool {
	switch AttestMode(s) {
	case AttestNone, AttestTLSHeader, AttestEndpoint, AttestCDSCert:
		return true
	default:
		return false
	}
}

type Cert struct {
	CommonName string `json:"common_name"`
	PEM        string `json:"pem"`
}

type Config struct {
	Remotes []Remote `json:"remotes"`
	Certs   []Cert   `json:"certs,omitempty"`
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

func (c *Config) RemoveCert(commonName string) bool {
	for i, cert := range c.Certs {
		if cert.CommonName == commonName {
			c.Certs = append(c.Certs[:i], c.Certs[i+1:]...)
			return true
		}
	}
	return false
}
