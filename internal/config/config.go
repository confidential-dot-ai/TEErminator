package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

type AuthType string

const (
	AuthNone  AuthType = "None"
	AuthToken AuthType = "Token"
	AuthMTLS  AuthType = "mTLS"
)

type TrustStatus string

const (
	StatusUnknown  TrustStatus = "Unknown"
	StatusVerified TrustStatus = "Verified"
	StatusUntrusted TrustStatus = "Untrusted"
	StatusFailed   TrustStatus = "Failed"
)

type Remote struct {
	Local  string      `json:"local"`
	Remote string      `json:"remote"`
	Auth   AuthType    `json:"auth"`
	Status TrustStatus `json:"status"`
	Token  string      `json:"token,omitempty"`
}

type Config struct {
	Remotes []Remote `json:"remotes"`
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

func (c *Config) AddRemote(r Remote) error {
	if c.FindByLocal(r.Local) != nil {
		return errors.New("a remote with that local address already exists")
	}
	c.Remotes = append(c.Remotes, r)
	return nil
}
