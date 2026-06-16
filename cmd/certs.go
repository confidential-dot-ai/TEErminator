package cmd

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/confidential-dot-ai/TEErminator/internal/config"
	"github.com/spf13/cobra"
)

var certsCmd = &cobra.Command{
	Use:   "certs",
	Short: "Manage trusted CA certificates",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load()
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}

		if len(cfg.Certs) == 0 {
			fmt.Println("No certificates configured.")
			return nil
		}

		for _, c := range cfg.Certs {
			block, _ := pem.Decode([]byte(c.PEM))
			if block == nil {
				fmt.Printf("%s:\n    (invalid PEM)\n\n", c.CommonName)
				continue
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				fmt.Printf("%s:\n    (unparseable certificate: %v)\n\n", c.CommonName, err)
				continue
			}

			fmt.Printf("%s:\n", c.CommonName)
			fmt.Printf("    Issued To:\n")
			fmt.Printf("        Common Name:   %s\n", cert.Subject.CommonName)
			if len(cert.Subject.Organization) > 0 {
				fmt.Printf("        Organization:  %s\n", strings.Join(cert.Subject.Organization, ", "))
			}
			if len(cert.Subject.Country) > 0 {
				fmt.Printf("        Country:       %s\n", strings.Join(cert.Subject.Country, ", "))
			}
			fmt.Printf("    Issued By:\n")
			fmt.Printf("        Common Name:   %s\n", cert.Issuer.CommonName)
			if len(cert.Issuer.Organization) > 0 {
				fmt.Printf("        Organization:  %s\n", strings.Join(cert.Issuer.Organization, ", "))
			}
			if len(cert.Issuer.Country) > 0 {
				fmt.Printf("        Country:       %s\n", strings.Join(cert.Issuer.Country, ", "))
			}
			fmt.Printf("    Validity Period:\n")
			fmt.Printf("        Issued On:  %s\n", cert.NotBefore.Format("2006-01-02T15:04:05Z"))
			fmt.Printf("        Expires On: %s\n", cert.NotAfter.Format("2006-01-02T15:04:05Z"))
			fmt.Printf("    PEM-Encoding:\n")
			for _, line := range strings.Split(strings.TrimRight(c.PEM, "\n"), "\n") {
				fmt.Printf("        %s\n", line)
			}
			fmt.Println()
		}
		return nil
	},
}

var certsAddCmd = &cobra.Command{
	Use:   "add <CA-PEM-file>",
	Short: "Add a trusted CA certificate from a PEM file",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		pemFile := args[0]

		data, err := os.ReadFile(pemFile)
		if err != nil {
			return fmt.Errorf("reading PEM file: %w", err)
		}

		block, _ := pem.Decode(data)
		if block == nil {
			return fmt.Errorf("no PEM block found in %s", pemFile)
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("parsing certificate: %w", err)
		}

		commonName := cert.Subject.CommonName
		if commonName == "" {
			return fmt.Errorf("certificate has no common name")
		}

		cfg, err := config.Load()
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}

		c := config.Cert{
			CommonName: commonName,
			PEM:        string(data),
		}
		if err := cfg.AddCert(c); err != nil {
			return err
		}
		if err := cfg.Save(); err != nil {
			return fmt.Errorf("saving config: %w", err)
		}

		fmt.Printf("Added certificate %q\n", commonName)
		return nil
	},
}

var certsRmCmd = &cobra.Command{
	Use:   "rm <common-name>",
	Short: "Remove a trusted CA certificate by common name",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		commonName := args[0]

		cfg, err := config.Load()
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}

		if !cfg.RemoveCert(commonName) {
			return fmt.Errorf("no certificate found with common name %q", commonName)
		}
		if err := cfg.Save(); err != nil {
			return fmt.Errorf("saving config: %w", err)
		}

		fmt.Printf("Removed certificate %q\n", commonName)
		return nil
	},
}
