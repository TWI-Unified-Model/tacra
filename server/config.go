package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Credential formats a request can be authenticated with.
const (
	FormatX509 = "x509"
	FormatWIC  = "wic"
	FormatWIT  = "wit"
	FormatJWT  = "jwt"
)

// Config is the RUP's only input: trust anchors and acceptance policy, all
// loaded from files so the RUP never depends on how credentials are issued.
type Config struct {
	// Audience is the "aud" value required in bearer JWTs.
	Audience         string `json:"audience"`
	ClockSkewSeconds int    `json:"clock_skew_seconds"`
	// Accept lists credential combinations; a request is authorized when it
	// presents every format of at least one combination.
	Accept [][]string `json:"accept"`
	TLS    TLSConfig  `json:"tls"`
	X509   X509Config `json:"x509"`
	WIC    WICConfig  `json:"wic"`
	JWT    JWTConfig  `json:"jwt"`
	WIT    WITConfig  `json:"wit"`
}

// TLSConfig names the RUP's own server certificate chain and private key.
type TLSConfig struct {
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
}

// X509Config holds the trust anchors for plain X.509 client certificates.
type X509Config struct {
	CAFiles []string `json:"ca_files"`
}

// WICConfig holds the trust anchors and identifier policy for WIMSE Workload
// Identity Certificates. An empty TrustDomains accepts any trust domain.
type WICConfig struct {
	CAFiles      []string `json:"ca_files"`
	URISchemes   []string `json:"uri_schemes"`
	TrustDomains []string `json:"trust_domains,omitempty"`
}

// JWTConfig holds bearer-token issuers and their public verification keys,
// as JWKS files and/or PEM SubjectPublicKeyInfo files. The RUP holds no
// secret that could mint a token.
type JWTConfig struct {
	Issuers        []string `json:"issuers"`
	Algorithms     []string `json:"algorithms"`
	JWKSFiles      []string `json:"jwks_files,omitempty"`
	PublicKeyFiles []string `json:"public_key_files,omitempty"`
}

// WITConfig holds WIMSE Workload Identity Token issuers and their public keys.
type WITConfig struct {
	Issuers        []string `json:"issuers"`
	Algorithms     []string `json:"algorithms"`
	JWKSFiles      []string `json:"jwks_files,omitempty"`
	PublicKeyFiles []string `json:"public_key_files,omitempty"`
}

// LoadConfig reads a JSON configuration file. Relative file paths inside it
// are resolved against the configuration file's directory.
func LoadConfig(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("rup: config: %w", err)
	}
	defer f.Close()

	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("rup: config %s: %w", path, err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return Config{}, fmt.Errorf("rup: config %s: unexpected trailing data", path)
	}
	cfg.resolvePaths(filepath.Dir(path))
	return cfg, nil
}

func (c *Config) resolvePaths(base string) {
	abs := func(p string) string {
		if p == "" || filepath.IsAbs(p) {
			return p
		}
		return filepath.Join(base, p)
	}
	all := func(ps []string) {
		for i := range ps {
			ps[i] = abs(ps[i])
		}
	}
	c.TLS.CertFile = abs(c.TLS.CertFile)
	c.TLS.KeyFile = abs(c.TLS.KeyFile)
	all(c.X509.CAFiles)
	all(c.WIC.CAFiles)
	all(c.JWT.JWKSFiles)
	all(c.JWT.PublicKeyFiles)
	all(c.WIT.JWKSFiles)
	all(c.WIT.PublicKeyFiles)
}

func (c Config) validate() error {
	if c.TLS.CertFile == "" || c.TLS.KeyFile == "" {
		return errors.New("rup: tls.cert_file and tls.key_file are required")
	}
	if c.ClockSkewSeconds < 0 {
		return errors.New("rup: clock_skew_seconds must not be negative")
	}
	if len(c.Accept) == 0 {
		return errors.New("rup: accept must list at least one credential combination")
	}
	for _, combo := range c.Accept {
		if len(combo) == 0 {
			return errors.New("rup: accept contains an empty combination")
		}
		for _, f := range combo {
			switch f {
			case FormatX509, FormatWIC, FormatWIT, FormatJWT:
			default:
				return fmt.Errorf("rup: accept contains unknown format %q", f)
			}
		}
	}
	if c.accepts(FormatJWT) {
		if c.Audience == "" {
			return errors.New("rup: audience is required when jwt is accepted")
		}
		if len(c.JWT.Algorithms) == 0 {
			return errors.New("rup: jwt.algorithms is required when jwt is accepted")
		}
	}
	if c.accepts(FormatWIT) && len(c.WIT.Algorithms) == 0 {
		return errors.New("rup: wit.algorithms is required when wit is accepted")
	}
	for _, alg := range append(append([]string{}, c.JWT.Algorithms...), c.WIT.Algorithms...) {
		if strings.EqualFold(alg, "none") {
			return errors.New(`rup: algorithm "none" is not permitted`)
		}
		if strings.HasPrefix(strings.ToUpper(alg), "HS") {
			return fmt.Errorf("rup: algorithm %q must be asymmetric", alg)
		}
	}
	return nil
}

func (c Config) accepts(format string) bool {
	for _, combo := range c.Accept {
		for _, f := range combo {
			if f == format {
				return true
			}
		}
	}
	return false
}
