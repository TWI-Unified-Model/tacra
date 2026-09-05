package cai

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net/url"

	"github.com/TWI-Unified-Model/twium/platform"
)

func createCSR(csk *platform.KeyPair, target string) ([]byte, error) {
	if csk == nil || csk.Private == nil {
		return nil, fmt.Errorf("cai: CSR: nil CSK")
	}
	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: truncateCN(target)},
	}
	if u, err := url.Parse(target); err == nil && u.Scheme != "" && u.Host != "" {
		tmpl.URIs = []*url.URL{u}
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, csk.Private)
	if err != nil {
		return nil, fmt.Errorf("cai: CSR: %w", err)
	}
	return der, nil
}

func truncateCN(s string) string {
	const maxCN = 64
	if len(s) <= maxCN {
		return s
	}
	return s[:maxCN]
}
