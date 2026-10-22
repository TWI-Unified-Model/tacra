package main

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
)

func loadCertPool(files []string) (*x509.CertPool, error) {
	if len(files) == 0 {
		return nil, nil
	}
	pool := x509.NewCertPool()
	for _, file := range files {
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("rup: CA file: %w", err)
		}
		if !pool.AppendCertsFromPEM(b) {
			return nil, fmt.Errorf("rup: CA file %s contains no PEM certificates", file)
		}
	}
	return pool, nil
}

// classifyPeer reports which certificate format the TLS peer chain satisfies.
// An empty format with a nil error means the certificate only proves key
// possession (usable for WIT binding) and authenticates nothing by itself.
func (v *Verifier) classifyPeer(certs []*x509.Certificate, now time.Time) (format, subject string, err error) {
	leaf := certs[0]
	intermediates := x509.NewCertPool()
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
	}
	opts := x509.VerifyOptions{
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	id, isWIC, err := v.wicIdentity(leaf)
	if isWIC {
		if err != nil {
			return "", "", err
		}
		if v.wicRoots == nil {
			return "", "", errors.New("WIC presented but no WIC trust anchors are configured")
		}
		opts.Roots = v.wicRoots
		if _, err := leaf.Verify(opts); err != nil {
			return "", "", fmt.Errorf("WIC chain: %w", err)
		}
		return FormatWIC, id, nil
	}

	if v.x509Roots == nil {
		return "", "", nil
	}
	opts.Roots = v.x509Roots
	if _, err := leaf.Verify(opts); err != nil {
		return "", "", nil
	}
	return FormatX509, leaf.Subject.CommonName, nil
}

// wicIdentity returns the single WIMSE workload identifier URI SAN, and
// whether the certificate claims to be a WIC at all.
func (v *Verifier) wicIdentity(leaf *x509.Certificate) (string, bool, error) {
	var ids []*url.URL
	for _, u := range leaf.URIs {
		if v.wicSchemes[strings.ToLower(u.Scheme)] {
			ids = append(ids, u)
		}
	}
	switch {
	case len(ids) == 0:
		return "", false, nil
	case len(ids) > 1:
		return "", true, errors.New("WIC carries more than one workload identifier")
	}
	id := ids[0]
	if id.Host == "" {
		return "", true, errors.New("WIC workload identifier has no trust domain")
	}
	if len(v.wicTrustDomains) > 0 && !v.wicTrustDomains[strings.ToLower(id.Host)] {
		return "", true, errors.New("WIC trust domain is not accepted")
	}
	return id.String(), true, nil
}
