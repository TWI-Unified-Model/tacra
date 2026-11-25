package cai

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"

	"github.com/TWI-Unified-Model/tacra/platform"
)

// createCSR builds the certification request of an Enrollment. The request
// carries the public CSK and the proof of its possession. The Credential
// Authority assigns the names of the certificate, so the request names nothing
// but the Credential Hint, as its common name, when the Workload gave one.
func createCSR(csk *platform.KeyPair, credentialHint string) ([]byte, error) {
	signer, err := csk.Signer()
	if err != nil {
		return nil, fmt.Errorf("cai: CSR: %w", err)
	}
	template := &x509.CertificateRequest{}
	if credentialHint != "" {
		template.Subject = pkix.Name{CommonName: truncateCN(credentialHint)}
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, signer)
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
