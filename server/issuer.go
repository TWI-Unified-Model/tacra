package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"
)

type issuer struct {
	caKey  *ecdsa.PrivateKey
	caCert *x509.Certificate
	caPEM  []byte

	serverTLS tls.Certificate
}

func newIssuer() (*issuer, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ca key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now().Add(-time.Minute)
	caTmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{Organization: []string{"TACRA"}, CommonName: "tacra-poc-ca"},
		NotBefore:             now,
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("ca cert: %w", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, err
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	i := &issuer{caKey: caKey, caCert: caCert, caPEM: caPEM}
	if err := i.issueServerCert(); err != nil {
		return nil, err
	}
	return i, nil
}

func (i *issuer) issueServerCert() error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("server key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return err
	}
	now := time.Now().Add(-time.Minute)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{Organization: []string{"TACRA"}, CommonName: "tacra-server"},
		NotBefore:    now,
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost", "tacra-server", "host.docker.internal"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, i.caCert, &key.PublicKey, i.caKey)
	if err != nil {
		return fmt.Errorf("server cert: %w", err)
	}
	i.serverTLS = tls.Certificate{
		Certificate: [][]byte{der, i.caCert.Raw},
		PrivateKey:  key,
		Leaf:        nil,
	}
	return nil
}

func (i *issuer) issueFromCSR(csrDER []byte) ([]byte, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now().Add(-time.Minute)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      csr.Subject,
		NotBefore:    now,
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		DNSNames:     csr.DNSNames,
		URIs:         csr.URIs,
		IPAddresses:  csr.IPAddresses,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, tmpl, i.caCert, csr.PublicKey, i.caKey)
	if err != nil {
		return nil, fmt.Errorf("client cert: %w", err)
	}
	var pemBuf []byte
	pemBuf = append(pemBuf, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})...)
	pemBuf = append(pemBuf, i.caPEM...)
	return pemBuf, nil
}

func (i *issuer) clientCAPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(i.caCert)
	return pool
}

func randomSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}
