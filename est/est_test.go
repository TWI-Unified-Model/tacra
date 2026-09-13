// Package esttest exercises the five RFC 7030 operations of the globalsign EST
// client library against the locally deployed twi-globalsign-est container.
package esttest

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/globalsign/est"
)

const (
	defaultHost   = "localhost:9444"
	defaultCN     = "twi-unified-model-client"
	defaultCACert = "../deploy/config/local/globalsign-est/certs/ca-certificates.pem"
)

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func defaultCACertPath() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return defaultCACert
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), defaultCACert))
}

// explicitAnchor loads the local EST CA as an RFC7030 3.6.1 Explicit TA database.
func explicitAnchor(t *testing.T) *x509.CertPool {
	t.Helper()

	explicit := os.Getenv("EST_CA_CERT")
	path := explicit
	if path == "" {
		path = defaultCACertPath()
	}

	pemBytes, err := os.ReadFile(path)
	if err != nil {
		if explicit == "" && os.IsNotExist(err) {
			t.Skipf("EST CA certificate %s not found; generate local config with deploy/init-local-est-config.sh and deploy globalsign-est", path)
		}
		t.Fatalf("read EST CA certificate %s: %v", path, err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		t.Fatalf("no PEM certificates found in %s", path)
	}

	return pool
}

func requireESTServer(t *testing.T) {
	t.Helper()

	host := envOr("EST_HOST", defaultHost)
	conn, err := net.DialTimeout("tcp", host, 2*time.Second)
	if err != nil {
		t.Skipf("EST server %s is not reachable: %v; deploy with ./deploy/components.sh deploy --components globalsign-est", host, err)
	}
	_ = conn.Close()
}

func newClient(anchor *x509.CertPool, cert *x509.Certificate, key crypto.Signer) *est.Client {
	c := &est.Client{
		Host:                  envOr("EST_HOST", defaultHost),
		AdditionalPathSegment: os.Getenv("EST_APS"),
		ExplicitAnchor:        anchor,
	}

	if cert != nil {
		c.Certificates = []*x509.Certificate{cert}
		c.PrivateKey = key
	}

	if bits := os.Getenv("EST_BIT_SIZE"); bits != "" {
		c.AdditionalHeaders = map[string]string{"Bit-Size": bits}
	}

	return c
}

func newCSR(t *testing.T) (*x509.CertificateRequest, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: envOr("EST_CN", defaultCN)},
	}
	if sans := os.Getenv("EST_SANS"); sans != "" {
		tmpl.DNSNames = strings.Split(sans, ",")
	}

	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}

	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("parse CSR: %v", err)
	}

	return csr, key
}

func verifyChain(t *testing.T, cert *x509.Certificate, anchor *x509.CertPool) {
	t.Helper()

	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     anchor,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Errorf("issued certificate does not chain to the local EST CA: %v", err)
	}
}

func TestESTOperations(t *testing.T) {
	if testing.Short() {
		t.Skip("requires a running EST server")
	}

	anchor := explicitAnchor(t)
	requireESTServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	wantCN := envOr("EST_CN", defaultCN)
	anon := newClient(anchor, nil, nil)

	var (
		enrolled  *x509.Certificate
		enrollKey *ecdsa.PrivateKey
		enrollCSR *x509.CertificateRequest
	)

	t.Run("CACerts", func(t *testing.T) {
		certs, err := anon.CACerts(ctx)
		if err != nil {
			t.Fatalf("cacerts: %v", err)
		}
		if len(certs) == 0 {
			t.Fatal("no CA certificates returned")
		}
		for _, c := range certs {
			t.Logf("CA certificate: subject=%q isCA=%t", c.Subject, c.IsCA)
		}
	})

	t.Run("CSRAttrs", func(t *testing.T) {
		attrs, err := anon.CSRAttrs(ctx)
		if err != nil {
			t.Fatalf("csrattrs: %v", err)
		}
		t.Logf("CSR attributes: %d OIDs, %d attributes", len(attrs.OIDs), len(attrs.Attributes))
	})

	t.Run("Enroll", func(t *testing.T) {
		csr, key := newCSR(t)

		cert, err := anon.Enroll(ctx, csr)
		if err != nil {
			t.Fatalf("enroll: %v", err)
		}
		if got := cert.Subject.CommonName; got != wantCN {
			t.Errorf("enrolled CN = %q, want %q", got, wantCN)
		}
		verifyChain(t, cert, anchor)

		t.Logf("enrolled: subject=%q serial=%s notAfter=%s dns=%v",
			cert.Subject, cert.SerialNumber, cert.NotAfter.Format(time.RFC3339), cert.DNSNames)

		enrolled, enrollKey, enrollCSR = cert, key, csr
	})

	// RFC7030 4.2.2 requires the certificate being renewed to be presented over
	// mTLS and the CSR subject to match it, so the enrolled CSR is reused here.
	t.Run("Reenroll", func(t *testing.T) {
		if enrolled == nil {
			t.Skip("enroll did not succeed")
		}

		cert, err := newClient(anchor, enrolled, enrollKey).Reenroll(ctx, enrollCSR)
		if err != nil {
			t.Fatalf("reenroll: %v", err)
		}
		if got := cert.Subject.CommonName; got != wantCN {
			t.Errorf("reenrolled CN = %q, want %q", got, wantCN)
		}
		verifyChain(t, cert, anchor)
		if cert.SerialNumber.Cmp(enrolled.SerialNumber) == 0 {
			t.Error("reenrolled certificate reuses the original serial number")
		}

		t.Logf("reenrolled: serial=%s notAfter=%s", cert.SerialNumber, cert.NotAfter.Format(time.RFC3339))
	})

	t.Run("ServerKeyGen", func(t *testing.T) {
		csr, _ := newCSR(t)

		cert, keyDER, err := anon.ServerKeyGen(ctx, csr)
		if err != nil {
			t.Fatalf("serverkeygen: %v", err)
		}
		if got := cert.Subject.CommonName; got != wantCN {
			t.Errorf("server-generated CN = %q, want %q", got, wantCN)
		}
		verifyChain(t, cert, anchor)

		key, err := x509.ParsePKCS8PrivateKey(keyDER)
		if err != nil {
			t.Fatalf("parse server-generated PKCS#8 key: %v", err)
		}

		signer, ok := key.(crypto.Signer)
		if !ok {
			t.Fatalf("server-generated key %T is not a crypto.Signer", key)
		}

		equal, ok := signer.Public().(interface{ Equal(crypto.PublicKey) bool })
		if !ok {
			t.Fatalf("server-generated public key %T is not comparable", signer.Public())
		}
		if !equal.Equal(cert.PublicKey) {
			t.Error("server-generated key does not match the issued certificate")
		}

		t.Logf("server-generated: key=%T serial=%s", key, cert.SerialNumber)
	})
}
