package casserver

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

// mockStepCA answers /1.0/sign as step-ca does for a JWK provisioner: it
// verifies the one-time token under the key of the provisioner and certifies
// the key of the CSR under the names of the token.
type mockStepCA struct {
	server      *httptest.Server
	provisioner *ecdsa.PrivateKey
	ca          *ecdsa.PrivateKey
	root        *x509.Certificate
	claims      map[string]any
	notAfter    string
	status      int
}

func newMockStepCA(t *testing.T) *mockStepCA {
	m := &mockStepCA{provisioner: newTestKey(t), ca: newTestKey(t)}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test root"}, NotBefore: time.Now().Add(-time.Minute),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &m.ca.PublicKey, m.ca)
	require.NoError(t, err)
	m.root, err = x509.ParseCertificate(der)
	require.NoError(t, err)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /1.0/sign", func(w http.ResponseWriter, r *http.Request) {
		if m.status != 0 {
			w.WriteHeader(m.status)
			_, _ = w.Write([]byte(`{"message":"refused"}`))
			return
		}
		var body struct{ CSR, OTT, NotAfter string }
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		signed, err := jose.ParseSigned(body.OTT, []jose.SignatureAlgorithm{jose.ES256})
		require.NoError(t, err)
		require.Equal(t, "provisioner-kid", signed.Signatures[0].Header.KeyID)
		payload, err := signed.Verify(&m.provisioner.PublicKey)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(payload, &m.claims))
		m.notAfter = body.NotAfter

		block, _ := pem.Decode([]byte(body.CSR))
		require.NotNil(t, block)
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		require.NoError(t, err)
		leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: m.claims["sub"].(string)}, DNSNames: []string{m.claims["sub"].(string)},
			NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
		der, err := x509.CreateCertificate(rand.Reader, leaf, m.root, csr.PublicKey, m.ca)
		require.NoError(t, err)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"certChain": []string{
			string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
			string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: m.root.Raw})),
		}})
	})
	m.server = httptest.NewServer(mux)
	t.Cleanup(m.server.Close)
	return m
}

func (m *mockStepCA) config(t *testing.T) *CredentialAuthorityConfig {
	raw, err := json.Marshal(jose.JSONWebKey{Key: m.provisioner, KeyID: "provisioner-kid"})
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "provisioner.jwk")
	require.NoError(t, os.WriteFile(path, raw, 0o600))
	return &CredentialAuthorityConfig{URL: m.server.URL, Provisioner: "tacra", ProvisionerKeyPath: path}
}

func TestIssueCertificate(t *testing.T) {
	ca := newMockStepCA(t)
	authority, err := newCredentialAuthority(ca.config(t))
	require.NoError(t, err)
	log, _ := test.NewNullLogger()
	a := newAcquirer(log, nil, nil, nil, nil, time.Now)
	a.authority = authority

	csr, err := x509.ParseCertificateRequest(testCSR(t))
	require.NoError(t, err)
	enrolled := &EnrollmentResult{CSR: csr, CertificateName: "workload.example", CertificateValidity: time.Hour}

	t.Run("the key of the CSR, certified under the name of the policy", func(t *testing.T) {
		chain, err := a.IssueCertificate(context.Background(), enrolled)
		require.NoError(t, err)
		require.Len(t, chain, 2)
		leaf, err := x509.ParseCertificate(chain[0])
		require.NoError(t, err)
		require.Equal(t, []string{"workload.example"}, leaf.DNSNames)
		require.True(t, leaf.PublicKey.(*ecdsa.PublicKey).Equal(csr.PublicKey))

		// The one-time token names the provisioner, the endpoint and the name; it is short-lived.
		require.Equal(t, "tacra", ca.claims["iss"])
		require.Equal(t, ca.server.URL+"/1.0/sign", ca.claims["aud"])
		require.Equal(t, "workload.example", ca.claims["sub"])
		require.Equal(t, []any{"workload.example"}, ca.claims["sans"])
		require.InDelta(t, tokenLifetime.Seconds(), ca.claims["exp"].(float64)-ca.claims["iat"].(float64), 1)
		require.NotEmpty(t, ca.claims["jti"])
		require.Equal(t, "1h0m0s", ca.notAfter)
	})
	t.Run("a Credential Authority that refuses", func(t *testing.T) {
		ca.status = http.StatusForbidden
		defer func() { ca.status = 0 }()
		_, err := a.IssueCertificate(context.Background(), enrolled)
		requireStatus(t, err, codes.Unavailable, "the Credential Authority is unavailable")
	})
	t.Run("an Enrollment without a name to certify", func(t *testing.T) {
		_, err := a.IssueCertificate(context.Background(), &EnrollmentResult{CSR: csr})
		requireStatus(t, err, codes.Internal, "names no certificate to issue")
	})
	t.Run("a host with no Credential Authority configured", func(t *testing.T) {
		none := newAcquirer(log, nil, nil, nil, nil, time.Now)
		_, err := none.IssueCertificate(context.Background(), enrolled)
		requireStatus(t, err, codes.Unavailable, "no Credential Authority is configured")
	})
}

func TestCredentialAuthorityConfig(t *testing.T) {
	require.ErrorContains(t, validateCredentialAuthority(&CredentialAuthorityConfig{CredentialAuthorityKind: "other"}), `kind "other" is not step-ca`)
	require.ErrorContains(t, validateCredentialAuthority(&CredentialAuthorityConfig{}), "url is required")
	require.ErrorContains(t, validateCredentialAuthority(&CredentialAuthorityConfig{URL: "https://ca.example"}), "provisioner is required")
	require.ErrorContains(t, validateCredentialAuthority(&CredentialAuthorityConfig{URL: "https://ca.example", Provisioner: "tacra"}), "provisioner_key_path is required")

	_, err := newCredentialAuthority(&CredentialAuthorityConfig{URL: "https://ca.example", Provisioner: "tacra", ProvisionerKeyPath: filepath.Join(t.TempDir(), "absent")})
	require.ErrorContains(t, err, "provisioner_key_path")

	t.Run("a Target in enroll mode names the certificate", func(t *testing.T) {
		c := validConfig()
		c.CredentialAuthority = &CredentialAuthorityConfig{URL: "https://ca.example", Provisioner: "tacra", ProvisionerKeyPath: "/run/provisioner.jwk"}
		_, err := c.Validate()
		require.ErrorContains(t, err, "certificate_name is required")

		c.Target["spiffe://example.org"].CertificateName = "workload.example"
		policies, err := c.Validate()
		require.NoError(t, err)
		require.Equal(t, "workload.example", policies["spiffe://example.org"].CertificateName)
		require.Equal(t, time.Hour, policies["spiffe://example.org"].CertificateValidity)

		c.Target["spiffe://example.org"].CertificateValidity = "soon"
		_, err = c.Validate()
		require.ErrorContains(t, err, "certificate_validity")
	})
}
