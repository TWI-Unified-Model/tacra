package casserver

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ErrAuthorityUnavailable is the Credential Authority not minting.
var ErrAuthorityUnavailable = errors.New("the Credential Authority is unavailable")

// A credentialAuthority is the configured Credential Authority: it certifies
// the key of a CSR under the name that the policy for the Target assigns.
type credentialAuthority interface {
	// Sign returns the certificate chain, leaf first, as DER.
	Sign(ctx context.Context, csrDER []byte, name string, validity time.Duration) ([][]byte, error)
}

// stepCAKind is the name of the kind of Credential Authority: step-ca, the
// default and the one kind for now.
const stepCAKind = "step-ca"

func validateCredentialAuthority(c *CredentialAuthorityConfig) error {
	switch {
	case c.CredentialAuthorityKind != "" && c.CredentialAuthorityKind != stepCAKind:
		return fmt.Errorf("kind %q is not %s", c.CredentialAuthorityKind, stepCAKind)
	case c.URL == "":
		return errors.New("url is required")
	case c.Provisioner == "":
		return errors.New("provisioner is required")
	case c.ProvisionerKeyPath == "":
		return errors.New("provisioner_key_path is required")
	}
	return nil
}

func newCredentialAuthority(c *CredentialAuthorityConfig) (credentialAuthority, error) {
	tc, err := clientTLS(c.CAPath, "", "")
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(c.ProvisionerKeyPath)
	if err != nil {
		return nil, fmt.Errorf("provisioner_key_path: %w", err)
	}
	var key jose.JSONWebKey
	if err := json.Unmarshal(raw, &key); err != nil {
		return nil, fmt.Errorf("provisioner_key_path: %w", err)
	}
	private, ok := key.Key.(*ecdsa.PrivateKey)
	if !ok || private.Curve != elliptic.P256() {
		return nil, errors.New("provisioner_key_path: the key of the provisioner must be an EC P-256 private JWK")
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: private, KeyID: key.KeyID}},
		(&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		return nil, fmt.Errorf("provisioner_key_path: %w", err)
	}
	base := strings.TrimRight(c.URL, "/")
	return &stepCA{
		signURL:     base + "/1.0/sign",
		provisioner: c.Provisioner,
		signer:      signer,
		client:      &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: tc}},
		now:         time.Now,
	}, nil
}

// stepCA is step-ca as the Credential Authority. The Server requests each
// certificate as a JWK provisioner of step-ca: with a one-time token, signed
// with the key of the provisioner, that names what the certificate carries.
type stepCA struct {
	signURL     string
	provisioner string
	signer      jose.Signer
	client      *http.Client
	now         func() time.Time
}

// tokenLifetime is how long a one-time token is valid.
const tokenLifetime = 5 * time.Minute

// token is a one-time token of the provisioner: sub is the common name and
// sans the names that the certificate will carry.
func (s *stepCA) token(name string) (string, error) {
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return "", err
	}
	now := s.now()
	claims, err := json.Marshal(map[string]any{
		"iss":  s.provisioner,
		"aud":  s.signURL,
		"sub":  name,
		"sans": []string{name},
		"iat":  now.Unix(),
		"nbf":  now.Unix(),
		"exp":  now.Add(tokenLifetime).Unix(),
		"jti":  hex.EncodeToString(id),
	})
	if err != nil {
		return "", err
	}
	signed, err := s.signer.Sign(claims)
	if err != nil {
		return "", err
	}
	return signed.CompactSerialize()
}

// Sign asks step-ca to certify the key of the CSR under name for validity.
func (s *stepCA) Sign(ctx context.Context, csrDER []byte, name string, validity time.Duration) ([][]byte, error) {
	token, err := s.token(name)
	if err != nil {
		return nil, fmt.Errorf("%w: one-time token: %w", ErrAuthorityUnavailable, err)
	}
	body, err := json.Marshal(map[string]string{
		"csr":      string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})),
		"ott":      token,
		"notAfter": validity.String(),
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrAuthorityUnavailable, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.signURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrAuthorityUnavailable, err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrAuthorityUnavailable, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrAuthorityUnavailable, err)
	}
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: HTTP %d: %s", ErrAuthorityUnavailable, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var answer struct {
		CertChain []string `json:"certChain"`
	}
	if err := json.Unmarshal(raw, &answer); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrAuthorityUnavailable, err)
	}
	chain := make([][]byte, 0, len(answer.CertChain))
	for _, certificate := range answer.CertChain {
		block, _ := pem.Decode([]byte(certificate))
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("%w: the certificate chain is not PEM", ErrAuthorityUnavailable)
		}
		chain = append(chain, block.Bytes)
	}
	if len(chain) == 0 {
		return nil, fmt.Errorf("%w: the certificate chain is empty", ErrAuthorityUnavailable)
	}
	return chain, nil
}

// IssueCertificate has the configured Credential Authority certify the key of
// the CSR of an Enrollment that Enroll admitted, under the name that the
// policy for the Target assigns. It returns the certificate chain, leaf first,
// as DER. A host with a CA of its own does not call it.
func (a *Acquirer) IssueCertificate(ctx context.Context, res *EnrollmentResult) ([][]byte, error) {
	if a.authority == nil {
		return nil, status.Error(codes.Unavailable, "no Credential Authority is configured")
	}
	if res == nil || res.CSR == nil || res.CertificateName == "" {
		return nil, status.Error(codes.Internal, "the Enrollment names no certificate to issue")
	}
	chain, err := a.authority.Sign(ctx, res.CSR.Raw, res.CertificateName, res.CertificateValidity)
	if err != nil {
		a.log.WithError(err).WithField("name", res.CertificateName).Warn("The Credential Authority issued no certificate")
		return nil, status.Errorf(codes.Unavailable, "%v", ErrAuthorityUnavailable)
	}
	a.log.WithFields(logrus.Fields{
		"name":        res.CertificateName,
		"verifier":    res.Verifier,
		"family":      res.Family,
		"measurement": hex.EncodeToString(res.Measurement),
	}).Info("Certificate issued by the Credential Authority")
	return chain, nil
}
