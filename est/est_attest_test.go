// Attested credential acquisition tests covering the TACRA EST extensions:
// attest-initiate, attest-enroll and attest-retrieve, in Passport mode against
// the locally deployed twi-globalsign-est container.
package esttest

import (
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/globalsign/est"
	"github.com/veraison/go-cose"
)

type testConfig struct {
	Host               string `json:"host"`
	CommonName         string `json:"common_name"`
	CACertificate      string `json:"ca_certificate"`
	ProviderPrivateKey string `json:"provider_private_key"`
	Targets            struct {
		Enroll   string `json:"enroll"`
		Retrieve string `json:"retrieve"`
		Rejected string `json:"rejected"`
	} `json:"targets"`
	CredentialTypes struct {
		X509   string `json:"x509"`
		Bearer string `json:"bearer"`
	} `json:"credential_types"`
}

var cfg testConfig

func TestMain(m *testing.M) {
	path := envOr("EST_TEST_CONFIG", "est_attest.json")
	loaded, err := loadTestConfig(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load EST test configuration %s: %v\n", path, err)
		os.Exit(1)
	}
	cfg = loaded
	os.Exit(m.Run())
}

func loadTestConfig(path string) (testConfig, error) {
	file, err := os.Open(path)
	if err != nil {
		return testConfig{}, err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()

	var loaded testConfig
	if err := decoder.Decode(&loaded); err != nil {
		return testConfig{}, err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return testConfig{}, fmt.Errorf("multiple JSON values")
		}
		return testConfig{}, err
	}

	required := map[string]string{
		"host":                    loaded.Host,
		"common_name":             loaded.CommonName,
		"ca_certificate":          loaded.CACertificate,
		"provider_private_key":    loaded.ProviderPrivateKey,
		"targets.enroll":          loaded.Targets.Enroll,
		"targets.retrieve":        loaded.Targets.Retrieve,
		"targets.rejected":        loaded.Targets.Rejected,
		"credential_types.x509":   loaded.CredentialTypes.X509,
		"credential_types.bearer": loaded.CredentialTypes.Bearer,
	}
	for field, value := range required {
		if value == "" {
			return testConfig{}, fmt.Errorf("%s is required", field)
		}
	}

	return loaded, nil
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func explicitAnchor(t *testing.T) *x509.CertPool {
	t.Helper()

	path := envOr("EST_CA_CERT", cfg.CACertificate)
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read EST CA certificate %s: %v", path, err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		t.Fatalf("no PEM certificates found in %s", path)
	}

	return pool
}

func newClient(anchor *x509.CertPool, cert *x509.Certificate, key crypto.Signer) *est.Client {
	client := &est.Client{
		Host:                  envOr("EST_HOST", cfg.Host),
		AdditionalPathSegment: os.Getenv("EST_APS"),
		ExplicitAnchor:        anchor,
	}

	if cert != nil {
		client.Certificates = []*x509.Certificate{cert}
		client.PrivateKey = key
	}

	return client
}

func newCSR(t *testing.T) (*x509.CertificateRequest, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: envOr("EST_CN", cfg.CommonName)},
	}
	if sans := os.Getenv("EST_SANS"); sans != "" {
		template.DNSNames = strings.Split(sans, ",")
	}

	der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
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

func target() string { return envOr("EST_TARGET", cfg.Targets.Enroll) }

func retrieveTarget() string { return envOr("EST_RETRIEVE_TARGET", cfg.Targets.Retrieve) }

// newCEK generates the Content Encryption Key used in Attested Retrieval Mode.
func newCEK(t *testing.T) (*ecdh.PrivateKey, []byte) {
	t.Helper()

	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate CEK: %v", err)
	}

	return key, key.PublicKey().Bytes()
}

func mockProviderKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()

	path := envOr("EST_PROVIDER_KEY", cfg.ProviderPrivateKey)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read mock TEE provider key %s: %v", path, err)
	}
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		t.Fatalf("mock TEE provider key %s is not EC PRIVATE KEY PEM", path)
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse mock TEE provider key: %v", err)
	}
	return key
}

func newMockEvidence(t *testing.T, freshnessKind string, handle []byte) []byte {
	t.Helper()

	evidence, err := est.NewMockEvidence(mockProviderKey(t), freshnessKind, handle)
	if err != nil {
		t.Fatalf("generate mock TEE evidence: %v", err)
	}

	return evidence
}

func signMockClaims(t *testing.T, claims *est.MockEATClaims) []byte {
	t.Helper()

	payload, err := cbor.Marshal(claims)
	if err != nil {
		t.Fatalf("encode mock EAT claims: %v", err)
	}
	signer, err := cose.NewSigner(cose.AlgorithmES256, mockProviderKey(t))
	if err != nil {
		t.Fatalf("create mock COSE signer: %v", err)
	}
	token, err := cose.Sign1(rand.Reader, signer, cose.Headers{
		Protected: cose.ProtectedHeader{
			cose.HeaderLabelAlgorithm:   cose.AlgorithmES256,
			cose.HeaderLabelContentType: est.MockEATMediaType,
		},
		Unprotected: cose.UnprotectedHeader{
			cose.HeaderLabelKeyID: []byte(est.MockTEESigningKeyID),
		},
	}, payload, nil)
	if err != nil {
		t.Fatalf("sign mock COSE evidence: %v", err)
	}
	return token
}

func TestMockTEEEvidence(t *testing.T) {
	handle := []byte("freshness-handle")
	evidence := newMockEvidence(t, est.FreshnessPresentNonce, handle)
	providerKey := mockProviderKey(t)

	claims, err := est.VerifyMockEvidence(evidence, &providerKey.PublicKey)
	if err != nil {
		t.Fatalf("verify mock TEE evidence: %v", err)
	}

	var message cose.Sign1Message
	if err := message.UnmarshalCBOR(evidence); err != nil {
		t.Fatalf("decode COSE Sign1 evidence: %v", err)
	}
	var fields map[int64]cbor.RawMessage
	if err := cbor.Unmarshal(message.Payload, &fields); err != nil {
		t.Fatalf("decode mock EAT payload: %v", err)
	}
	allowedClaims := map[int64]bool{
		1: true, 2: true, 6: true, 10: true, 256: true, 259: true,
		262: true, 263: true, 265: true, 267: true, 268: true, 270: true,
		-70003: true, -70004: true,
	}
	for claim := range fields {
		if !allowedClaims[claim] {
			t.Errorf("mock EAT contains unexpected claim label %d", claim)
		}
	}

	tampered := append([]byte(nil), evidence...)
	tampered[len(tampered)-1] ^= 0xff
	if _, err := est.VerifyMockEvidence(tampered, &providerKey.PublicKey); err == nil {
		t.Error("tampered COSE evidence passed signature verification")
	}
	untrustedKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate untrusted provider key: %v", err)
	}
	if _, err := est.VerifyMockEvidence(evidence, &untrustedKey.PublicKey); err == nil {
		t.Error("evidence passed verification with an untrusted provider key")
	}

	claims.PCRs[est.MockTEEPlatformPCR][0] ^= 0xff
	badMeasurements := signMockClaims(t, claims)
	if _, err := est.VerifyMockEvidence(badMeasurements, &providerKey.PublicKey); err == nil {
		t.Error("signed unacceptable PCR value passed appraisal")
	}
}

// assertStatus asserts that err carries the expected HTTP status code.
func assertStatus(t *testing.T, err error, expect int) {
	t.Helper()

	if err == nil {
		t.Fatalf("expected error with status %d, got nil", expect)
	}

	var estErr est.Error
	if !errors.As(err, &estErr) {
		t.Fatalf("expected est.Error with status %d, got %T: %v", expect, err, err)
	}

	if got := estErr.StatusCode(); got != expect {
		t.Errorf("status = %d, expect %d (%v)", got, expect, err)
	}
}

func TestAttestedCredentialAcquisition(t *testing.T) {
	if testing.Short() {
		t.Skip("requires a running EST server")
	}

	anchor := explicitAnchor(t)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	expectCN := envOr("EST_CN", cfg.CommonName)
	client := newClient(anchor, nil, nil)

	t.Run("Initiate/EnrollMode", func(t *testing.T) {
		resp, err := client.InitiateRemoteAttestation(ctx, target(), cfg.CredentialTypes.X509)
		if err != nil {
			t.Fatalf("attest-initiate: %v", err)
		}
		if resp.FreshnessKind != est.FreshnessPresentNonce {
			t.Errorf("freshness_kind = %q, expect %q", resp.FreshnessKind, est.FreshnessPresentNonce)
		}
		if len(resp.Handle) == 0 {
			t.Error("present-nonce response must carry a handle")
		}
		if resp.Mechanism != est.MechanismEnroll {
			t.Errorf("mode = %q, expect %q", resp.Mechanism, est.MechanismEnroll)
		}
		t.Logf("initiate: kind=%s mode=%s handleLen=%d expiresIn=%d bindings=%v",
			resp.FreshnessKind, resp.Mechanism, len(resp.Handle), resp.ExpiresIn, resp.RequiredBindings)
	})

	t.Run("Initiate/RetrieveMode", func(t *testing.T) {
		resp, err := client.InitiateRemoteAttestation(ctx, retrieveTarget(), cfg.CredentialTypes.Bearer)
		if err != nil {
			t.Fatalf("attest-initiate: %v", err)
		}
		if resp.Mechanism != est.MechanismRetrieve {
			t.Errorf("mode = %q, expect %q", resp.Mechanism, est.MechanismRetrieve)
		}
		if len(resp.AcceptableCEK) == 0 {
			t.Error("retrieve mode must advertise acceptable CEK suites")
		}
		t.Logf("initiate: mode=%s bindings=%v cek=%v", resp.Mechanism, resp.RequiredBindings, resp.AcceptableCEK)
	})

	// The EST server whitelists only the configured target.
	t.Run("Initiate/RejectedTarget", func(t *testing.T) {
		_, err := client.InitiateRemoteAttestation(ctx, cfg.Targets.Rejected, cfg.CredentialTypes.X509)
		assertStatus(t, err, 403)
	})

	t.Run("Enroll/PresentNonce", func(t *testing.T) {
		init, err := client.InitiateRemoteAttestation(ctx, target(), cfg.CredentialTypes.X509)
		if err != nil {
			t.Fatalf("attest-initiate: %v", err)
		}

		csr, _ := newCSR(t)

		cert, err := client.EnrollCredential(ctx, &est.AttestedEnrollmentRequest{
			Target:         target(),
			CredentialType: cfg.CredentialTypes.X509,
			FreshnessKind:  init.FreshnessKind,
			Handle:         init.Handle,
			CSR:            csr.Raw,
			Evidence:       newMockEvidence(t, init.FreshnessKind, init.Handle),
			Binding:        est.Binding{Method: est.BindingCSRHash, HashAlg: "SHA-256"},
		})
		if err != nil {
			t.Fatalf("attest-enroll: %v", err)
		}

		if got := cert.Subject.CommonName; got != expectCN {
			t.Errorf("enrolled CN = %q, expect %q", got, expectCN)
		}
		verifyChain(t, cert, anchor)

		t.Logf("attested enroll: subject=%q serial=%s", cert.Subject, cert.SerialNumber)
	})

	// An absent freshness kind is completed locally; the client never calls
	// attest-initiate.
	t.Run("Enroll/AbsentNone", func(t *testing.T) {
		csr, _ := newCSR(t)

		cert, err := client.EnrollCredential(ctx, &est.AttestedEnrollmentRequest{
			Target:         target(),
			CredentialType: cfg.CredentialTypes.X509,
			FreshnessKind:  est.FreshnessAbsentNone,
			CSR:            csr.Raw,
			Evidence:       newMockEvidence(t, est.FreshnessAbsentNone, nil),
			Binding:        est.Binding{Method: est.BindingCSRHash, HashAlg: "SHA-256"},
		})
		if err != nil {
			t.Fatalf("attest-enroll: %v", err)
		}

		verifyChain(t, cert, anchor)
		t.Logf("attested enroll (absent-none): serial=%s", cert.SerialNumber)
	})

	t.Run("Enroll/ReplayedHandle", func(t *testing.T) {
		init, err := client.InitiateRemoteAttestation(ctx, target(), cfg.CredentialTypes.X509)
		if err != nil {
			t.Fatalf("attest-initiate: %v", err)
		}

		enroll := func() error {
			csr, _ := newCSR(t)
			_, err := client.EnrollCredential(ctx, &est.AttestedEnrollmentRequest{
				Target:         target(),
				CredentialType: cfg.CredentialTypes.X509,
				FreshnessKind:  init.FreshnessKind,
				Handle:         init.Handle,
				CSR:            csr.Raw,
				Evidence:       newMockEvidence(t, init.FreshnessKind, init.Handle),
				Binding:        est.Binding{Method: est.BindingCSRHash, HashAlg: "SHA-256"},
			})
			return err
		}

		if err := enroll(); err != nil {
			t.Fatalf("first attest-enroll: %v", err)
		}

		assertStatus(t, enroll(), 409)
	})

	t.Run("Enroll/EvidenceFreshnessMismatch", func(t *testing.T) {
		init, err := client.InitiateRemoteAttestation(ctx, target(), cfg.CredentialTypes.X509)
		if err != nil {
			t.Fatalf("attest-initiate: %v", err)
		}

		csr, _ := newCSR(t)
		_, err = client.EnrollCredential(ctx, &est.AttestedEnrollmentRequest{
			Target:         target(),
			CredentialType: cfg.CredentialTypes.X509,
			FreshnessKind:  init.FreshnessKind,
			Handle:         init.Handle,
			CSR:            csr.Raw,
			Evidence:       newMockEvidence(t, init.FreshnessKind, []byte("wrong-handle")),
			Binding:        est.Binding{Method: est.BindingCSRHash, HashAlg: "SHA-256"},
		})
		assertStatus(t, err, 403)
	})

	// The Verifier rejects a PCR value changed after the mock TEE provider
	// signed the evidence.
	t.Run("Enroll/TamperedMeasurement", func(t *testing.T) {
		init, err := client.InitiateRemoteAttestation(ctx, target(), cfg.CredentialTypes.X509)
		if err != nil {
			t.Fatalf("attest-initiate: %v", err)
		}

		csr, _ := newCSR(t)
		evidence := newMockEvidence(t, init.FreshnessKind, init.Handle)
		providerKey := mockProviderKey(t)
		claims, err := est.VerifyMockEvidence(evidence, &providerKey.PublicKey)
		if err != nil {
			t.Fatalf("verify generated evidence: %v", err)
		}
		claims.PCRs[est.MockTEEWorkloadPCR][0] ^= 0xff
		evidence = signMockClaims(t, claims)

		_, err = client.EnrollCredential(ctx, &est.AttestedEnrollmentRequest{
			Target:         target(),
			CredentialType: cfg.CredentialTypes.X509,
			FreshnessKind:  init.FreshnessKind,
			Handle:         init.Handle,
			CSR:            csr.Raw,
			Evidence:       evidence,
			Binding:        est.Binding{Method: est.BindingCSRHash, HashAlg: "SHA-256"},
		})
		assertStatus(t, err, 403)
	})

	// The CAS decides the mechanism per target, not from the credential type,
	// so varying the type must not change the mechanism.
	t.Run("Initiate/MechanismIndependentOfCredentialType", func(t *testing.T) {
		for _, ct := range []string{
			est.CredentialTypeX509,
			est.CredentialTypeWIT,
			est.CredentialTypePSK,
			est.CredentialTypeJWT,
		} {
			enrollResp, err := client.InitiateRemoteAttestation(ctx, target(), ct)
			if err != nil {
				t.Fatalf("attest-initiate %s on enroll target: %v", ct, err)
			}
			if enrollResp.Mechanism != est.MechanismEnroll {
				t.Errorf("credential type %q on enroll target gave mechanism %q, expect %q",
					ct, enrollResp.Mechanism, est.MechanismEnroll)
			}

			retrieveResp, err := client.InitiateRemoteAttestation(ctx, retrieveTarget(), ct)
			if err != nil {
				t.Fatalf("attest-initiate %s on retrieve target: %v", ct, err)
			}
			if retrieveResp.Mechanism != est.MechanismRetrieve {
				t.Errorf("credential type %q on retrieve target gave mechanism %q, expect %q",
					ct, retrieveResp.Mechanism, est.MechanismRetrieve)
			}
		}
	})

	// The mechanism is fixed by the CAS, so the wrong second leg is rejected.
	t.Run("Enroll/WrongMechanismForTarget", func(t *testing.T) {
		init, err := client.InitiateRemoteAttestation(ctx, retrieveTarget(), cfg.CredentialTypes.X509)
		if err != nil {
			t.Fatalf("attest-initiate: %v", err)
		}

		csr, _ := newCSR(t)

		_, err = client.EnrollCredential(ctx, &est.AttestedEnrollmentRequest{
			Target:         retrieveTarget(),
			CredentialType: cfg.CredentialTypes.X509,
			FreshnessKind:  init.FreshnessKind,
			Handle:         init.Handle,
			CSR:            csr.Raw,
			Evidence:       newMockEvidence(t, init.FreshnessKind, init.Handle),
			Binding:        est.Binding{Method: est.BindingCSRHash, HashAlg: "SHA-256"},
		})
		assertStatus(t, err, 403)
	})

	retrieve := func(t *testing.T, cekPub []byte) *est.EncryptedCredentialBundle {
		t.Helper()

		init, err := client.InitiateRemoteAttestation(ctx, retrieveTarget(), cfg.CredentialTypes.Bearer)
		if err != nil {
			t.Fatalf("attest-initiate: %v", err)
		}

		bundle, err := client.RetrieveCredential(ctx, &est.AttestedRetrievalRequest{
			Target:         retrieveTarget(),
			CredentialType: cfg.CredentialTypes.Bearer,
			FreshnessKind:  init.FreshnessKind,
			Handle:         init.Handle,
			CEKPub:         cekPub,
			Evidence:       newMockEvidence(t, init.FreshnessKind, init.Handle),
			Binding:        est.Binding{Method: est.BindingCEKThumbprint, HashAlg: "SHA-256"},
		})
		if err != nil {
			t.Fatalf("attest-retrieve: %v", err)
		}

		return bundle
	}

	t.Run("Retrieve/PresentNonce", func(t *testing.T) {
		cekPriv, cekPub := newCEK(t)

		sealed := retrieve(t, cekPub)
		if sealed.Enc != est.EncECDHP256 {
			t.Errorf("enc = %q, expect %q", sealed.Enc, est.EncECDHP256)
		}
		if len(sealed.Ciphertext) == 0 {
			t.Fatal("bundle carries no ciphertext")
		}

		// Only the holder of CEKpri can recover the credential.
		bundle, err := sealed.Open(cekPriv)
		if err != nil {
			t.Fatalf("open bundle: %v", err)
		}
		if bundle.GroupID != sealed.GroupID {
			t.Errorf("inner group_id = %q, expect %q", bundle.GroupID, sealed.GroupID)
		}

		var certDER, keyDER []byte
		for _, item := range bundle.CredentialItems {
			switch item.Type {
			case est.CredentialItemX509Cert:
				certDER = item.Data
			case est.CredentialItemPKCS8Key:
				keyDER = item.Data
			}
		}
		if certDER == nil || keyDER == nil {
			t.Fatal("bundle missing certificate or key")
		}

		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			t.Fatalf("parse retrieved certificate: %v", err)
		}
		verifyChain(t, cert, anchor)

		if _, err := x509.ParsePKCS8PrivateKey(keyDER); err != nil {
			t.Fatalf("parse retrieved key: %v", err)
		}

		t.Logf("retrieved: group=%s subject=%q items=%d",
			bundle.GroupID, cert.Subject, len(bundle.CredentialItems))
	})

	// Replica workloads attesting to the same subject share a credential group.
	t.Run("Retrieve/ReplicaStability", func(t *testing.T) {
		firstPriv, firstPub := newCEK(t)
		secondPriv, secondPub := newCEK(t)

		first, err := retrieve(t, firstPub).Open(firstPriv)
		if err != nil {
			t.Fatalf("open first bundle: %v", err)
		}

		second, err := retrieve(t, secondPub).Open(secondPriv)
		if err != nil {
			t.Fatalf("open second bundle: %v", err)
		}

		if first.GroupID != second.GroupID {
			t.Errorf("group_id differs across replicas: %q vs %q", first.GroupID, second.GroupID)
		}

		if len(first.CredentialItems) == 0 || len(second.CredentialItems) == 0 {
			t.Fatal("bundles carry no credential items")
		}
		if string(first.CredentialItems[0].Data) != string(second.CredentialItems[0].Data) {
			t.Error("replicas received different credentials for the same group")
		}
	})

	// The bundle is sealed to CEKpub, so a different key cannot open it.
	t.Run("Retrieve/WrongCEK", func(t *testing.T) {
		_, cekPub := newCEK(t)
		wrongPriv, _ := newCEK(t)

		if _, err := retrieve(t, cekPub).Open(wrongPriv); err == nil {
			t.Error("bundle opened with the wrong CEK private key")
		}
	})

	t.Run("Retrieve/RejectedTarget", func(t *testing.T) {
		_, cekPub := newCEK(t)

		_, err := client.RetrieveCredential(ctx, &est.AttestedRetrievalRequest{
			Target:         cfg.Targets.Rejected,
			CredentialType: cfg.CredentialTypes.Bearer,
			FreshnessKind:  est.FreshnessAbsentNone,
			CEKPub:         cekPub,
			Evidence:       newMockEvidence(t, est.FreshnessAbsentNone, nil),
			Binding:        est.Binding{Method: est.BindingCEKThumbprint, HashAlg: "SHA-256"},
		})
		assertStatus(t, err, 403)
	})
}
