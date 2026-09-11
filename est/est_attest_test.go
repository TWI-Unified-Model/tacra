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
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/globalsign/est"
)

const (
	defaultHost          = "localhost:9444"
	defaultCN            = "twi-unified-model-client"
	defaultCACert        = "../deploy/config/local/globalsign-est/certs/ca-certificates.pem"
	defaultTarget        = "RUP-workload-1"
	retrieveTargetName   = "RUP-workload-2"
	rejectedTarget       = "RUP-workload-unknown"
	credentialTypeX509   = est.CredentialTypeX509
	credentialTypeBearer = est.CredentialTypePSK
)

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func explicitAnchor(t *testing.T) *x509.CertPool {
	t.Helper()

	path := envOr("EST_CA_CERT", defaultCACert)
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
		Host:                  envOr("EST_HOST", defaultHost),
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
		Subject: pkix.Name{CommonName: envOr("EST_CN", defaultCN)},
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

func target() string { return envOr("EST_TARGET", defaultTarget) }

func retrieveTarget() string { return envOr("EST_RETRIEVE_TARGET", retrieveTargetName) }

// newCEK generates the Content Encryption Key used in Attested Retrieval Mode.
func newCEK(t *testing.T) (*ecdh.PrivateKey, []byte) {
	t.Helper()

	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate CEK: %v", err)
	}

	return key, key.PublicKey().Bytes()
}

// marshalEvidence encodes mock Evidence as the opaque byte string the protocol
// carries.
func marshalEvidence(t *testing.T, ev est.MockEvidence) []byte {
	t.Helper()

	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal evidence: %v", err)
	}

	return b
}

func newMockEvidence(t *testing.T, freshnessKind string, handle []byte) est.MockEvidence {
	t.Helper()

	evidence, err := est.NewMockEvidence(freshnessKind, handle)
	if err != nil {
		t.Fatalf("generate mock TEE evidence: %v", err)
	}

	return evidence
}

func TestMockTEEEvidence(t *testing.T) {
	handle := []byte("freshness-handle")
	evidence := newMockEvidence(t, est.FreshnessPresentNonce, handle)

	if err := est.VerifyMockEvidence(evidence); err != nil {
		t.Fatalf("verify mock TEE evidence: %v", err)
	}

	encoded := marshalEvidence(t, evidence)
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatalf("decode mock TEE evidence: %v", err)
	}
	for _, field := range []string{
		"target", "credential_type", "csr", "csr_hash", "cek_pub",
		"cek_thumbprint", "binding", "profile", "endorsements", "claims",
	} {
		if _, ok := fields[field]; ok {
			t.Errorf("mock TEE evidence contains request field %q", field)
		}
	}

	evidence.PCRs["0"][0] ^= 0xff
	if err := est.VerifyMockEvidence(evidence); err == nil {
		t.Error("tampered PCR value passed signature verification")
	}
}

// assertStatus asserts that err carries the expected HTTP status code.
func assertStatus(t *testing.T, err error, want int) {
	t.Helper()

	if err == nil {
		t.Fatalf("expected error with status %d, got nil", want)
	}

	var estErr est.Error
	if !errors.As(err, &estErr) {
		t.Fatalf("expected est.Error with status %d, got %T: %v", want, err, err)
	}

	if got := estErr.StatusCode(); got != want {
		t.Errorf("status = %d, want %d (%v)", got, want, err)
	}
}

func TestAttestedCredentialAcquisition(t *testing.T) {
	if testing.Short() {
		t.Skip("requires a running EST server")
	}

	anchor := explicitAnchor(t)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	wantCN := envOr("EST_CN", defaultCN)
	client := newClient(anchor, nil, nil)

	t.Run("Initiate/EnrollMode", func(t *testing.T) {
		resp, err := client.InitiateRemoteAttestation(ctx, target(), credentialTypeX509)
		if err != nil {
			t.Fatalf("attest-initiate: %v", err)
		}
		if resp.FreshnessKind != est.FreshnessPresentNonce {
			t.Errorf("freshness_kind = %q, want %q", resp.FreshnessKind, est.FreshnessPresentNonce)
		}
		if len(resp.Handle) == 0 {
			t.Error("present-nonce response must carry a handle")
		}
		if resp.Mechanism != est.MechanismEnroll {
			t.Errorf("mode = %q, want %q", resp.Mechanism, est.MechanismEnroll)
		}
		t.Logf("initiate: kind=%s mode=%s handleLen=%d expiresIn=%d bindings=%v",
			resp.FreshnessKind, resp.Mechanism, len(resp.Handle), resp.ExpiresIn, resp.RequiredBindings)
	})

	t.Run("Initiate/RetrieveMode", func(t *testing.T) {
		resp, err := client.InitiateRemoteAttestation(ctx, retrieveTarget(), credentialTypeBearer)
		if err != nil {
			t.Fatalf("attest-initiate: %v", err)
		}
		if resp.Mechanism != est.MechanismRetrieve {
			t.Errorf("mode = %q, want %q", resp.Mechanism, est.MechanismRetrieve)
		}
		if len(resp.AcceptableCEK) == 0 {
			t.Error("retrieve mode must advertise acceptable CEK suites")
		}
		t.Logf("initiate: mode=%s bindings=%v cek=%v", resp.Mechanism, resp.RequiredBindings, resp.AcceptableCEK)
	})

	// The EST server whitelists only the configured target.
	t.Run("Initiate/RejectedTarget", func(t *testing.T) {
		_, err := client.InitiateRemoteAttestation(ctx, rejectedTarget, credentialTypeX509)
		assertStatus(t, err, 403)
	})

	t.Run("Enroll/PresentNonce", func(t *testing.T) {
		init, err := client.InitiateRemoteAttestation(ctx, target(), credentialTypeX509)
		if err != nil {
			t.Fatalf("attest-initiate: %v", err)
		}

		csr, _ := newCSR(t)

		cert, err := client.EnrollCredential(ctx, &est.AttestedEnrollmentRequest{
			Target:         target(),
			CredentialType: credentialTypeX509,
			FreshnessKind:  init.FreshnessKind,
			Handle:         init.Handle,
			CSR:            csr.Raw,
			Evidence:       marshalEvidence(t, newMockEvidence(t, init.FreshnessKind, init.Handle)),
			Binding:        est.Binding{Method: est.BindingCSRHash, HashAlg: "SHA-256"},
		})
		if err != nil {
			t.Fatalf("attest-enroll: %v", err)
		}

		if got := cert.Subject.CommonName; got != wantCN {
			t.Errorf("enrolled CN = %q, want %q", got, wantCN)
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
			CredentialType: credentialTypeX509,
			FreshnessKind:  est.FreshnessAbsentNone,
			CSR:            csr.Raw,
			Evidence:       marshalEvidence(t, newMockEvidence(t, est.FreshnessAbsentNone, nil)),
			Binding:        est.Binding{Method: est.BindingCSRHash, HashAlg: "SHA-256"},
		})
		if err != nil {
			t.Fatalf("attest-enroll: %v", err)
		}

		verifyChain(t, cert, anchor)
		t.Logf("attested enroll (absent-none): serial=%s", cert.SerialNumber)
	})

	t.Run("Enroll/ReplayedHandle", func(t *testing.T) {
		init, err := client.InitiateRemoteAttestation(ctx, target(), credentialTypeX509)
		if err != nil {
			t.Fatalf("attest-initiate: %v", err)
		}

		enroll := func() error {
			csr, _ := newCSR(t)
			_, err := client.EnrollCredential(ctx, &est.AttestedEnrollmentRequest{
				Target:         target(),
				CredentialType: credentialTypeX509,
				FreshnessKind:  init.FreshnessKind,
				Handle:         init.Handle,
				CSR:            csr.Raw,
				Evidence:       marshalEvidence(t, newMockEvidence(t, init.FreshnessKind, init.Handle)),
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
		init, err := client.InitiateRemoteAttestation(ctx, target(), credentialTypeX509)
		if err != nil {
			t.Fatalf("attest-initiate: %v", err)
		}

		csr, _ := newCSR(t)
		_, err = client.EnrollCredential(ctx, &est.AttestedEnrollmentRequest{
			Target:         target(),
			CredentialType: credentialTypeX509,
			FreshnessKind:  init.FreshnessKind,
			Handle:         init.Handle,
			CSR:            csr.Raw,
			Evidence:       marshalEvidence(t, newMockEvidence(t, init.FreshnessKind, []byte("wrong-handle"))),
			Binding:        est.Binding{Method: est.BindingCSRHash, HashAlg: "SHA-256"},
		})
		assertStatus(t, err, 403)
	})

	// The Verifier rejects a PCR value changed after the mock TEE provider
	// signed the evidence.
	t.Run("Enroll/TamperedMeasurement", func(t *testing.T) {
		init, err := client.InitiateRemoteAttestation(ctx, target(), credentialTypeX509)
		if err != nil {
			t.Fatalf("attest-initiate: %v", err)
		}

		csr, _ := newCSR(t)
		evidence := newMockEvidence(t, init.FreshnessKind, init.Handle)
		evidence.PCRs[est.MockTEEWorkloadPCR][0] ^= 0xff

		_, err = client.EnrollCredential(ctx, &est.AttestedEnrollmentRequest{
			Target:         target(),
			CredentialType: credentialTypeX509,
			FreshnessKind:  init.FreshnessKind,
			Handle:         init.Handle,
			CSR:            csr.Raw,
			Evidence:       marshalEvidence(t, evidence),
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
				t.Errorf("credential type %q on enroll target gave mechanism %q, want %q",
					ct, enrollResp.Mechanism, est.MechanismEnroll)
			}

			retrieveResp, err := client.InitiateRemoteAttestation(ctx, retrieveTarget(), ct)
			if err != nil {
				t.Fatalf("attest-initiate %s on retrieve target: %v", ct, err)
			}
			if retrieveResp.Mechanism != est.MechanismRetrieve {
				t.Errorf("credential type %q on retrieve target gave mechanism %q, want %q",
					ct, retrieveResp.Mechanism, est.MechanismRetrieve)
			}
		}
	})

	// The mechanism is fixed by the CAS, so the wrong second leg is rejected.
	t.Run("Enroll/WrongMechanismForTarget", func(t *testing.T) {
		init, err := client.InitiateRemoteAttestation(ctx, retrieveTarget(), credentialTypeX509)
		if err != nil {
			t.Fatalf("attest-initiate: %v", err)
		}

		csr, _ := newCSR(t)

		_, err = client.EnrollCredential(ctx, &est.AttestedEnrollmentRequest{
			Target:         retrieveTarget(),
			CredentialType: credentialTypeX509,
			FreshnessKind:  init.FreshnessKind,
			Handle:         init.Handle,
			CSR:            csr.Raw,
			Evidence:       marshalEvidence(t, newMockEvidence(t, init.FreshnessKind, init.Handle)),
			Binding:        est.Binding{Method: est.BindingCSRHash, HashAlg: "SHA-256"},
		})
		assertStatus(t, err, 403)
	})

	retrieve := func(t *testing.T, cekPub []byte) *est.EncryptedCredentialBundle {
		t.Helper()

		init, err := client.InitiateRemoteAttestation(ctx, retrieveTarget(), credentialTypeBearer)
		if err != nil {
			t.Fatalf("attest-initiate: %v", err)
		}

		bundle, err := client.RetrieveCredential(ctx, &est.AttestedRetrievalRequest{
			Target:         retrieveTarget(),
			CredentialType: credentialTypeBearer,
			FreshnessKind:  init.FreshnessKind,
			Handle:         init.Handle,
			CEKPub:         cekPub,
			Evidence:       marshalEvidence(t, newMockEvidence(t, init.FreshnessKind, init.Handle)),
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
			t.Errorf("enc = %q, want %q", sealed.Enc, est.EncECDHP256)
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
			t.Errorf("inner group_id = %q, want %q", bundle.GroupID, sealed.GroupID)
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
			Target:         rejectedTarget,
			CredentialType: credentialTypeBearer,
			FreshnessKind:  est.FreshnessAbsentNone,
			CEKPub:         cekPub,
			Evidence:       marshalEvidence(t, newMockEvidence(t, est.FreshnessAbsentNone, nil)),
			Binding:        est.Binding{Method: est.BindingCEKThumbprint, HashAlg: "SHA-256"},
		})
		assertStatus(t, err, 403)
	})
}
