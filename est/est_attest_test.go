// Attested credential acquisition tests covering the TACRA EST extensions:
// attest-initiate, attest-enroll and attest-retrieve, in Passport mode against
// the locally deployed twi-globalsign-est container.
package esttest

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/globalsign/est"
)

const (
	defaultTarget        = "RUP-workload-1"
	rejectedTarget       = "RUP-workload-unknown"
	credentialTypeX509   = est.CredentialTypeX509
	credentialTypeBearer = est.CredentialTypePSK
	workloadClaim        = "twi-poc-workload"
)

func target() string { return envOr("EST_TARGET", defaultTarget) }

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

	if ev.Claims == nil {
		ev.Claims = map[string]string{"workload": workloadClaim}
	}

	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal evidence: %v", err)
	}

	return b
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
		resp, err := client.InitiateRemoteAttestation(ctx, target(), credentialTypeBearer)
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
			Evidence: marshalEvidence(t, est.MockEvidence{
				Target:        target(),
				FreshnessKind: init.FreshnessKind,
				Handle:        init.Handle,
				CSRHash:       est.CSRHash(csr.Raw),
			}),
			Binding: est.Binding{Method: est.BindingCSRHash, HashAlg: "SHA-256"},
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
			Evidence: marshalEvidence(t, est.MockEvidence{
				Target:        target(),
				FreshnessKind: est.FreshnessAbsentNone,
				CSRHash:       est.CSRHash(csr.Raw),
			}),
			Binding: est.Binding{Method: est.BindingCSRHash, HashAlg: "SHA-256"},
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
				Evidence: marshalEvidence(t, est.MockEvidence{
					Target:        target(),
					FreshnessKind: init.FreshnessKind,
					Handle:        init.Handle,
					CSRHash:       est.CSRHash(csr.Raw),
				}),
				Binding: est.Binding{Method: est.BindingCSRHash, HashAlg: "SHA-256"},
			})
			return err
		}

		if err := enroll(); err != nil {
			t.Fatalf("first attest-enroll: %v", err)
		}

		assertStatus(t, enroll(), 409)
	})

	// Evidence carrying a digest of a different CSR must be rejected, so a CSR
	// cannot be substituted.
	t.Run("Enroll/EvidenceNotBoundToCSR", func(t *testing.T) {
		init, err := client.InitiateRemoteAttestation(ctx, target(), credentialTypeX509)
		if err != nil {
			t.Fatalf("attest-initiate: %v", err)
		}

		csr, _ := newCSR(t)
		other, _ := newCSR(t)

		_, err = client.EnrollCredential(ctx, &est.AttestedEnrollmentRequest{
			Target:         target(),
			CredentialType: credentialTypeX509,
			FreshnessKind:  init.FreshnessKind,
			Handle:         init.Handle,
			CSR:            csr.Raw,
			Evidence: marshalEvidence(t, est.MockEvidence{
				Target:        target(),
				FreshnessKind: init.FreshnessKind,
				Handle:        init.Handle,
				CSRHash:       est.CSRHash(other.Raw),
			}),
			Binding: est.Binding{Method: est.BindingCSRHash, HashAlg: "SHA-256"},
		})
		assertStatus(t, err, 403)
	})

	retrieve := func(t *testing.T, cekPub []byte) *est.EncryptedCredentialBundle {
		t.Helper()

		init, err := client.InitiateRemoteAttestation(ctx, target(), credentialTypeBearer)
		if err != nil {
			t.Fatalf("attest-initiate: %v", err)
		}

		bundle, err := client.RetrieveCredential(ctx, &est.AttestedRetrievalRequest{
			Target:         target(),
			CredentialType: credentialTypeBearer,
			FreshnessKind:  init.FreshnessKind,
			Handle:         init.Handle,
			Evidence: marshalEvidence(t, est.MockEvidence{
				Target:        target(),
				FreshnessKind: init.FreshnessKind,
				Handle:        init.Handle,
				CEKPub:        cekPub,
				CEKThumbprint: est.CEKThumbprint(cekPub),
			}),
			Binding: est.Binding{Method: est.BindingCEKThumbprint, HashAlg: "SHA-256"},
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
			Evidence: marshalEvidence(t, est.MockEvidence{
				Target:        rejectedTarget,
				FreshnessKind: est.FreshnessAbsentNone,
				CEKPub:        cekPub,
				CEKThumbprint: est.CEKThumbprint(cekPub),
			}),
			Binding: est.Binding{Method: est.BindingCEKThumbprint, HashAlg: "SHA-256"},
		})
		assertStatus(t, err, 403)
	})
}
