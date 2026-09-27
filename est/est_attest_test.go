// Attested credential acquisition tests covering the TACRA EST extensions:
// attest-initiate, attest-enroll and attest-retrieve, in Passport mode against
// the locally deployed twi-globalsign-est container.
package esttest

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
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
	ServerID           string `json:"server_id"`
	CommonName         string `json:"common_name"`
	CACertificate      string `json:"ca_certificate"`
	ProviderPrivateKey string `json:"provider_private_key"`
	Targets            struct {
		Enroll   string `json:"enroll"`
		Retrieve string `json:"retrieve"`
		Rejected string `json:"rejected"`
	} `json:"targets"`
	Freshness struct {
		EpochMarker     string `json:"epoch_marker"`
		TimestampMaxAge int    `json:"timestamp_max_age"`
		EnrollTargets   struct {
			AbsentTimestamp string `json:"absent_timestamp"`
			AbsentNone      string `json:"absent_none"`
			AbsentEpoch     string `json:"absent_epoch"`
			PresentEpoch    string `json:"present_epoch"`
		} `json:"enroll_targets"`
		RetrieveTargets struct {
			AbsentTimestamp string `json:"absent_timestamp"`
			AbsentNone      string `json:"absent_none"`
			AbsentEpoch     string `json:"absent_epoch"`
			PresentEpoch    string `json:"present_epoch"`
		} `json:"retrieve_targets"`
	} `json:"freshness"`
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
		"host":                   loaded.Host,
		"server_id":              loaded.ServerID,
		"common_name":            loaded.CommonName,
		"ca_certificate":         loaded.CACertificate,
		"provider_private_key":   loaded.ProviderPrivateKey,
		"targets.enroll":         loaded.Targets.Enroll,
		"targets.retrieve":       loaded.Targets.Retrieve,
		"targets.rejected":       loaded.Targets.Rejected,
		"freshness.epoch_marker": loaded.Freshness.EpochMarker,
		"freshness.enroll_targets.absent_timestamp":   loaded.Freshness.EnrollTargets.AbsentTimestamp,
		"freshness.enroll_targets.absent_none":        loaded.Freshness.EnrollTargets.AbsentNone,
		"freshness.enroll_targets.absent_epoch":       loaded.Freshness.EnrollTargets.AbsentEpoch,
		"freshness.enroll_targets.present_epoch":      loaded.Freshness.EnrollTargets.PresentEpoch,
		"freshness.retrieve_targets.absent_timestamp": loaded.Freshness.RetrieveTargets.AbsentTimestamp,
		"freshness.retrieve_targets.absent_none":      loaded.Freshness.RetrieveTargets.AbsentNone,
		"freshness.retrieve_targets.absent_epoch":     loaded.Freshness.RetrieveTargets.AbsentEpoch,
		"freshness.retrieve_targets.present_epoch":    loaded.Freshness.RetrieveTargets.PresentEpoch,
		"credential_types.x509":                       loaded.CredentialTypes.X509,
		"credential_types.bearer":                     loaded.CredentialTypes.Bearer,
	}
	for field, value := range required {
		if value == "" {
			return testConfig{}, fmt.Errorf("%s is required", field)
		}
	}
	if loaded.Freshness.TimestampMaxAge <= 0 {
		return testConfig{}, fmt.Errorf("freshness.timestamp_max_age must be positive")
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

// serverID is the EST Server identity the Attester is configured to trust,
// compared against AttestationInitiateResponse.ServerID before producing
// Evidence, and bound into Evidence via the binding_input digest.
func serverID() string { return cfg.ServerID }

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

func newMockEvidence(t *testing.T, freshnessKind string, handle []byte, serverID, target string, subject []byte) []byte {
	t.Helper()

	evidence, err := est.NewMockEvidence(mockProviderKey(t), freshnessKind, handle, serverID, target, subject)
	if err != nil {
		t.Fatalf("generate mock TEE evidence: %v", err)
	}

	return evidence
}

func newMockEvidenceAt(
	t *testing.T,
	freshnessKind string,
	handle []byte,
	serverID, target string,
	subject []byte,
	issuedAt time.Time,
) []byte {
	t.Helper()

	evidence, err := est.NewMockEvidenceAt(
		mockProviderKey(t), freshnessKind, handle, serverID, target, subject, issuedAt,
	)
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
	evidence := newMockEvidence(t, est.FreshnessPresentNonce, handle, serverID(), target(), []byte("test-subject-der"))
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
		-70003: true, -70004: true, -70005: true,
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

func TestMockEvidenceFreshnessKinds(t *testing.T) {
	issuedAt := time.Unix(1_800_000_000, 0)
	epochMarker := []byte(cfg.Freshness.EpochMarker)
	cases := []struct {
		kind        string
		handle      []byte
		expectNonce bool
	}{
		{est.FreshnessAbsentTimestamp, nil, false},
		{est.FreshnessAbsentNone, nil, false},
		{est.FreshnessAbsentEpoch, epochMarker, true},
		{est.FreshnessPresentNonce, []byte("freshness-nonce"), true},
		{est.FreshnessPresentEpoch, epochMarker, true},
	}

	providerKey := mockProviderKey(t)
	for _, tc := range cases {
		tc := tc
		t.Run(tc.kind, func(t *testing.T) {
			evidence := newMockEvidenceAt(
				t, tc.kind, tc.handle, serverID(), target(), []byte("test-subject-der"), issuedAt,
			)
			claims, err := est.VerifyMockEvidence(evidence, &providerKey.PublicKey)
			if err != nil {
				t.Fatalf("verify mock TEE evidence: %v", err)
			}
			if claims.FreshnessKind != tc.kind {
				t.Errorf("freshness kind = %q, expect %q", claims.FreshnessKind, tc.kind)
			}
			if claims.IssuedAt != issuedAt.Unix() {
				t.Errorf("issued-at = %d, expect %d", claims.IssuedAt, issuedAt.Unix())
			}
			if tc.expectNonce {
				if claims.Nonce == nil || claims.Nonce.Len() != 1 ||
					!bytes.Equal(claims.Nonce.GetI(0), tc.handle) {
					t.Errorf("evidence nonce does not contain freshness element %x", tc.handle)
				}
			} else if claims.Nonce != nil {
				t.Error("absent timestamp/none evidence unexpectedly contains a nonce")
			}
		})
	}

	if _, err := est.NewMockEvidence(
		mockProviderKey(t), est.FreshnessAbsentTimestamp, []byte("unexpected"),
		serverID(), target(), []byte("test-subject-der"),
	); err == nil {
		t.Error("absent-timestamp accepted a freshness handle")
	}
	if _, err := est.NewMockEvidence(
		mockProviderKey(t), est.FreshnessPresentEpoch, nil,
		serverID(), target(), []byte("test-subject-der"),
	); err == nil {
		t.Error("present-epoch accepted a missing freshness handle")
	}
}

// TestBindingInputEncoding verifies the length-prefixed octet framing of
// {{binding-input}} against hand-computed bytes: values chosen so a reader can
// verify the framing by eye, since the draft's own worked example ({{test-vector}}
// in zz_suds-docs/est_lamps-tacra-est-updates) needs an exact 223-octet CSR DER
// that isn't safely reproducible from prose.
func TestBindingInputEncoding(t *testing.T) {
	handle := []byte("H")
	subject := []byte{0x01, 0x02, 0x03, 0x04}

	got := est.EncodeBindingInput(handle, "AB", "XYZ", subject)
	want := []byte{
		0, 0, 0, 1, 'H',
		0, 0, 0, 2, 'A', 'B',
		0, 0, 0, 3, 'X', 'Y', 'Z',
		0, 0, 0, 4, 0x01, 0x02, 0x03, 0x04,
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("EncodeBindingInput = % x, expect % x", got, want)
	}

	wantDigest := sha512.Sum512(want)
	if gotDigest := est.BindingDigest(handle, "AB", "XYZ", subject); !bytes.Equal(gotDigest, wantDigest[:]) {
		t.Errorf("BindingDigest = % x, expect SHA-512(binding_input) = % x", gotDigest, wantDigest)
	}
}

// TestBindingInputUnambiguous confirms the length prefixes required by
// {{binding-input}} prevent two different (server_id, target) splits of the
// same concatenated characters from producing the same binding_input, the
// property the draft relies on to rule out server/target substitution.
func TestBindingInputUnambiguous(t *testing.T) {
	handle := []byte("h")
	subject := []byte("s")

	a := est.EncodeBindingInput(handle, "AB", "CD", subject)
	b := est.EncodeBindingInput(handle, "ABC", "D", subject)
	if bytes.Equal(a, b) {
		t.Error("EncodeBindingInput is ambiguous: different server_id/target splits of the same characters collide")
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
		// The Attester MUST compare server_id with the EST Server configured
		// for the Target and MUST NOT produce Evidence on mismatch.
		if resp.ServerID != serverID() {
			t.Errorf("server_id = %q, expect %q", resp.ServerID, serverID())
		}
		if len(resp.AcceptableCSK) == 0 {
			t.Error("enroll mode must advertise acceptable CSK suites")
		}
		t.Logf("initiate: kind=%s mode=%s server_id=%s handleLen=%d expiresIn=%d bindings=%v",
			resp.FreshnessKind, resp.Mechanism, resp.ServerID, len(resp.Handle), resp.ExpiresIn, resp.RequiredBindings)
	})

	t.Run("Initiate/RetrieveMode", func(t *testing.T) {
		resp, err := client.InitiateRemoteAttestation(ctx, retrieveTarget(), cfg.CredentialTypes.Bearer)
		if err != nil {
			t.Fatalf("attest-initiate: %v", err)
		}
		if resp.Mechanism != est.MechanismRetrieve {
			t.Errorf("mode = %q, expect %q", resp.Mechanism, est.MechanismRetrieve)
		}
		if resp.ServerID != serverID() {
			t.Errorf("server_id = %q, expect %q", resp.ServerID, serverID())
		}
		if len(resp.AcceptableCEK) == 0 {
			t.Error("retrieve mode must advertise acceptable CEK suites")
		}
		t.Logf("initiate: mode=%s server_id=%s bindings=%v cek=%v", resp.Mechanism, resp.ServerID, resp.RequiredBindings, resp.AcceptableCEK)
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
			Evidence:       newMockEvidence(t, init.FreshnessKind, init.Handle, init.ServerID, target(), csr.Raw),
			Binding:        est.Binding{Method: est.BindingInput, Hash: "sha512"},
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
		absentNoneTarget := cfg.Freshness.EnrollTargets.AbsentNone
		csr, _ := newCSR(t)

		cert, err := client.EnrollCredential(ctx, &est.AttestedEnrollmentRequest{
			Target:         absentNoneTarget,
			CredentialType: cfg.CredentialTypes.X509,
			FreshnessKind:  est.FreshnessAbsentNone,
			CSR:            csr.Raw,
			Evidence:       newMockEvidence(t, est.FreshnessAbsentNone, nil, serverID(), absentNoneTarget, csr.Raw),
			Binding:        est.Binding{Method: est.BindingInput, Hash: "sha512"},
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
				Evidence:       newMockEvidence(t, init.FreshnessKind, init.Handle, init.ServerID, target(), csr.Raw),
				Binding:        est.Binding{Method: est.BindingInput, Hash: "sha512"},
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
			Evidence:       newMockEvidence(t, init.FreshnessKind, []byte("wrong-handle"), init.ServerID, target(), csr.Raw),
			Binding:        est.Binding{Method: est.BindingInput, Hash: "sha512"},
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
		evidence := newMockEvidence(t, init.FreshnessKind, init.Handle, init.ServerID, target(), csr.Raw)
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
			Binding:        est.Binding{Method: est.BindingInput, Hash: "sha512"},
		})
		assertStatus(t, err, 403)
	})

	// A conduit that carries genuine Evidence to a different server than the
	// one it was bound to must be rejected: the Credential Authority
	// recomputes binding_input with its own server_id.
	t.Run("Enroll/ServerSubstitution", func(t *testing.T) {
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
			Evidence:       newMockEvidence(t, init.FreshnessKind, init.Handle, "https://not-this-server.example", target(), csr.Raw),
			Binding:        est.Binding{Method: est.BindingInput, Hash: "sha512"},
		})
		assertStatus(t, err, 403)
	})

	// A conduit that presents a genuine request under a Target the Attester
	// did not choose must be rejected: the Credential Authority recomputes
	// binding_input with the Target the Handle was issued for.
	t.Run("Enroll/TargetSubstitution", func(t *testing.T) {
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
			Evidence:       newMockEvidence(t, init.FreshnessKind, init.Handle, init.ServerID, "RUP-not-requested", csr.Raw),
			Binding:        est.Binding{Method: est.BindingInput, Hash: "sha512"},
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
			Evidence:       newMockEvidence(t, init.FreshnessKind, init.Handle, init.ServerID, retrieveTarget(), csr.Raw),
			Binding:        est.Binding{Method: est.BindingInput, Hash: "sha512"},
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
			Evidence:       newMockEvidence(t, init.FreshnessKind, init.Handle, init.ServerID, retrieveTarget(), cekPub),
			Binding:        est.Binding{Method: est.BindingInput, Hash: "sha512"},
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

	// The same Evidence-to-Server binding closes server substitution for
	// retrieval as it does for enrollment.
	t.Run("Retrieve/ServerSubstitution", func(t *testing.T) {
		init, err := client.InitiateRemoteAttestation(ctx, retrieveTarget(), cfg.CredentialTypes.Bearer)
		if err != nil {
			t.Fatalf("attest-initiate: %v", err)
		}

		_, cekPub := newCEK(t)
		_, err = client.RetrieveCredential(ctx, &est.AttestedRetrievalRequest{
			Target:         retrieveTarget(),
			CredentialType: cfg.CredentialTypes.Bearer,
			FreshnessKind:  init.FreshnessKind,
			Handle:         init.Handle,
			CEKPub:         cekPub,
			Evidence:       newMockEvidence(t, init.FreshnessKind, init.Handle, "https://not-this-server.example", retrieveTarget(), cekPub),
			Binding:        est.Binding{Method: est.BindingInput, Hash: "sha512"},
		})
		assertStatus(t, err, 403)
	})

	t.Run("Retrieve/RejectedTarget", func(t *testing.T) {
		_, cekPub := newCEK(t)

		_, err := client.RetrieveCredential(ctx, &est.AttestedRetrievalRequest{
			Target:         cfg.Targets.Rejected,
			CredentialType: cfg.CredentialTypes.Bearer,
			FreshnessKind:  est.FreshnessAbsentNone,
			CEKPub:         cekPub,
			Evidence:       newMockEvidence(t, est.FreshnessAbsentNone, nil, serverID(), cfg.Targets.Rejected, cekPub),
			Binding:        est.Binding{Method: est.BindingInput, Hash: "sha512"},
		})
		assertStatus(t, err, 403)
	})
}

func TestAllFreshnessKinds(t *testing.T) {
	if testing.Short() {
		t.Skip("requires a running EST server")
	}

	type freshnessCase struct {
		kind           string
		enrollTarget   string
		retrieveTarget string
		localHandle    []byte
		present        bool
	}

	cases := []freshnessCase{
		{
			kind:           est.FreshnessAbsentTimestamp,
			enrollTarget:   cfg.Freshness.EnrollTargets.AbsentTimestamp,
			retrieveTarget: cfg.Freshness.RetrieveTargets.AbsentTimestamp,
		},
		{
			kind:           est.FreshnessAbsentNone,
			enrollTarget:   cfg.Freshness.EnrollTargets.AbsentNone,
			retrieveTarget: cfg.Freshness.RetrieveTargets.AbsentNone,
		},
		{
			kind:           est.FreshnessAbsentEpoch,
			enrollTarget:   cfg.Freshness.EnrollTargets.AbsentEpoch,
			retrieveTarget: cfg.Freshness.RetrieveTargets.AbsentEpoch,
			localHandle:    []byte(cfg.Freshness.EpochMarker),
		},
		{
			kind:           est.FreshnessPresentNonce,
			enrollTarget:   target(),
			retrieveTarget: retrieveTarget(),
			present:        true,
		},
		{
			kind:           est.FreshnessPresentEpoch,
			enrollTarget:   cfg.Freshness.EnrollTargets.PresentEpoch,
			retrieveTarget: cfg.Freshness.RetrieveTargets.PresentEpoch,
			present:        true,
		},
	}

	anchor := explicitAnchor(t)
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	client := newClient(anchor, nil, nil)

	initFor := func(t *testing.T, tc freshnessCase, target, credentialType, mechanism string) *est.AttestationInitiateResponse {
		t.Helper()

		resp, err := client.InitiateRemoteAttestation(ctx, target, credentialType)
		if err != nil {
			t.Fatalf("attest-initiate: %v", err)
		}
		if resp.FreshnessKind != tc.kind {
			t.Errorf("freshness_kind = %q, expect %q", resp.FreshnessKind, tc.kind)
		}
		if resp.Mechanism != mechanism {
			t.Errorf("mode = %q, expect %q", resp.Mechanism, mechanism)
		}
		if resp.ServerID != serverID() {
			t.Errorf("server_id = %q, expect %q", resp.ServerID, serverID())
		}
		if tc.present && len(resp.Handle) == 0 {
			t.Error("present freshness response has no handle")
		}
		if !tc.present && len(resp.Handle) != 0 {
			t.Errorf("absent freshness response unexpectedly returned handle %x", resp.Handle)
		}
		if tc.kind == est.FreshnessPresentEpoch && !bytes.Equal(resp.Handle, []byte(cfg.Freshness.EpochMarker)) {
			t.Errorf("epoch handle = %q, expect %q", resp.Handle, cfg.Freshness.EpochMarker)
		}
		if tc.kind == est.FreshnessAbsentTimestamp && resp.MaxAge != cfg.Freshness.TimestampMaxAge {
			t.Errorf("max_age = %d, expect %d", resp.MaxAge, cfg.Freshness.TimestampMaxAge)
		}

		return resp
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.kind, func(t *testing.T) {
			t.Run("InitiateEnroll", func(t *testing.T) {
				resp := initFor(t, tc, tc.enrollTarget, cfg.CredentialTypes.X509, est.MechanismEnroll)
				if len(resp.AcceptableCSK) == 0 {
					t.Error("enroll mode must advertise acceptable CSK suites")
				}
			})

			t.Run("InitiateRetrieve", func(t *testing.T) {
				resp := initFor(t, tc, tc.retrieveTarget, cfg.CredentialTypes.Bearer, est.MechanismRetrieve)
				if len(resp.AcceptableCEK) == 0 {
					t.Error("retrieve mode must advertise acceptable CEK suites")
				}
			})

			t.Run("Enroll", func(t *testing.T) {
				handle := tc.localHandle
				if tc.present {
					handle = initFor(t, tc, tc.enrollTarget, cfg.CredentialTypes.X509, est.MechanismEnroll).Handle
				}
				csr, _ := newCSR(t)
				cert, err := client.EnrollCredential(ctx, &est.AttestedEnrollmentRequest{
					Target:         tc.enrollTarget,
					CredentialType: cfg.CredentialTypes.X509,
					FreshnessKind:  tc.kind,
					Handle:         handle,
					CSR:            csr.Raw,
					Evidence:       newMockEvidence(t, tc.kind, handle, serverID(), tc.enrollTarget, csr.Raw),
					Binding:        est.Binding{Method: est.BindingInput, Hash: "sha512"},
				})
				if err != nil {
					t.Fatalf("attest-enroll: %v", err)
				}
				verifyChain(t, cert, anchor)
			})

			t.Run("Retrieve", func(t *testing.T) {
				handle := tc.localHandle
				if tc.present {
					handle = initFor(t, tc, tc.retrieveTarget, cfg.CredentialTypes.Bearer, est.MechanismRetrieve).Handle
				}
				cekPriv, cekPub := newCEK(t)
				sealed, err := client.RetrieveCredential(ctx, &est.AttestedRetrievalRequest{
					Target:         tc.retrieveTarget,
					CredentialType: cfg.CredentialTypes.Bearer,
					FreshnessKind:  tc.kind,
					Handle:         handle,
					CEKPub:         cekPub,
					Evidence:       newMockEvidence(t, tc.kind, handle, serverID(), tc.retrieveTarget, cekPub),
					Binding:        est.Binding{Method: est.BindingInput, Hash: "sha512"},
				})
				if err != nil {
					t.Fatalf("attest-retrieve: %v", err)
				}
				if _, err := sealed.Open(cekPriv); err != nil {
					t.Fatalf("open retrieved bundle: %v", err)
				}
			})
		})
	}

	t.Run("AbsentTimestamp/Stale", func(t *testing.T) {
		target := cfg.Freshness.EnrollTargets.AbsentTimestamp
		csr, _ := newCSR(t)
		_, err := client.EnrollCredential(ctx, &est.AttestedEnrollmentRequest{
			Target:         target,
			CredentialType: cfg.CredentialTypes.X509,
			FreshnessKind:  est.FreshnessAbsentTimestamp,
			CSR:            csr.Raw,
			Evidence: newMockEvidenceAt(
				t, est.FreshnessAbsentTimestamp, nil, serverID(), target, csr.Raw,
				time.Now().Add(-time.Duration(cfg.Freshness.TimestampMaxAge+30)*time.Second),
			),
			Binding: est.Binding{Method: est.BindingInput, Hash: "sha512"},
		})
		assertStatus(t, err, 403)
	})

	t.Run("AbsentTimestamp/Future", func(t *testing.T) {
		target := cfg.Freshness.EnrollTargets.AbsentTimestamp
		csr, _ := newCSR(t)
		_, err := client.EnrollCredential(ctx, &est.AttestedEnrollmentRequest{
			Target:         target,
			CredentialType: cfg.CredentialTypes.X509,
			FreshnessKind:  est.FreshnessAbsentTimestamp,
			CSR:            csr.Raw,
			Evidence: newMockEvidenceAt(
				t, est.FreshnessAbsentTimestamp, nil, serverID(), target, csr.Raw,
				time.Now().Add(time.Minute),
			),
			Binding: est.Binding{Method: est.BindingInput, Hash: "sha512"},
		})
		assertStatus(t, err, 403)
	})

	for _, tc := range []struct {
		kind   string
		target string
	}{
		{est.FreshnessAbsentEpoch, cfg.Freshness.EnrollTargets.AbsentEpoch},
		{est.FreshnessPresentEpoch, cfg.Freshness.EnrollTargets.PresentEpoch},
	} {
		tc := tc
		t.Run(tc.kind+"/Stale", func(t *testing.T) {
			staleMarker := []byte("stale-epoch-marker")
			csr, _ := newCSR(t)
			_, err := client.EnrollCredential(ctx, &est.AttestedEnrollmentRequest{
				Target:         tc.target,
				CredentialType: cfg.CredentialTypes.X509,
				FreshnessKind:  tc.kind,
				Handle:         staleMarker,
				CSR:            csr.Raw,
				Evidence:       newMockEvidence(t, tc.kind, staleMarker, serverID(), tc.target, csr.Raw),
				Binding:        est.Binding{Method: est.BindingInput, Hash: "sha512"},
			})
			assertStatus(t, err, 409)
		})
	}

	t.Run("PolicyMismatch", func(t *testing.T) {
		csr, _ := newCSR(t)
		_, err := client.EnrollCredential(ctx, &est.AttestedEnrollmentRequest{
			Target:         target(),
			CredentialType: cfg.CredentialTypes.X509,
			FreshnessKind:  est.FreshnessAbsentNone,
			CSR:            csr.Raw,
			Evidence:       newMockEvidence(t, est.FreshnessAbsentNone, nil, serverID(), target(), csr.Raw),
			Binding:        est.Binding{Method: est.BindingInput, Hash: "sha512"},
		})
		assertStatus(t, err, 403)
	})
}
