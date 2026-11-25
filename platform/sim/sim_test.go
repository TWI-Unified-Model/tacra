package sim

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hpke"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/psatoken"

	"github.com/TWI-Unified-Model/tacra/platform"
)

const testTarget = "https://server.example"

var (
	testHandle      = bytes.Repeat([]byte{0xa5}, 32)
	testMeasurement = sha256.Sum256([]byte("a measured program"))
)

func newTestPlugin(t *testing.T, opts ...Option) *Simulated {
	t.Helper()
	p, err := NewSimulated(append([]Option{WithMeasurement(testMeasurement[:])}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func verified(t *testing.T, p *Simulated, e *platform.Evidence) psatoken.IClaims {
	t.Helper()
	if e.MediaType != MediaTypePSAToken {
		t.Fatalf("media type %q, expected %q", e.MediaType, MediaTypePSAToken)
	}
	claims, err := VerifyEvidence(e.Token, p.AttestationPublicKey())
	if err != nil {
		t.Fatal(err)
	}
	return claims
}

func nonceOf(t *testing.T, claims psatoken.IClaims) []byte {
	t.Helper()
	nonce, err := claims.GetNonce()
	if err != nil {
		t.Fatal(err)
	}
	return nonce
}

func TestRetrieveEvidence(t *testing.T) {
	p := newTestPlugin(t)
	cek, err := p.GenerateCEK(platform.EncryptionAlgorithmECDHP256)
	if err != nil {
		t.Fatal(err)
	}
	e, err := p.GenerateEvidence(platform.EvidenceRequest{
		FreshnessKind:   platform.FreshnessKindPresentNonce,
		FreshnessHandle: testHandle,
		BoundKey:        cek.Public(),
		BoundKeyUse:     platform.BoundKeyUseEncrypt,
		Target:          testTarget,
	})
	if err != nil {
		t.Fatal(err)
	}
	claims := verified(t, p, e)

	cekPub, err := platform.CEKPub(cek.Public())
	if err != nil {
		t.Fatal(err)
	}
	expected := platform.BindingValue(testHandle, testTarget, cekPub)
	if !bytes.Equal(nonceOf(t, claims), expected[:]) {
		t.Fatal("the nonce of the token is not the binding value over the Handle, the Target and CEKpub")
	}

	profile, err := claims.GetProfile()
	if err != nil || profile != ProfileName {
		t.Fatalf("profile %q, %v", profile, err)
	}
	implementation, err := claims.GetImplID()
	if err != nil || !bytes.Equal(implementation, ImplementationID()) {
		t.Fatalf("Implementation ID %x, %v", implementation, err)
	}
	instance, err := claims.GetInstID()
	if err != nil {
		t.Fatal(err)
	}
	expectedInstance, err := InstanceID(p.AttestationPublicKey())
	if err != nil || !bytes.Equal(instance, expectedInstance) {
		t.Fatalf("Instance ID %x, expected %x, %v", instance, expectedInstance, err)
	}
	lifecycle, err := claims.GetSecurityLifeCycle()
	if err != nil || lifecycle != psatoken.SecurityLifecycleSecuredMin {
		t.Fatalf("security lifecycle %#x, %v", lifecycle, err)
	}
	components, err := claims.GetSoftwareComponents()
	if err != nil || len(components) != 1 {
		t.Fatalf("software components %d, %v", len(components), err)
	}
	measurement, err := components[0].GetMeasurementValue()
	if err != nil || !bytes.Equal(measurement, testMeasurement[:]) {
		t.Fatalf("measurement %x, %v", measurement, err)
	}
	if !bytes.Equal(p.Measurement(), testMeasurement[:]) {
		t.Fatal("Measurement does not return the measurement of the token")
	}
	label, err := components[0].GetMeasurementType()
	if err != nil || label != MeasurementType {
		t.Fatalf("measurement type %q, %v", label, err)
	}
	if version, err := components[0].GetVersion(); err != nil || version == "" {
		t.Fatalf("version %q, %v: the psa-iot scheme of Veraison reads it of every component", version, err)
	}
	signer, err := components[0].GetSignerID()
	expectedSigner, _ := SignerID(p.AttestationPublicKey())
	if err != nil || !bytes.Equal(signer, expectedSigner) {
		t.Fatalf("signer ID %x, %v", signer, err)
	}

	var unsigned map[string]any
	if err := cbor.Unmarshal(e.Claims, &unsigned); err != nil {
		t.Fatal(err)
	}
	if unsigned[platform.TSMClaimTarget] != testTarget {
		t.Fatalf("unsigned Target %v", unsigned[platform.TSMClaimTarget])
	}
	if !bytes.Equal(unsigned[platform.TSMClaimFreshnessElement].([]byte), testHandle) {
		t.Fatal("unsigned freshness element is not the Handle")
	}
	if !bytes.Equal(unsigned[platform.TSMClaimBindingValue].([]byte), expected[:]) {
		t.Fatal("unsigned binding value is not the binding value")
	}
	if kind, ok := unsigned[platform.TSMClaimFreshnessKind].(uint64); !ok || kind != uint64(platform.FreshnessKindPresentNonce) {
		t.Fatalf("unsigned Freshness Kind %v", unsigned[platform.TSMClaimFreshnessKind])
	}
}

func TestEnrollEvidence(t *testing.T) {
	p := newTestPlugin(t)
	csk, err := p.GenerateCSK(platform.SigningAlgorithmECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	csr := []byte("the DER of a certification request")
	e, err := p.GenerateEvidence(platform.EvidenceRequest{
		FreshnessKind:   platform.FreshnessKindPresentNonce,
		FreshnessHandle: testHandle,
		BoundKey:        csk.Public(),
		CSR:             csr,
		Target:          testTarget,
	})
	if err != nil {
		t.Fatal(err)
	}
	expected := platform.BindingValue(testHandle, testTarget, csr)
	if !bytes.Equal(nonceOf(t, verified(t, p, e)), expected[:]) {
		t.Fatal("the nonce of the token is not the binding value over the Handle, the Target and the CSR")
	}
}

func TestBindingCoversTargetHandleAndSubject(t *testing.T) {
	p := newTestPlugin(t)
	cek, err := p.GenerateCEK(platform.EncryptionAlgorithmECDHP256)
	if err != nil {
		t.Fatal(err)
	}
	other, err := p.GenerateCEK(platform.EncryptionAlgorithmECDHP256)
	if err != nil {
		t.Fatal(err)
	}
	base := platform.EvidenceRequest{
		FreshnessKind:   platform.FreshnessKindPresentNonce,
		FreshnessHandle: testHandle,
		BoundKey:        cek.Public(),
		Target:          testTarget,
	}
	nonce := func(req platform.EvidenceRequest) []byte {
		e, err := p.GenerateEvidence(req)
		if err != nil {
			t.Fatal(err)
		}
		return nonceOf(t, verified(t, p, e))
	}
	reference := nonce(base)

	otherTarget := base
	otherTarget.Target = "https://other.example"
	otherHandle := base
	otherHandle.FreshnessHandle = bytes.Repeat([]byte{0x5a}, 32)
	otherKey := base
	otherKey.BoundKey = other.Public()
	for name, req := range map[string]platform.EvidenceRequest{"Target": otherTarget, "Handle": otherHandle, "CEKpub": otherKey} {
		if bytes.Equal(nonce(req), reference) {
			t.Fatalf("another %s gave the same binding value", name)
		}
	}
}

func TestFreshnessKinds(t *testing.T) {
	now := time.Unix(1795600000, 0)
	p := newTestPlugin(t, WithClock(func() time.Time { return now }))
	cek, err := p.GenerateCEK(platform.EncryptionAlgorithmECDHP256)
	if err != nil {
		t.Fatal(err)
	}
	cekPub, err := platform.CEKPub(cek.Public())
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name    string
		kind    platform.FreshnessKind
		handle  []byte
		element []byte
	}{
		{name: "present-nonce", kind: platform.FreshnessKindPresentNonce, handle: testHandle, element: testHandle},
		{name: "present-epoch", kind: platform.FreshnessKindPresentEpoch, handle: testHandle, element: testHandle},
		{name: "absent-epoch", kind: platform.FreshnessKindAbsentEpoch, handle: p.LocalEpoch(), element: p.LocalEpoch()},
		{name: "absent-timestamp", kind: platform.FreshnessKindAbsentTimestamp, element: platform.TimestampElement(now.Unix())},
		{name: "absent-none", kind: platform.FreshnessKindAbsentNone},
	} {
		t.Run(tt.name, func(t *testing.T) {
			e, err := p.GenerateEvidence(platform.EvidenceRequest{FreshnessKind: tt.kind, FreshnessHandle: tt.handle, BoundKey: cek.Public(), Target: testTarget})
			if err != nil {
				t.Fatal(err)
			}
			expected := platform.BindingValue(tt.element, testTarget, cekPub)
			if !bytes.Equal(nonceOf(t, verified(t, p, e)), expected[:]) {
				t.Fatal("the nonce of the token is not the binding value over the freshness element of the Freshness Kind")
			}
		})
	}
}

func TestEvidenceRefusals(t *testing.T) {
	p := newTestPlugin(t)
	cek, err := p.GenerateCEK(platform.EncryptionAlgorithmECDHP256)
	if err != nil {
		t.Fatal(err)
	}
	for _, size := range []int{0, 5, 7, 65} {
		_, err := p.GenerateEvidence(platform.EvidenceRequest{
			FreshnessKind:   platform.FreshnessKindPresentNonce,
			FreshnessHandle: make([]byte, size),
			BoundKey:        cek.Public(),
			Target:          testTarget,
		})
		if !errors.Is(err, platform.ErrInvalidFreshnessHandle) {
			t.Fatalf("Handle of %d octets: got %v, expected platform.ErrInvalidFreshnessHandle", size, err)
		}
	}
	if _, err := p.GenerateEvidence(platform.EvidenceRequest{FreshnessKind: platform.FreshnessKindAbsentNone, FreshnessHandle: testHandle, BoundKey: cek.Public()}); !errors.Is(err, platform.ErrFreshnessElement) {
		t.Fatalf("absent-none with a Handle: got %v, expected platform.ErrFreshnessElement", err)
	}
	if _, err := p.GenerateEvidence(platform.EvidenceRequest{FreshnessKind: platform.FreshnessKindPresentNonce, FreshnessHandle: testHandle, Target: testTarget}); !errors.Is(err, platform.ErrMissingBoundKey) {
		t.Fatalf("Retrieval without a key: got %v, expected platform.ErrMissingBoundKey", err)
	}
	if _, err := p.GenerateEvidence(platform.EvidenceRequest{FreshnessKind: platform.FreshnessKindPresentNonce, FreshnessHandle: testHandle, BoundKeyUse: platform.BoundKeyUseSign, BoundKey: cek.Public()}); err == nil {
		t.Fatal("Enrollment without a CSR was not refused")
	}
	if _, err := p.GenerateEvidence(platform.EvidenceRequest{FreshnessHandle: testHandle, BoundKey: cek.Public()}); !errors.Is(err, platform.ErrFreshnessElement) {
		t.Fatalf("no Freshness Kind: got %v, expected platform.ErrFreshnessElement", err)
	}
}

func TestChangedTokenFailsVerification(t *testing.T) {
	p := newTestPlugin(t)
	cek, err := p.GenerateCEK(platform.EncryptionAlgorithmECDHP256)
	if err != nil {
		t.Fatal(err)
	}
	e, err := p.GenerateEvidence(platform.EvidenceRequest{FreshnessKind: platform.FreshnessKindPresentNonce, FreshnessHandle: testHandle, BoundKey: cek.Public(), Target: testTarget})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseEvidence(e.Token); err != nil {
		t.Fatal(err)
	}

	changed := append([]byte(nil), e.Token...)
	changed[len(changed)-1] ^= 0x01
	if _, err := VerifyEvidence(changed, p.AttestationPublicKey()); err == nil {
		t.Fatal("a token with a changed signature verified")
	}

	other := newTestPlugin(t)
	if _, err := VerifyEvidence(e.Token, other.AttestationPublicKey()); err == nil {
		t.Fatal("a token verified under the Attestation Key of another platform")
	}
	if _, err := ParseEvidence([]byte("not a token")); err == nil {
		t.Fatal("octets that are no token were decoded")
	}
}

func TestGenerateKeys(t *testing.T) {
	p := newTestPlugin(t)

	cek, err := p.GenerateCEK(platform.EncryptionAlgorithmECDHP256)
	if err != nil {
		t.Fatal(err)
	}
	if key, ok := cek.Public().(*ecdsa.PublicKey); !ok || key.Curve != elliptic.P256() {
		t.Fatalf("CEK %T, expected an ECDSA P-256 public key", cek.Public())
	}
	cek, err = p.GenerateCEK(platform.EncryptionAlgorithmMLKEM768P256)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cek.Public().(hpke.PublicKey); !ok {
		t.Fatalf("CEK %T, expected an hpke.PublicKey", cek.Public())
	}
	cek, err = p.GenerateCEK(platform.EncryptionAlgorithmRSA2048)
	if err != nil {
		t.Fatal(err)
	}
	if key, ok := cek.Public().(*rsa.PublicKey); !ok || key.N.BitLen() != 2048 {
		t.Fatalf("CEK %T, expected an RSA-2048 public key", cek.Public())
	}
	if _, err := p.GenerateCEK(platform.EncryptionAlgorithmUnspecified); !errors.Is(err, platform.ErrUnsupportedEncryptionAlgorithm) {
		t.Fatalf("got %v, expected platform.ErrUnsupportedEncryptionAlgorithm", err)
	}

	csk, err := p.GenerateCSK(platform.SigningAlgorithmECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := csk.Signer(); err != nil {
		t.Fatal(err)
	}
	if _, err := p.GenerateCSK(platform.SigningAlgorithm(99)); !errors.Is(err, platform.ErrUnsupportedSigningAlgorithm) {
		t.Fatalf("got %v, expected platform.ErrUnsupportedSigningAlgorithm", err)
	}
}

func TestAttestationKeyFile(t *testing.T) {
	key, err := NewAttestationKey()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := MarshalAttestationKey(key)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := ParseAttestationKey(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !decoded.Equal(key) {
		t.Fatal("the Attestation Key read from PEM is not the key written")
	}

	// Two instances with one Attestation Key name it by the same Instance ID.
	first := newTestPlugin(t, WithAttestationKey(key))
	second := newTestPlugin(t, WithAttestationKey(decoded))
	a, _ := InstanceID(first.AttestationPublicKey())
	b, _ := InstanceID(second.AttestationPublicKey())
	if len(a) != psatoken.InstIDLen || a[0] != 0x01 || !bytes.Equal(a, b) {
		t.Fatalf("Instance IDs %x and %x", a, b)
	}
	if bytes.Equal(first.LocalEpoch(), second.LocalEpoch()) {
		t.Fatal("two instances have the same boot seed")
	}

	for name, pemBytes := range map[string][]byte{
		"no PEM":       []byte("not PEM"),
		"another type": []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"),
	} {
		if _, err := ParseAttestationKey(pemBytes); err == nil {
			t.Fatalf("%s was read as an Attestation Key", name)
		}
	}
}

func TestOptionsRefuse(t *testing.T) {
	if _, err := NewSimulated(WithAttestationKey(nil)); err == nil {
		t.Fatal("no Attestation Key was accepted")
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewSimulated(WithAttestationKey(p384)); err == nil {
		t.Fatal("a P-384 Attestation Key was accepted")
	}
	if _, err := NewSimulated(WithMeasurement([]byte("short"))); !errors.Is(err, ErrMeasurement) {
		t.Fatalf("got %v, expected ErrMeasurement", err)
	}
}

func TestMeasurementOfTheRunningProgram(t *testing.T) {
	p, err := NewSimulated()
	if err != nil {
		t.Fatal(err)
	}
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	expected, err := MeasureFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(expected) != MeasurementSize || !bytes.Equal(p.Measurement(), expected) {
		t.Fatalf("measurement %x, expected the SHA-256 of the running program %x", p.Measurement(), expected)
	}
	if len(ImplementationID()) != psatoken.ImplIDLen {
		t.Fatalf("Implementation ID of %d octets", len(ImplementationID()))
	}
	if _, err := MeasureFile("/nonexistent/program"); err == nil {
		t.Fatal("a file that does not exist was measured")
	}
}

func TestPluginInterface(t *testing.T) {
	var p platform.Plugin = newTestPlugin(t)
	if p.Name() != "simulated" {
		t.Fatalf("name %q", p.Name())
	}
}

func TestAttestationPublicKey(t *testing.T) {
	key, err := NewAttestationKey()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := MarshalAttestationPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	block, rest := pem.Decode(encoded)
	if block == nil || block.Type != "PUBLIC KEY" || len(rest) != 0 {
		t.Fatalf("the public Attestation Key is not one PEM block of type PUBLIC KEY: %q", encoded)
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !key.PublicKey.Equal(parsed) {
		t.Fatal("the public key read from PEM is not the public half of the Attestation Key")
	}
}
