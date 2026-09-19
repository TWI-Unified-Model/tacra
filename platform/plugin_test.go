package platform

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"

	"github.com/veraison/eat"
	"github.com/veraison/go-cose"
)

func TestSimulatedRetrieveEvidence(t *testing.T) {
	p, err := NewSimulated()
	if err != nil {
		t.Fatal(err)
	}

	cek, err := p.GenerateCEK()
	if err != nil {
		t.Fatal(err)
	}
	ec, ok := cek.Public().(*ecdsa.PublicKey)
	if !ok || ec.Curve != elliptic.P256() {
		t.Fatalf("CEK %T, want P-256 ECDSA", cek.Public())
	}

	handle := bytes.Repeat([]byte{0x11}, 32)
	ev, err := p.GenerateEvidence(EvidenceRequest{
		FreshnessHandle: handle,
		BoundKey:        cek.Public(),
	})
	if err != nil {
		t.Fatal(err)
	}
	assertCOSESign1(t, ev.Token)
	if ev.MediaType != MediaTypeEATProfile {
		t.Fatalf("media type %q", ev.MediaType)
	}

	claims, err := ev.Verify(p.AttestationPublicKey())
	if err != nil {
		t.Fatal(err)
	}
	assertNonce(t, claims, handle)
	if claims.BoundKeyUse != BoundKeyUseEncrypt {
		t.Fatalf("bound key use %d, want encrypt", claims.BoundKeyUse)
	}
	if len(claims.CSR) != 0 {
		t.Fatalf("CSR present in retrieve evidence: %d bytes", len(claims.CSR))
	}
	assertBoundKey(t, claims, cek.Public())
	assertStandardEAT(t, claims)
	assertVeraisonEatDecode(t, ev.Claims, handle)
}

func TestSimulatedEnrollEvidence(t *testing.T) {
	ak, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewSimulated(WithAttestationKey(ak), WithIssuer("tacra-test"))
	if err != nil {
		t.Fatal(err)
	}

	csk, err := p.GenerateCSK(SigningAlgorithmECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	csr := []byte("dummy-pkcs10-csr")
	handle := bytes.Repeat([]byte{0x22}, 16)

	ev, err := p.GenerateEvidence(EvidenceRequest{
		FreshnessHandle: handle,
		BoundKey:        csk.Public(),
		CSR:             csr,
	})
	if err != nil {
		t.Fatal(err)
	}

	claims, err := VerifyEvidence(ev.Token, &ak.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Issuer != "tacra-test" {
		t.Fatalf("issuer %q", claims.Issuer)
	}
	if claims.BoundKeyUse != BoundKeyUseSign {
		t.Fatalf("bound key use %d, want sign", claims.BoundKeyUse)
	}
	if !bytes.Equal(claims.CSR, csr) {
		t.Fatalf("CSR mismatch")
	}
	assertBoundKey(t, claims, csk.Public())
	assertNonce(t, claims, handle)
}

func TestEvidenceRejectsBadFreshnessHandle(t *testing.T) {
	p, err := NewSimulated()
	if err != nil {
		t.Fatal(err)
	}
	cek, err := p.GenerateCEK()
	if err != nil {
		t.Fatal(err)
	}

	cases := [][]byte{
		[]byte("short"),
		bytes.Repeat([]byte{0x01}, 7),
		bytes.Repeat([]byte{0x01}, 65),
	}
	for _, ch := range cases {
		_, err := p.GenerateEvidence(EvidenceRequest{FreshnessHandle: ch, BoundKey: cek.Public()})
		if !errors.Is(err, ErrInvalidFreshnessHandle) {
			t.Errorf("freshness handle len %d: got %v, want ErrInvalidFreshnessHandle", len(ch), err)
		}
	}
}

func TestEvidenceOmitsNonceWhenHandleAbsent(t *testing.T) {
	p, err := NewSimulated()
	if err != nil {
		t.Fatal(err)
	}
	cek, err := p.GenerateCEK()
	if err != nil {
		t.Fatal(err)
	}
	ev, err := p.GenerateEvidence(EvidenceRequest{BoundKey: cek.Public()})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := ev.Verify(p.AttestationPublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if claims.Nonce != nil {
		t.Fatal("absent handle must omit eat_nonce")
	}
	if claims.IssuedAt == 0 {
		t.Fatal("iat")
	}
}

func TestEvidenceRejectsBadKey(t *testing.T) {
	p, err := NewSimulated()
	if err != nil {
		t.Fatal(err)
	}
	ch := bytes.Repeat([]byte{0x33}, 8)

	_, err = p.GenerateEvidence(EvidenceRequest{FreshnessHandle: ch})
	if !errors.Is(err, ErrMissingBoundKey) {
		t.Fatalf("nil key: %v", err)
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	_, err = p.GenerateEvidence(EvidenceRequest{FreshnessHandle: ch, BoundKey: &rsaKey.PublicKey})
	if !errors.Is(err, ErrUnsupportedKey) {
		t.Fatalf("short RSA key: %v", err)
	}

	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, err = p.GenerateEvidence(EvidenceRequest{FreshnessHandle: ch, BoundKey: &p384.PublicKey})
	if !errors.Is(err, ErrUnsupportedKey) {
		t.Fatalf("p384 key: %v", err)
	}
}

func TestEvidenceRSABoundKey(t *testing.T) {
	p, err := NewSimulated()
	if err != nil {
		t.Fatal(err)
	}
	csk, err := p.GenerateCSK(SigningAlgorithmRSA2048)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := csk.Public().(*rsa.PublicKey); !ok {
		t.Fatalf("CSK %T, want RSA", csk.Public())
	}
	handle := bytes.Repeat([]byte{0x66}, 8)
	ev, err := p.GenerateEvidence(EvidenceRequest{
		FreshnessHandle: handle,
		BoundKey:        csk.Public(),
		BoundKeyUse:     BoundKeyUseSign,
	})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := ev.Verify(p.AttestationPublicKey())
	if err != nil {
		t.Fatal(err)
	}
	assertBoundKey(t, claims, csk.Public())
}

func TestTamperedEvidenceFailsVerify(t *testing.T) {
	p, err := NewSimulated()
	if err != nil {
		t.Fatal(err)
	}
	cek, err := p.GenerateCEK()
	if err != nil {
		t.Fatal(err)
	}
	ev, err := p.GenerateEvidence(EvidenceRequest{
		FreshnessHandle: bytes.Repeat([]byte{0x44}, 8),
		BoundKey:        cek.Public(),
	})
	if err != nil {
		t.Fatal(err)
	}
	ev.Token[len(ev.Token)-1] ^= 0xff
	if _, err := ev.Verify(p.AttestationPublicKey()); err == nil {
		t.Fatal("expected signature failure")
	}
}

func TestWrongAKFailsVerify(t *testing.T) {
	p, err := NewSimulated()
	if err != nil {
		t.Fatal(err)
	}
	cek, err := p.GenerateCEK()
	if err != nil {
		t.Fatal(err)
	}
	ev, err := p.GenerateEvidence(EvidenceRequest{
		FreshnessHandle: bytes.Repeat([]byte{0x55}, 8),
		BoundKey:        cek.Public(),
	})
	if err != nil {
		t.Fatal(err)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyEvidence(ev.Token, &other.PublicKey); err == nil {
		t.Fatal("expected verification failure with wrong AK")
	}
}

func TestKeyPairEncodings(t *testing.T) {
	p, err := NewSimulated()
	if err != nil {
		t.Fatal(err)
	}
	kp, err := p.GenerateCSK(SigningAlgorithmECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	pkix, err := kp.PublicPKIX()
	if err != nil || len(pkix) == 0 {
		t.Fatalf("PKIX: %v", err)
	}
	pkcs8, err := kp.PrivatePKCS8()
	if err != nil || len(pkcs8) == 0 {
		t.Fatalf("PKCS8: %v", err)
	}
	signer, err := kp.Signer()
	if err != nil {
		t.Fatal(err)
	}
	if !publicKeysEqual(signer.Public(), kp.Public()) {
		t.Fatal("signer public key mismatch")
	}
	if _, err := p.AttestationPublicPKIX(); err != nil {
		t.Fatal(err)
	}
}

func TestPluginInterface(t *testing.T) {
	var _ Plugin = (*Simulated)(nil)
}

func TestWithUEIDRejectsInvalid(t *testing.T) {
	_, err := NewSimulated(WithUEID([]byte{0x01, 0x02}))
	if err == nil {
		t.Fatal("expected invalid UEID")
	}
}

func assertCOSESign1(t *testing.T, token []byte) {
	t.Helper()
	if len(token) == 0 || token[0] != 0xd2 {
		t.Fatalf("token is not tagged COSE_Sign1 (tag 18): first byte 0x%02x", firstByte(token))
	}
	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(token); err != nil {
		t.Fatalf("COSE_Sign1 unmarshal: %v", err)
	}
	ct, ok := msg.Headers.Protected[cose.HeaderLabelContentType]
	if !ok || ct != MediaTypeEAT {
		t.Fatalf("content type %v, want %s", ct, MediaTypeEAT)
	}
}

func firstByte(b []byte) byte {
	if len(b) == 0 {
		return 0
	}
	return b[0]
}

func assertNonce(t *testing.T, c *Claims, want []byte) {
	t.Helper()
	if c.Nonce == nil || c.Nonce.Len() != 1 {
		t.Fatalf("nonce missing")
	}
	got := c.Nonce.GetI(0)
	if !bytes.Equal(got, want) {
		t.Fatalf("nonce %x, want %x", got, want)
	}
}

func assertBoundKey(t *testing.T, c *Claims, want crypto.PublicKey) {
	t.Helper()
	got, err := c.Cnf.BoundPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if !publicKeysEqual(got, want) {
		t.Fatal("cnf public key mismatch")
	}
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	type equaler interface{ Equal(crypto.PublicKey) bool }
	eq, ok := a.(equaler)
	return ok && eq.Equal(b)
}

func assertStandardEAT(t *testing.T, c *Claims) {
	t.Helper()
	if err := c.UEID.Validate(); err != nil {
		t.Fatal(err)
	}
	if c.Profile == nil {
		t.Fatal("missing eat_profile")
	}
	uri, err := c.Profile.Get()
	if err != nil || uri != ProfileURI {
		t.Fatalf("profile %q (%v)", uri, err)
	}
	if c.OemBoot == nil || !*c.OemBoot {
		t.Fatal("oemboot")
	}
	if c.DebugStatus == nil || *c.DebugStatus != eat.DebugDisabledSinceBoot {
		t.Fatal("dbgstat")
	}
	if c.IssuedAt == 0 {
		t.Fatal("iat")
	}
}

func assertVeraisonEatDecode(t *testing.T, payload, handle []byte) {
	t.Helper()
	var e eat.Eat
	if err := e.FromCBOR(payload); err != nil {
		t.Fatalf("veraison/eat FromCBOR: %v", err)
	}
	if e.Nonce == nil || !bytes.Equal(e.Nonce.GetI(0), handle) {
		t.Fatal("veraison/eat nonce mismatch")
	}
	if e.UEID == nil {
		t.Fatal("veraison/eat missing UEID")
	}
	if e.Cnf == nil || e.Cnf.Key == nil {
		t.Fatal("veraison/eat missing cnf")
	}
}
