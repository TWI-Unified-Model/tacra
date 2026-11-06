package platform

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/go-sev-guest/abi"
	sgtest "github.com/google/go-sev-guest/testing"
)

// Fixed inputs of the Evidence tests. testNow is the clock, 2026-09-28T12:53:20Z, so that the absent-timestamp
// element is known in advance.
var (
	testNow   = time.Date(2026, time.September, 28, 12, 53, 20, 0, time.UTC)
	testEpoch = bytes.Repeat([]byte{0xe7}, 32)
	testNonce = bytes.Repeat([]byte{0x42}, 32)
)

func testClock() time.Time {
	return testNow
}

// The mock TDX outblob: a quote whose signature data is mockTDXSignatureLen octets, in a buffer of mockTDXBufferLen
// octets, larger than the quote, as the buffer of the kernel is.
const (
	mockTDXSignatureLen = 100
	mockTDXBufferLen    = 8000
)

// mockSNP emulates /sys/kernel/config/tsm/report for the sev_guest provider:
// the report echoes inblob in REPORT_DATA, auxblob is a certificate table.
type mockSNP struct {
	inblob   []byte
	gen      uint64
	aux      []byte
	provider string
	signer   abi.ReportSigner // SIGNING_KEY of the report; the zero value is the VCEK
	tamper   bool
	tdx      bool // outblob is a version 4 TDX quote, padded as the buffer of the kernel is
}

func (f *mockSNP) MkdirTemp(dir, pattern string) (string, error) {
	return dir + "/" + pattern + "0", nil
}
func (f *mockSNP) ReadDir(string) ([]os.DirEntry, error) {
	return nil, nil
}
func (f *mockSNP) RemoveAll(string) error {
	return nil
}
func (f *mockSNP) WriteFile(name string, b []byte) error {
	if path.Base(name) == "inblob" {
		f.inblob = append([]byte(nil), b...)
	}
	f.gen++
	return nil
}
func (f *mockSNP) ReadFile(name string) ([]byte, error) {
	switch path.Base(name) {
	case "outblob":
		if f.tdx {
			q := make([]byte, mockTDXBufferLen)
			binary.LittleEndian.PutUint16(q[tdxVersionOffset:], tdxQuoteVersion4)
			binary.LittleEndian.PutUint32(q[tdxTEETypeOffset:], tdxTEETypeTDX)
			copy(q[tdxReportDataStart:tdxReportDataEnd], f.inblob)
			binary.LittleEndian.PutUint32(q[tdxSignatureLenOffs:], mockTDXSignatureLen)
			if f.tamper {
				q[tdxReportDataStart] ^= 1
			}
			return q, nil
		}
		var rd [abi.ReportDataSize]byte
		copy(rd[:], f.inblob)
		if f.tamper {
			rd[0] ^= 1
		}
		raw := sgtest.CreateRawReport(&sgtest.TestReportOptions{ReportData: rd[:],
			SignerInfo: abi.SignerInfo{SigningKey: f.signer}})
		return raw[:abi.ReportSize], nil
	case "auxblob":
		return f.aux, nil
	case "provider":
		return []byte(f.provider + "\n"), nil
	case "generation":
		return []byte(fmt.Sprintf("%d\n", f.gen)), nil
	}
	return nil, os.ErrNotExist
}

// certTable builds a one-entry host certificate table holding a P-384
// self-signed certificate under the VCEK GUID.
func certTable(t *testing.T) ([]byte, *ecdsa.PublicKey) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "mock VCEK"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	guid, _ := hex.DecodeString(guidVCEK)
	return encodeCertTable([]certEntry{{guid, der}}), &k.PublicKey
}

func TestSEVSNPEvidenceAllFreshnessKinds(t *testing.T) {
	aux, vcek := certTable(t)
	fake := &mockSNP{provider: snpProvider, aux: aux}
	p, err := NewSEVSNP(WithTSMClient(fake), WithClock(testClock), WithLocalEpoch(testEpoch))
	if err != nil {
		t.Fatal(err)
	}
	csk, _ := generateP256()
	cek, _ := generateP256()
	csr := []byte("a DER CSR stands here")
	cases := []struct {
		name     string
		kind     FreshnessKind
		handle   []byte
		expected []byte
	}{
		{"present-nonce", FreshnessKindPresentNonce, testNonce, testNonce},
		{"present-epoch", FreshnessKindPresentEpoch, testEpoch, testEpoch},
		{"absent-epoch", FreshnessKindAbsentEpoch, testEpoch, testEpoch},
		{"absent-timestamp", FreshnessKindAbsentTimestamp, nil, TimestampElement(testNow.Unix())},
		{"absent-none", FreshnessKindAbsentNone, nil, nil},
	}
	for _, c := range cases {
		for _, enroll := range []bool{true, false} {
			req := EvidenceRequest{FreshnessKind: c.kind, FreshnessHandle: c.handle, Target: "https://db.example"}
			var subject []byte
			if enroll {
				req.BoundKey, req.CSR, req.BoundKeyUse, subject = csk.Public(), csr, BoundKeyUseSign, csr
			} else {
				req.BoundKey, req.BoundKeyUse = cek.Public(), BoundKeyUseEncrypt
				subject, _ = x509.MarshalPKIXPublicKey(cek.Public())
			}
			ev, err := p.GenerateEvidence(req)
			if err != nil {
				t.Fatalf("%s enroll=%v: %v", c.name, enroll, err)
			}
			if ev.MediaType != TSMReportMediaTypeCBOR {
				t.Fatalf("media type %q", ev.MediaType)
			}
			var tsm tsmReport
			if err := cbor.Unmarshal(ev.Token, &tsm); err != nil {
				t.Fatal(err)
			}
			expected := BindingValue(c.expected, req.Target, subject)
			rep, err := abi.ReportToProto(tsm.OutBlob)
			if err != nil {
				t.Fatal(err)
			}
			if tsm.Provider != snpProvider || !bytes.Equal(rep.GetReportData(), expected[:]) {
				t.Fatalf("%s enroll=%v: REPORT_DATA does not carry the binding value", c.name, enroll)
			}
			var claims map[string]any
			if err := cbor.Unmarshal(ev.Claims, &claims); err != nil {
				t.Fatal(err)
			}
			if got, _ := claims[TSMClaimFreshnessElement].([]byte); !bytes.Equal(got, c.expected) && !(len(got) == 0 && len(c.expected) == 0) {
				t.Fatalf("%s: freshness element %x, expected %x", c.name, got, c.expected)
			}
		}
	}
	if pub := p.AttestationPublicKey(); pub == nil || !pub.Equal(vcek) {
		t.Fatal("AttestationPublicKey is not the VCEK from the certificate table")
	}
}

func TestSEVSNPAttestationPublicKeyIsTheKeyTheReportNames(t *testing.T) {
	vcek, vlek := leafIssuedBy(t, "SEV-Milan"), leafIssuedBy(t, "SEV-VLEK-Milan")
	fake := &mockSNP{provider: snpProvider, signer: abi.VlekReportSigner,
		aux: table(t, map[string][]byte{guidVCEK: vcek, guidVLEK: vlek}, guidVCEK, guidVLEK)}
	p, err := NewSEVSNP(WithTSMClient(fake), WithoutChainCompletion())
	if err != nil {
		t.Fatal(err)
	}
	cek, _ := generateP256()
	req := EvidenceRequest{FreshnessKind: FreshnessKindPresentNonce, FreshnessHandle: testNonce,
		BoundKey: cek.Public(), BoundKeyUse: BoundKeyUseEncrypt, Target: "t"}
	if _, err := p.GenerateEvidence(req); err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(vlek)
	if pub := p.AttestationPublicKey(); pub == nil || !pub.Equal(c.PublicKey) {
		t.Fatal("AttestationPublicKey is not the VLEK the report names, with a VCEK also in the table")
	}
	fake.aux = nil
	if _, err := p.GenerateEvidence(req); err != nil {
		t.Fatal(err)
	}
	if p.AttestationPublicKey() != nil {
		t.Fatal("AttestationPublicKey kept the key of an earlier report when the host supplied no table")
	}
}

func TestSEVSNPRefusesTamperedReportAndOtherProviders(t *testing.T) {
	cek, _ := generateP256()
	req := EvidenceRequest{FreshnessKind: FreshnessKindPresentNonce, FreshnessHandle: testNonce,
		BoundKey: cek.Public(), BoundKeyUse: BoundKeyUseEncrypt, Target: "t"}
	p, _ := NewSEVSNP(WithTSMClient(&mockSNP{provider: snpProvider, tamper: true}))
	if _, err := p.GenerateEvidence(req); !errors.Is(err, ErrReportDataMismatch) {
		t.Fatalf("tampered REPORT_DATA: got %v", err)
	}
	p, _ = NewSEVSNP(WithTSMClient(&mockSNP{provider: tdxProvider}))
	if _, err := p.GenerateEvidence(req); !errors.Is(err, ErrNotSEVSNP) {
		t.Fatalf("tdx provider: got %v", err)
	}
	req.FreshnessKind, req.FreshnessHandle = FreshnessKindAbsentNone, []byte("x")
	if _, err := p.GenerateEvidence(req); !errors.Is(err, ErrFreshnessElement) {
		t.Fatalf("absent-none with a handle: got %v", err)
	}
	if !strings.Contains(fmt.Sprint(ErrReportDataMismatch), "REPORT_DATA") {
		t.Fatal("error text")
	}
}

func TestTDXEvidenceAllFreshnessKinds(t *testing.T) {
	p, err := NewTDX(WithTSMClient(&mockSNP{provider: tdxProvider, tdx: true}),
		WithClock(testClock), WithLocalEpoch(testEpoch))
	if err != nil {
		t.Fatal(err)
	}
	cek, _ := generateP256()
	for _, c := range []struct {
		kind     FreshnessKind
		handle   []byte
		expected []byte
	}{
		{FreshnessKindPresentNonce, testNonce, testNonce},
		{FreshnessKindPresentEpoch, testEpoch, testEpoch},
		{FreshnessKindAbsentEpoch, testEpoch, testEpoch},
		{FreshnessKindAbsentTimestamp, nil, TimestampElement(testNow.Unix())},
		{FreshnessKindAbsentNone, nil, nil},
	} {
		req := EvidenceRequest{FreshnessKind: c.kind, FreshnessHandle: c.handle, Target: "https://db.example",
			BoundKey: cek.Public(), BoundKeyUse: BoundKeyUseEncrypt}
		ev, err := p.GenerateEvidence(req)
		if err != nil {
			t.Fatalf("kind %d: %v", c.kind, err)
		}
		var tsm tsmReport
		if err := cbor.Unmarshal(ev.Token, &tsm); err != nil {
			t.Fatal(err)
		}
		spki, _ := x509.MarshalPKIXPublicKey(cek.Public())
		expected := BindingValue(c.expected, req.Target, spki)
		if tsm.Provider != tdxProvider || !bytes.Equal(tsm.OutBlob[tdxReportDataStart:tdxReportDataEnd], expected[:]) {
			t.Fatalf("kind %d: REPORTDATA does not carry the binding value", c.kind)
		}
		if n := tdxSignatureLenOffs + tdxSignatureLenSize + mockTDXSignatureLen; len(tsm.OutBlob) != n {
			t.Fatalf("quote is %d octets, expected the %d the signature length gives", len(tsm.OutBlob), n)
		}
	}
}

func TestTDXRefusesTamperedQuoteAndOtherProviders(t *testing.T) {
	cek, _ := generateP256()
	req := EvidenceRequest{FreshnessKind: FreshnessKindPresentNonce, FreshnessHandle: testNonce,
		BoundKey: cek.Public(), BoundKeyUse: BoundKeyUseEncrypt, Target: "t"}
	p, _ := NewTDX(WithTSMClient(&mockSNP{provider: tdxProvider, tdx: true, tamper: true}))
	if _, err := p.GenerateEvidence(req); !errors.Is(err, ErrReportDataMismatch) {
		t.Fatalf("tampered REPORTDATA: got %v", err)
	}
	p, _ = NewTDX(WithTSMClient(&mockSNP{provider: snpProvider, tdx: true}))
	if _, err := p.GenerateEvidence(req); !errors.Is(err, ErrNotTDX) {
		t.Fatalf("sev_guest provider: got %v", err)
	}
	p, _ = NewTDX(WithTSMClient(&mockSNP{provider: tdxProvider})) // an SEV-SNP report where a quote belongs
	if _, err := p.GenerateEvidence(req); !errors.Is(err, ErrNotTDX) {
		t.Fatalf("not a quote: got %v", err)
	}
}
