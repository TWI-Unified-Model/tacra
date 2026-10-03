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

// fakeSNP emulates /sys/kernel/config/tsm/report for the sev_guest provider:
// the report echoes inblob in REPORT_DATA, auxblob is a certificate table.
type fakeSNP struct {
	inblob   []byte
	gen      uint64
	aux      []byte
	provider string
	tamper   bool
	tdx      bool // outblob is a version 4 TDX quote, padded as the kernel's buffer is
}

func (f *fakeSNP) MkdirTemp(dir, pattern string) (string, error) {
	return dir + "/" + pattern + "0", nil
}
func (f *fakeSNP) ReadDir(string) ([]os.DirEntry, error) { return nil, nil }
func (f *fakeSNP) RemoveAll(string) error                { return nil }
func (f *fakeSNP) WriteFile(name string, b []byte) error {
	if path.Base(name) == "inblob" {
		f.inblob = append([]byte(nil), b...)
	}
	f.gen++
	return nil
}
func (f *fakeSNP) ReadFile(name string) ([]byte, error) {
	switch path.Base(name) {
	case "outblob":
		if f.tdx {
			q := make([]byte, 8000)
			binary.LittleEndian.PutUint16(q[tdxVersionOffset:], tdxQuoteVersion4)
			binary.LittleEndian.PutUint32(q[tdxTEETypeOffset:], tdxTEETypeTDX)
			copy(q[tdxReportDataStart:tdxReportDataEnd], f.inblob)
			binary.LittleEndian.PutUint32(q[tdxSignatureLenOffs:], 100)
			if f.tamper {
				q[tdxReportDataStart] ^= 1
			}
			return q, nil
		}
		var rd [64]byte
		copy(rd[:], f.inblob)
		if f.tamper {
			rd[0] ^= 1
		}
		raw := sgtest.TestRawReport(rd)
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
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fake VCEK"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	guid, _ := hex.DecodeString("63da758de6644564adc5f4b93be8accd")
	tbl := append([]byte(nil), guid...)
	tbl = binary.LittleEndian.AppendUint32(tbl, 48)
	tbl = binary.LittleEndian.AppendUint32(tbl, uint32(len(der)))
	tbl = append(tbl, make([]byte, 24)...)
	return append(tbl, der...), &k.PublicKey
}

func TestBindingValueMatchesDraftTestVector(t *testing.T) {
	handle, _ := hex.DecodeString(tvHandleHex)
	subject, _ := hex.DecodeString(tvSubjectHex)
	want, _ := hex.DecodeString(tvDigestHex)
	got := BindingValue(handle, tvTarget, tvRRPID, subject)
	if !bytes.Equal(got[:], want) {
		t.Fatalf("SHA-512(binding_input) = %x, want the draft's %x", got, want)
	}
	if n := len(BindingInput(handle, tvTarget, tvRRPID, subject)); n != 320 {
		t.Fatalf("binding_input is %d octets, the draft's vector is 320", n)
	}
}

func TestSEVSNPEvidenceAllFreshnessKinds(t *testing.T) {
	aux, vcek := certTable(t)
	fake := &fakeSNP{provider: "sev_guest", aux: aux}
	epoch := bytes.Repeat([]byte{0xe7}, 32)
	now := time.Unix(1790600000, 0)
	p, err := NewSEVSNP(WithTSMClient(fake), WithClock(func() time.Time { return now }), WithLocalEpoch(epoch))
	if err != nil {
		t.Fatal(err)
	}
	csk, _ := generateP256()
	cek, _ := generateP256()
	csr := []byte("a DER CSR stands here")
	nonce := bytes.Repeat([]byte{0x42}, 32)
	cases := []struct {
		name   string
		kind   FreshnessKind
		handle []byte
		want   []byte
	}{
		{"present-nonce", FreshnessKindPresentNonce, nonce, nonce},
		{"present-epoch", FreshnessKindPresentEpoch, epoch, epoch},
		{"absent-epoch", FreshnessKindAbsentEpoch, epoch, epoch},
		{"absent-timestamp", FreshnessKindAbsentTimestamp, nil, TimestampElement(now.Unix())},
		{"absent-none", FreshnessKindAbsentNone, nil, nil},
	}
	for _, c := range cases {
		for _, enroll := range []bool{true, false} {
			req := EvidenceRequest{FreshnessKind: c.kind, FreshnessHandle: c.handle, Target: "https://db.example",
				RelyingParty: "https://ca.example"}
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
			want := BindingValue(c.want, req.Target, req.RelyingParty, subject)
			rep, err := abi.ReportToProto(tsm.OutBlob)
			if err != nil {
				t.Fatal(err)
			}
			if tsm.Provider != "sev_guest" || !bytes.Equal(rep.GetReportData(), want[:]) {
				t.Fatalf("%s enroll=%v: REPORT_DATA does not carry the binding value", c.name, enroll)
			}
			var claims map[string]any
			if err := cbor.Unmarshal(ev.Claims, &claims); err != nil {
				t.Fatal(err)
			}
			if got, _ := claims["freshness-element"].([]byte); !bytes.Equal(got, c.want) && !(len(got) == 0 && len(c.want) == 0) {
				t.Fatalf("%s: freshness element %x, want %x", c.name, got, c.want)
			}
		}
	}
	if pub := p.AttestationPublicKey(); pub == nil || !pub.Equal(vcek) {
		t.Fatal("AttestationPublicKey is not the VCEK from the certificate table")
	}
}

func TestSEVSNPRefusesTamperedReportAndOtherProviders(t *testing.T) {
	cek, _ := generateP256()
	req := EvidenceRequest{FreshnessKind: FreshnessKindPresentNonce, FreshnessHandle: bytes.Repeat([]byte{1}, 16),
		BoundKey: cek.Public(), BoundKeyUse: BoundKeyUseEncrypt, Target: "t"}
	p, _ := NewSEVSNP(WithTSMClient(&fakeSNP{provider: "sev_guest", tamper: true}))
	if _, err := p.GenerateEvidence(req); !errors.Is(err, ErrReportDataMismatch) {
		t.Fatalf("tampered REPORT_DATA: got %v", err)
	}
	p, _ = NewSEVSNP(WithTSMClient(&fakeSNP{provider: "tdx_guest"}))
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
	epoch := bytes.Repeat([]byte{0xe7}, 32)
	now := time.Unix(1790600000, 0)
	p, err := NewTDX(WithTSMClient(&fakeSNP{provider: "tdx_guest", tdx: true}),
		WithClock(func() time.Time { return now }), WithLocalEpoch(epoch))
	if err != nil {
		t.Fatal(err)
	}
	cek, _ := generateP256()
	nonce := bytes.Repeat([]byte{0x42}, 32)
	for _, c := range []struct {
		kind   FreshnessKind
		handle []byte
		want   []byte
	}{
		{FreshnessKindPresentNonce, nonce, nonce},
		{FreshnessKindPresentEpoch, epoch, epoch},
		{FreshnessKindAbsentEpoch, epoch, epoch},
		{FreshnessKindAbsentTimestamp, nil, TimestampElement(now.Unix())},
		{FreshnessKindAbsentNone, nil, nil},
	} {
		req := EvidenceRequest{FreshnessKind: c.kind, FreshnessHandle: c.handle, Target: "https://db.example",
			RelyingParty: "https://vault.example", BoundKey: cek.Public(), BoundKeyUse: BoundKeyUseEncrypt}
		ev, err := p.GenerateEvidence(req)
		if err != nil {
			t.Fatalf("kind %d: %v", c.kind, err)
		}
		var tsm tsmReport
		if err := cbor.Unmarshal(ev.Token, &tsm); err != nil {
			t.Fatal(err)
		}
		spki, _ := x509.MarshalPKIXPublicKey(cek.Public())
		want := BindingValue(c.want, req.Target, req.RelyingParty, spki)
		if tsm.Provider != "tdx_guest" || !bytes.Equal(tsm.OutBlob[tdxReportDataStart:tdxReportDataEnd], want[:]) {
			t.Fatalf("kind %d: REPORTDATA does not carry the binding value", c.kind)
		}
		if n := tdxSignatureLenOffs + 4 + 100; len(tsm.OutBlob) != n {
			t.Fatalf("quote is %d octets, want the %d the signature length gives", len(tsm.OutBlob), n)
		}
	}
}

func TestTDXRefusesTamperedQuoteAndOtherProviders(t *testing.T) {
	cek, _ := generateP256()
	req := EvidenceRequest{FreshnessKind: FreshnessKindPresentNonce, FreshnessHandle: bytes.Repeat([]byte{1}, 16),
		BoundKey: cek.Public(), BoundKeyUse: BoundKeyUseEncrypt, Target: "t"}
	p, _ := NewTDX(WithTSMClient(&fakeSNP{provider: "tdx_guest", tdx: true, tamper: true}))
	if _, err := p.GenerateEvidence(req); !errors.Is(err, ErrReportDataMismatch) {
		t.Fatalf("tampered REPORTDATA: got %v", err)
	}
	p, _ = NewTDX(WithTSMClient(&fakeSNP{provider: "sev_guest", tdx: true}))
	if _, err := p.GenerateEvidence(req); !errors.Is(err, ErrNotTDX) {
		t.Fatalf("sev_guest provider: got %v", err)
	}
	p, _ = NewTDX(WithTSMClient(&fakeSNP{provider: "tdx_guest"})) // an SEV-SNP report where a quote belongs
	if _, err := p.GenerateEvidence(req); !errors.Is(err, ErrNotTDX) {
		t.Fatalf("not a quote: got %v", err)
	}
}
