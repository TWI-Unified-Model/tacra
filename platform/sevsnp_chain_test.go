package platform

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	"github.com/google/go-sev-guest/kds"
	"github.com/google/go-sev-guest/verify/trust"
)

// leafIssuedBy returns a DER certificate whose issuer common name is cn (self-signed, so subject and issuer agree).
func leafIssuedBy(t *testing.T, cn string) []byte {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func table(t *testing.T, entries map[string][]byte, order ...string) []byte {
	t.Helper()
	var es []certEntry
	for _, g := range order {
		b, _ := hex.DecodeString(g)
		es = append(es, certEntry{b, entries[g]})
	}
	return encodeCertTable(es)
}

func TestCompleteCertTable(t *testing.T) {
	milanVlekASVK, milanARK, err := kds.ParseProductCertChain(trust.AskArkMilanVlekBytes)
	if err != nil {
		t.Fatal(err)
	}
	genoaASK, genoaARK, err := kds.ParseProductCertChain(trust.AskArkGenoaVcekBytes)
	if err != nil {
		t.Fatal(err)
	}
	vlek := leafIssuedBy(t, "SEV-VLEK-Milan")
	vcekGenoa := leafIssuedBy(t, "SEV-Genoa")

	t.Run("AWS: VLEK only gets the Milan ASVK and ARK", func(t *testing.T) {
		out, added, err := completeCertTable(table(t, map[string][]byte{guidVLEK: vlek}, guidVLEK))
		if err != nil || !added {
			t.Fatalf("added=%v err=%v", added, err)
		}
		certs, err := ParseSNPCertTable(out)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(certs["VLEK"], vlek) || !bytes.Equal(certs["ASK"], milanVlekASVK) || !bytes.Equal(certs["ARK"], milanARK) {
			t.Fatal("table is not VLEK + Milan ASVK + Milan ARK")
		}
	})
	t.Run("VCEK only gets the Genoa ASK and ARK", func(t *testing.T) {
		out, added, err := completeCertTable(table(t, map[string][]byte{guidVCEK: vcekGenoa}, guidVCEK))
		if err != nil || !added {
			t.Fatalf("added=%v err=%v", added, err)
		}
		certs, _ := ParseSNPCertTable(out)
		if !bytes.Equal(certs["ASK"], genoaASK) || !bytes.Equal(certs["ARK"], genoaARK) {
			t.Fatal("table is not VCEK + Genoa ASK + Genoa ARK")
		}
	})
	t.Run("GCP: a complete table is left as delivered", func(t *testing.T) {
		in := table(t, map[string][]byte{guidVCEK: vcekGenoa, guidASK: genoaASK, guidARK: genoaARK}, guidVCEK, guidASK, guidARK)
		out, added, err := completeCertTable(in)
		if err != nil || added || !bytes.Equal(out, in) {
			t.Fatalf("added=%v err=%v changed=%v", added, err, !bytes.Equal(out, in))
		}
	})
	t.Run("an issuer that names no known product line is left as delivered", func(t *testing.T) {
		in := table(t, map[string][]byte{guidVCEK: leafIssuedBy(t, "fake VCEK")}, guidVCEK)
		out, added, err := completeCertTable(in)
		if err != nil || added || !bytes.Equal(out, in) {
			t.Fatalf("added=%v err=%v", added, err)
		}
	})
}
