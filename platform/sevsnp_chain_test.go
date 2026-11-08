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
	chains, err := loadAMDChains("")
	if err != nil {
		t.Fatal(err)
	}
	milanVLEK, _ := chains.chain("SEV-VLEK-Milan")
	milanVlekASVK, milanARK := milanVLEK.ask, milanVLEK.ark
	genoa, _ := chains.chain("SEV-Genoa")
	genoaASK, genoaARK := genoa.ask, genoa.ark
	vlek := leafIssuedBy(t, "SEV-VLEK-Milan")
	vcekGenoa := leafIssuedBy(t, "SEV-Genoa")

	t.Run("AWS: VLEK only gets the Milan ASVK and ARK", func(t *testing.T) {
		out, added, err := completeCertTable(table(t, map[string][]byte{guidVLEK: vlek}, guidVLEK), chains)
		if err != nil || !added {
			t.Fatalf("added=%v err=%v", added, err)
		}
		certs, err := ParseSNPCertTable(out)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(certs[SNPCertVLEK], vlek) || !bytes.Equal(certs[SNPCertASK], milanVlekASVK) ||
			!bytes.Equal(certs[SNPCertARK], milanARK) {
			t.Fatal("table is not VLEK + Milan ASVK + Milan ARK")
		}
	})
	t.Run("VLEK on Turin gets the Turin ASVK and ARK", func(t *testing.T) {
		turin, ok := chains.chain("SEV-VLEK-Turin")
		if !ok {
			t.Fatal("no Turin VLEK chain")
		}
		turinASVK, turinARK := turin.ask, turin.ark
		vlekTurin := leafIssuedBy(t, "SEV-VLEK-Turin")
		out, added, err := completeCertTable(table(t, map[string][]byte{guidVLEK: vlekTurin}, guidVLEK), chains)
		if err != nil || !added {
			t.Fatalf("added=%v err=%v", added, err)
		}
		certs, _ := ParseSNPCertTable(out)
		if !bytes.Equal(certs[SNPCertASK], turinASVK) || !bytes.Equal(certs[SNPCertARK], turinARK) {
			t.Fatal("table is not VLEK + Turin ASVK + Turin ARK")
		}
	})
	t.Run("VCEK only gets the Genoa ASK and ARK", func(t *testing.T) {
		out, added, err := completeCertTable(table(t, map[string][]byte{guidVCEK: vcekGenoa}, guidVCEK), chains)
		if err != nil || !added {
			t.Fatalf("added=%v err=%v", added, err)
		}
		certs, _ := ParseSNPCertTable(out)
		if !bytes.Equal(certs[SNPCertASK], genoaASK) || !bytes.Equal(certs[SNPCertARK], genoaARK) {
			t.Fatal("table is not VCEK + Genoa ASK + Genoa ARK")
		}
	})
	t.Run("GCP: a complete table is left as delivered", func(t *testing.T) {
		in := table(t, map[string][]byte{guidVCEK: vcekGenoa, guidASK: genoaASK, guidARK: genoaARK}, guidVCEK, guidASK, guidARK)
		out, added, err := completeCertTable(in, chains)
		if err != nil || added || !bytes.Equal(out, in) {
			t.Fatalf("added=%v err=%v changed=%v", added, err, !bytes.Equal(out, in))
		}
	})
	t.Run("an issuer that names no known product line is left as delivered", func(t *testing.T) {
		in := table(t, map[string][]byte{guidVCEK: leafIssuedBy(t, "mock VCEK")}, guidVCEK)
		out, added, err := completeCertTable(in, chains)
		if err != nil || added || !bytes.Equal(out, in) {
			t.Fatalf("added=%v err=%v", added, err)
		}
	})
}

func TestAMDChainsAreKeyedByTheirASKName(t *testing.T) {
	chains, err := loadAMDChains("")
	if err != nil {
		t.Fatal(err)
	}
	for name, chain := range chains.byIssuer {
		c, err := x509.ParseCertificate(chain.ask)
		if err != nil {
			t.Fatal(err)
		}
		if c.Subject.CommonName != name {
			t.Fatalf("chain under %q has the ASK or ASVK %q", name, c.Subject.CommonName)
		}
		if _, err := x509.ParseCertificate(chain.ark); err != nil {
			t.Fatalf("%s: ARK: %v", name, err)
		}
	}
	// the copies this package ships are the bundles go-sev-guest embeds, byte for byte
	for issuer, bundle := range map[string][]byte{"SEV-Milan": trust.AskArkMilanVcekBytes, "SEV-VLEK-Turin": trust.AskArkTurinVlekBytes} {
		ch, _ := chains.chain(issuer)
		raw, err := shippedAMDChains.ReadFile("amdchains/" + ch.file)
		if err != nil || !bytes.Equal(raw, bundle) {
			t.Fatalf("%s: the shipped copy differs from the bundle of go-sev-guest", ch.file)
		}
	}
}
