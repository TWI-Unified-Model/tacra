package main

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"testing"
	"time"

	caapiv1 "github.com/TWI-Unified-Model/tacra/gen/go/caapi/v1"
	"github.com/TWI-Unified-Model/tacra/platform"
	"github.com/fxamacker/cbor/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func TestCAAPIEnrollAndRetrieve(t *testing.T) {
	iss, err := newIssuer()
	if err != nil {
		t.Fatal(err)
	}
	cas, err := newCAAPIServer(iss)
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer()
	caapiv1.RegisterCredentialAcquisitionServiceServer(gs, cas)
	go gs.Serve(ln)
	t.Cleanup(gs.Stop)

	conn, err := grpc.NewClient(ln.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	cli := caapiv1.NewCredentialAcquisitionServiceClient(conn)

	plugin, err := platform.NewSimulated()
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	target := "https://localhost:8443"

	initEnroll, err := cli.InitiateRemoteAttestation(ctx, &caapiv1.InitiateCredentialAcquistionRequest{
		Target:         target,
		CredentialType: caapiv1.CredentialType_CREDENTIAL_TYPE_X509,
	})
	if err != nil {
		t.Fatalf("initiate enroll: %v", err)
	}
	if initEnroll.GetMode() != caapiv1.CredentialAcquisitionMode_ACQUISITION_ENROLL {
		t.Fatalf("mode %s", initEnroll.GetMode())
	}
	csk, err := plugin.GenerateCSK(platform.SigningAlgorithm(initEnroll.GetSigningAlgorithm()))
	if err != nil {
		t.Fatal(err)
	}
	csr := mustCSR(t, csk, target)
	enrollEv, err := plugin.GenerateEvidence(platform.EvidenceRequest{
		FreshnessKind:   platform.FreshnessKind(initEnroll.GetFreshnessKind()),
		FreshnessHandle: initEnroll.GetFreshnessHandle(),
		BoundKey:        csk.Public(),
		CSR:             csr,
		BoundKeyUse:     platform.BoundKeyUseSign,
	})
	if err != nil {
		t.Fatal(err)
	}
	enroll, err := cli.EnrollCredential(ctx, &caapiv1.EnrollCredentialRequest{
		Target:           target,
		CredentialType:   caapiv1.CredentialType_CREDENTIAL_TYPE_X509,
		Evidence:         enrollEv.Token,
		Csr:              csr,
		SigningAlgorithm: new(initEnroll.GetSigningAlgorithm()),
	})
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	block, rest := pem.Decode(enroll.GetPlaintextCredential())
	if block == nil {
		t.Fatal("expected PEM cert")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if leaf.PublicKey == nil {
		t.Fatal("leaf has no public key")
	}
	if caBlock, _ := pem.Decode(rest); caBlock == nil {
		t.Fatal("expected CA cert after leaf")
	}

	initRetr, err := cli.InitiateRemoteAttestation(ctx, &caapiv1.InitiateCredentialAcquistionRequest{
		Target:         target,
		CredentialType: caapiv1.CredentialType_CREDENTIAL_TYPE_JWT,
	})
	if err != nil {
		t.Fatalf("initiate retrieve: %v", err)
	}
	if initRetr.GetMode() != caapiv1.CredentialAcquisitionMode_ACQUISITION_RETRIEVE {
		t.Fatalf("mode %s", initRetr.GetMode())
	}
	cek, err := plugin.GenerateCEK(platform.EncryptionAlgorithm(initRetr.GetEncryptionAlgorithm()))
	if err != nil {
		t.Fatal(err)
	}
	retrEv, err := plugin.GenerateEvidence(platform.EvidenceRequest{
		FreshnessKind:   platform.FreshnessKind(initRetr.GetFreshnessKind()),
		FreshnessHandle: initRetr.GetFreshnessHandle(),
		BoundKey:        cek.Public(),
		BoundKeyUse:     platform.BoundKeyUseEncrypt,
	})
	if err != nil {
		t.Fatal(err)
	}
	retr, err := cli.RetrieveCredential(ctx, &caapiv1.RetrieveCredentialRequest{
		Target:              target,
		CredentialType:      caapiv1.CredentialType_CREDENTIAL_TYPE_JWT,
		Evidence:            retrEv.Token,
		EncryptionAlgorithm: new(initRetr.GetEncryptionAlgorithm()),
	})
	if err != nil {
		t.Fatalf("retrieve: %v", err)
	}
	tok, err := unwrapCredential(cek.Private, retr.GetWrappedCredential())
	if err != nil {
		t.Fatal(err)
	}
	if err := cas.verifyJWT(string(tok)); err != nil {
		t.Fatalf("verify JWT: %v", err)
	}
}

func mustCSR(t *testing.T, csk *platform.KeyPair, target string) []byte {
	t.Helper()
	signer, err := csk.Signer()
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: target},
	}, signer)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func unwrapCredential(priv crypto.PrivateKey, wrapped []byte) ([]byte, error) {
	var w wrappedV1
	if err := cbor.Unmarshal(wrapped, &w); err != nil {
		return nil, err
	}
	ephAny, err := x509.ParsePKIXPublicKey(w.Ephemeral)
	if err != nil {
		return nil, err
	}
	ephECDH, err := publicToECDH(ephAny)
	if err != nil {
		return nil, err
	}
	cekECDH, err := privateToECDH(priv)
	if err != nil {
		return nil, err
	}
	secret, err := cekECDH.ECDH(ephECDH)
	if err != nil {
		return nil, err
	}
	key, err := deriveWrapKey(secret)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, w.Nonce, w.Ciphertext, nil)
}

func privateToECDH(priv crypto.PrivateKey) (*ecdh.PrivateKey, error) {
	switch k := priv.(type) {
	case *ecdh.PrivateKey:
		return k, nil
	case *ecdsa.PrivateKey:
		return k.ECDH()
	default:
		return nil, fmt.Errorf("key type %T", priv)
	}
}
