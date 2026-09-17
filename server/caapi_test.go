package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"net"
	"testing"
	"time"

	"github.com/TWI-Unified-Model/tacra/cai"
	caapiv1 "github.com/TWI-Unified-Model/tacra/gen/go/caapi/v1"
	"github.com/TWI-Unified-Model/tacra/platform"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func TestAcquireX509AndJWT(t *testing.T) {
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

	plugin, err := platform.NewSimulated()
	if err != nil {
		t.Fatal(err)
	}
	c, err := cai.New(plugin, caapiv1.NewCredentialAcquisitionServiceClient(conn))
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	target := "https://localhost:8443"

	x509Cred, err := c.AcquireCredential(ctx, target, cai.CredentialTypeX509, "")
	if err != nil {
		t.Fatalf("X509: %v", err)
	}
	if x509Cred.PrivateKey == nil {
		t.Fatal("missing CSK")
	}
	block, rest := pem.Decode(x509Cred.Document)
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
	caBlock, _ := pem.Decode(rest)
	if caBlock == nil {
		t.Fatal("expected CA cert after leaf")
	}

	jwtCred, err := c.AcquireCredential(ctx, target, cai.CredentialTypeJWT, "")
	if err != nil {
		t.Fatalf("JWT: %v", err)
	}
	if err := cas.verifyJWT(string(jwtCred.Document)); err != nil {
		t.Fatalf("verify JWT: %v", err)
	}
}
