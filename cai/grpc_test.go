package cai

import (
	"bytes"
	"context"
	"crypto/x509"
	"net"
	"testing"
	"time"

	caapiv1 "github.com/TWI-Unified-Model/twium/gen/go/caapi/v1"
	caiv1 "github.com/TWI-Unified-Model/twium/gen/go/cai/v1"
	"github.com/TWI-Unified-Model/twium/platform"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func TestGRPCAcquireCredential(t *testing.T) {
	challenge := bytes.Repeat([]byte{0x0c}, 32)
	fake := &fakeCAAPI{
		init: func(_ context.Context, in *caapiv1.InitiateCredentialAcquistionRequest) (*caapiv1.InitiateCredentialAcquisitionResponse, error) {
			mode := caapiv1.CredentialAcquisitionMode_ACQUISITION_RETRIEVE
			if in.GetCredentialType() == caapiv1.CredentialType_CREDENTIAL_TYPE_X509 {
				mode = caapiv1.CredentialAcquisitionMode_ACQUISITION_ENROLL
			}
			return &caapiv1.InitiateCredentialAcquisitionResponse{
				Mode:      mode,
				Challenge: challenge,
			}, nil
		},
		enroll: func(_ context.Context, in *caapiv1.EnrollCredentialRequest) (*caapiv1.EnrollCredentialResponse, error) {
			return &caapiv1.EnrollCredentialResponse{PlaintextCredential: []byte("dummy-cert")}, nil
		},
		retrieve: func(_ context.Context, in *caapiv1.RetrieveCredentialRequest) (*caapiv1.RetrieveCredentialResponse, error) {
			claims, err := platform.ParseEvidence(in.GetEvidence())
			if err != nil {
				t.Fatal(err)
			}
			pub, err := claims.Cnf.BoundPublicKey()
			if err != nil {
				t.Fatal(err)
			}
			wrapped, err := WrapCredential(pub, []byte("hdr.payload.sig"))
			if err != nil {
				t.Fatal(err)
			}
			return &caapiv1.RetrieveCredentialResponse{WrappedCredential: wrapped}, nil
		},
	}

	inner, _ := newTestCAI(t, fake)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer()
	caiv1.RegisterCredentialAcquisitionInterfaceServer(gs, NewGRPC(inner))
	go gs.Serve(ln)
	t.Cleanup(gs.Stop)

	conn, err := grpc.NewClient(ln.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	cli := caiv1.NewCredentialAcquisitionInterfaceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	x509Resp, err := cli.AcquireCredential(ctx, &caiv1.AcquireCredentialRequest{
		Target:         "https://api.example",
		CredentialType: caapiv1.CredentialType_CREDENTIAL_TYPE_X509,
	})
	if err != nil {
		t.Fatalf("X509: %v", err)
	}
	if _, err := x509.ParsePKCS8PrivateKey(x509Resp.GetPrivateKeyPkcs8()); err != nil {
		t.Fatalf("PKCS#8: %v", err)
	}

	jwtResp, err := cli.AcquireCredential(ctx, &caiv1.AcquireCredentialRequest{
		Target:         "https://api.example",
		CredentialType: caapiv1.CredentialType_CREDENTIAL_TYPE_JWT,
	})
	if err != nil {
		t.Fatalf("JWT: %v", err)
	}
	if string(jwtResp.GetDocument()) != "hdr.payload.sig" {
		t.Fatalf("JWT document %q", jwtResp.GetDocument())
	}
}
