package cai

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"testing"

	caapiv1 "github.com/TWI-Unified-Model/tacra/gen/go/caapi/v1"
	"github.com/TWI-Unified-Model/tacra/platform"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type fakeCAAPI struct {
	init     func(context.Context, *caapiv1.InitiateCredentialAcquistionRequest) (*caapiv1.InitiateCredentialAcquisitionResponse, error)
	enroll   func(context.Context, *caapiv1.EnrollCredentialRequest) (*caapiv1.EnrollCredentialResponse, error)
	retrieve func(context.Context, *caapiv1.RetrieveCredentialRequest) (*caapiv1.RetrieveCredentialResponse, error)
}

func (f *fakeCAAPI) InitiateRemoteAttestation(ctx context.Context, in *caapiv1.InitiateCredentialAcquistionRequest, _ ...grpc.CallOption) (*caapiv1.InitiateCredentialAcquisitionResponse, error) {
	if f.init != nil {
		return f.init(ctx, in)
	}
	return nil, status.Error(codes.Unimplemented, "init")
}

func (f *fakeCAAPI) EnrollCredential(ctx context.Context, in *caapiv1.EnrollCredentialRequest, _ ...grpc.CallOption) (*caapiv1.EnrollCredentialResponse, error) {
	if f.enroll != nil {
		return f.enroll(ctx, in)
	}
	return nil, status.Error(codes.Unimplemented, "enroll")
}

func (f *fakeCAAPI) RetrieveCredential(ctx context.Context, in *caapiv1.RetrieveCredentialRequest, _ ...grpc.CallOption) (*caapiv1.RetrieveCredentialResponse, error) {
	if f.retrieve != nil {
		return f.retrieve(ctx, in)
	}
	return nil, status.Error(codes.Unimplemented, "retrieve")
}

func newTestCAI(t *testing.T, fake *fakeCAAPI) (*Client, *platform.Simulated) {
	t.Helper()
	p, err := platform.NewSimulated()
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(p, fake)
	if err != nil {
		t.Fatal(err)
	}
	return c, p
}

func TestAcquireCredentialRetrieve(t *testing.T) {
	secret := []byte("pre-shared-api-key")
	handle := bytes.Repeat([]byte{0x0a}, 32)

	fake := &fakeCAAPI{
		init: func(_ context.Context, in *caapiv1.InitiateCredentialAcquistionRequest) (*caapiv1.InitiateCredentialAcquisitionResponse, error) {
			if in.GetTarget() != "https://api.example" || in.GetCredentialType() != caapiv1.CredentialType_CREDENTIAL_TYPE_API_KEY {
				t.Fatalf("init args: %+v", in)
			}
			return &caapiv1.InitiateCredentialAcquisitionResponse{
				Mode:            caapiv1.CredentialAcquisitionMode_ACQUISITION_RETRIEVE,
				FreshnessKind:   caapiv1.FreshnessKind_FRESHNESS_KIND_PRESENT_NONCE,
				FreshnessHandle: handle,
			}, nil
		},
		retrieve: func(_ context.Context, in *caapiv1.RetrieveCredentialRequest) (*caapiv1.RetrieveCredentialResponse, error) {
			if in.GetCredentialHint() != "hint-retrieve" {
				t.Fatalf("hint %q", in.GetCredentialHint())
			}
			claims, err := platform.ParseEvidence(in.GetEvidence())
			if err != nil {
				t.Fatal(err)
			}
			if claims.BoundKeyUse != platform.BoundKeyUseEncrypt {
				t.Fatalf("bound key use %d", claims.BoundKeyUse)
			}
			if !bytes.Equal(claims.Nonce.GetI(0), handle) {
				t.Fatal("nonce mismatch")
			}
			pub, err := claims.Cnf.BoundPublicKey()
			if err != nil {
				t.Fatal(err)
			}
			wrapped, err := WrapCredential(pub, secret)
			if err != nil {
				t.Fatal(err)
			}
			return &caapiv1.RetrieveCredentialResponse{WrappedCredential: wrapped}, nil
		},
	}

	c, _ := newTestCAI(t, fake)
	cred, err := c.AcquireCredential(context.Background(), "https://api.example", CredentialTypeAPIKey, "hint-retrieve")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cred.Document, secret) {
		t.Fatalf("document %q", cred.Document)
	}
	if cred.PrivateKey != nil {
		t.Fatal("retrieve must not return CSK")
	}
}

func TestAcquireCredentialEnroll(t *testing.T) {
	handle := bytes.Repeat([]byte{0x0b}, 16)
	minted := []byte("dummy-x509-der")
	var gotCSR []byte

	fake := &fakeCAAPI{
		init: func(_ context.Context, _ *caapiv1.InitiateCredentialAcquistionRequest) (*caapiv1.InitiateCredentialAcquisitionResponse, error) {
			return &caapiv1.InitiateCredentialAcquisitionResponse{
				Mode:            caapiv1.CredentialAcquisitionMode_ACQUISITION_ENROLL,
				FreshnessKind:   caapiv1.FreshnessKind_FRESHNESS_KIND_PRESENT_NONCE,
				FreshnessHandle: handle,
			}, nil
		},
		enroll: func(_ context.Context, in *caapiv1.EnrollCredentialRequest) (*caapiv1.EnrollCredentialResponse, error) {
			if in.GetCredentialHint() != "hint-enroll" {
				t.Fatalf("hint %q", in.GetCredentialHint())
			}
			if len(in.GetCsr()) == 0 || len(in.GetEvidence()) == 0 {
				t.Fatal("missing csr or evidence")
			}
			gotCSR = append([]byte(nil), in.GetCsr()...)
			csr, err := x509.ParseCertificateRequest(in.GetCsr())
			if err != nil {
				t.Fatal(err)
			}
			if csr.Subject.CommonName != "https://ca.example" {
				t.Fatalf("CN %q", csr.Subject.CommonName)
			}
			claims, err := platform.ParseEvidence(in.GetEvidence())
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(claims.CSR, in.GetCsr()) {
				t.Fatal("evidence CSR != request CSR")
			}
			if claims.BoundKeyUse != platform.BoundKeyUseSign {
				t.Fatalf("bound key use %d", claims.BoundKeyUse)
			}
			pub, err := claims.Cnf.BoundPublicKey()
			if err != nil {
				t.Fatal(err)
			}
			csrPub, ok := csr.PublicKey.(*ecdsa.PublicKey)
			if !ok {
				t.Fatalf("CSR key %T", csr.PublicKey)
			}
			if csrPub.X.Cmp(pub.X) != 0 || csrPub.Y.Cmp(pub.Y) != 0 {
				t.Fatal("CSR public key != evidence cnf")
			}
			return &caapiv1.EnrollCredentialResponse{PlaintextCredential: minted}, nil
		},
	}

	c, _ := newTestCAI(t, fake)
	cred, err := c.AcquireCredential(context.Background(), "https://ca.example", CredentialTypeX509, "hint-enroll")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cred.Document, minted) {
		t.Fatal("minted credential mismatch")
	}
	if cred.PrivateKey == nil {
		t.Fatal("enroll must return CSK")
	}
	if cred.PrivateKey.Curve != elliptic.P256() {
		t.Fatal("CSK must be P-256")
	}
	csr, err := x509.ParseCertificateRequest(gotCSR)
	if err != nil {
		t.Fatal(err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatal(err)
	}
}

func TestAcquireCredentialValidation(t *testing.T) {
	c, _ := newTestCAI(t, &fakeCAAPI{})
	if _, err := c.AcquireCredential(context.Background(), "", CredentialTypeJWT, ""); !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("empty target: %v", err)
	}
	if _, err := c.AcquireCredential(context.Background(), "t", CredentialTypeUnspecified, ""); !errors.Is(err, ErrInvalidCredentialType) {
		t.Fatalf("unspecified type: %v", err)
	}
	if _, err := New(nil, &fakeCAAPI{}); !errors.Is(err, ErrNilPlugin) {
		t.Fatalf("nil plugin: %v", err)
	}
	p, _ := platform.NewSimulated()
	if _, err := New(p, nil); !errors.Is(err, ErrNilCAAPI) {
		t.Fatalf("nil caapi: %v", err)
	}
}

func TestAcquireCredentialCASError(t *testing.T) {
	fake := &fakeCAAPI{
		init: func(context.Context, *caapiv1.InitiateCredentialAcquistionRequest) (*caapiv1.InitiateCredentialAcquisitionResponse, error) {
			return nil, status.Error(codes.InvalidArgument, "Invalid Target")
		},
	}
	c, _ := newTestCAI(t, fake)
	_, err := c.AcquireCredential(context.Background(), "bad", CredentialTypeJWT, "")
	var ce *Error
	if !errors.As(err, &ce) {
		t.Fatalf("want *cai.Error, got %T %v", err, err)
	}
	if ce.GRPCStatus().Code() != codes.InvalidArgument {
		t.Fatalf("code %s", ce.GRPCStatus().Code())
	}
}

func TestAcquireCredentialBadFreshnessHandle(t *testing.T) {
	fake := &fakeCAAPI{
		init: func(context.Context, *caapiv1.InitiateCredentialAcquistionRequest) (*caapiv1.InitiateCredentialAcquisitionResponse, error) {
			return &caapiv1.InitiateCredentialAcquisitionResponse{
				Mode:            caapiv1.CredentialAcquisitionMode_ACQUISITION_RETRIEVE,
				FreshnessKind:   caapiv1.FreshnessKind_FRESHNESS_KIND_PRESENT_NONCE,
				FreshnessHandle: []byte("short"),
			}, nil
		},
	}
	c, _ := newTestCAI(t, fake)
	_, err := c.AcquireCredential(context.Background(), "t", CredentialTypeJWT, "")
	if !errors.Is(err, ErrInvalidFreshnessHandle) {
		t.Fatalf("got %v", err)
	}
}

func TestWrapRoundTrip(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("hello-secret")
	wrapped, err := WrapCredential(&priv.PublicKey, plain)
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnwrapCredential(priv, wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("got %q", got)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnwrapCredential(other, wrapped); err == nil {
		t.Fatal("wrong CEK must fail")
	}
}

func TestClientImplements(t *testing.T) {
	var _ caapiv1.CredentialAcquisitionServiceClient = (*fakeCAAPI)(nil)
}
