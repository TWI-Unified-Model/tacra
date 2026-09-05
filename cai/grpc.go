package cai

import (
	"context"
	"crypto/x509"

	caiv1 "github.com/TWI-Unified-Model/twium/gen/go/cai/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// GRPC exposes Client as the Attester-facing CAI gRPC service (sidecar).
type GRPC struct {
	caiv1.UnimplementedCredentialAcquisitionInterfaceServer
	inner *Client
}

func NewGRPC(inner *Client) *GRPC {
	return &GRPC{inner: inner}
}

func (g *GRPC) AcquireCredential(ctx context.Context, in *caiv1.AcquireCredentialRequest) (*caiv1.AcquireCredentialResponse, error) {
	if g == nil || g.inner == nil {
		return nil, status.Error(codes.Internal, ErrNilClient.Error())
	}
	cred, err := g.inner.AcquireCredential(ctx, in.GetTarget(), in.GetCredentialType())
	if err != nil {
		return nil, status.Errorf(codes.Unknown, "%v", err)
	}
	resp := &caiv1.AcquireCredentialResponse{
		Type:      cred.Type,
		Mechanism: cred.Mechanism,
		Document:  cred.Document,
	}
	if cred.PrivateKey != nil {
		pkcs8, err := x509.MarshalPKCS8PrivateKey(cred.PrivateKey)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "marshal CSK: %v", err)
		}
		resp.PrivateKeyPkcs8 = pkcs8
	}
	return resp, nil
}
