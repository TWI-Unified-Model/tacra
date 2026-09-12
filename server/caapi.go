package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/TWI-Unified-Model/twium/cai"
	caapiv1 "github.com/TWI-Unified-Model/twium/gen/go/caapi/v1"
	"github.com/TWI-Unified-Model/twium/platform"
	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const jwtAudience = "twium-server"

type caapiServer struct {
	caapiv1.UnimplementedCredentialAcquisitionServiceServer
	issuer *issuer
	jwtKey []byte
}

func newCAAPIServer(iss *issuer) (*caapiServer, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("jwt key: %w", err)
	}
	return &caapiServer{issuer: iss, jwtKey: key}, nil
}

func (s *caapiServer) InitiateRemoteAttestation(_ context.Context, in *caapiv1.InitiateCredentialAcquistionRequest) (*caapiv1.InitiateCredentialAcquisitionResponse, error) {
	if in.GetTarget() == "" {
		return nil, status.Error(codes.InvalidArgument, "Invalid Target")
	}
	mode, err := modeFor(in.GetCredentialType())
	if err != nil {
		return nil, err
	}
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return nil, status.Errorf(codes.Internal, "challenge: %v", err)
	}
	return &caapiv1.InitiateCredentialAcquisitionResponse{
		Mode:      mode,
		Challenge: challenge,
	}, nil
}

func (s *caapiServer) EnrollCredential(_ context.Context, in *caapiv1.EnrollCredentialRequest) (*caapiv1.EnrollCredentialResponse, error) {
	if in.GetTarget() == "" {
		return nil, status.Error(codes.InvalidArgument, "Invalid Target")
	}
	if len(in.GetCsr()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "CSR is required")
	}
	if len(in.GetEvidence()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "Evidence is required")
	}
	claims, err := platform.ParseEvidence(in.GetEvidence())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "Evidence: %v", err)
	}
	if len(claims.CSR) > 0 && !bytes.Equal(claims.CSR, in.GetCsr()) {
		return nil, status.Error(codes.InvalidArgument, "Evidence CSR does not match request CSR")
	}
	pemBundle, err := s.issuer.issueFromCSR(in.GetCsr())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	return &caapiv1.EnrollCredentialResponse{PlaintextCredential: pemBundle}, nil
}

func (s *caapiServer) RetrieveCredential(_ context.Context, in *caapiv1.RetrieveCredentialRequest) (*caapiv1.RetrieveCredentialResponse, error) {
	if in.GetTarget() == "" {
		return nil, status.Error(codes.InvalidArgument, "Invalid Target")
	}
	if len(in.GetEvidence()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "Evidence is required")
	}
	claims, err := platform.ParseEvidence(in.GetEvidence())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "Evidence: %v", err)
	}
	pub, err := claims.Cnf.BoundPublicKey()
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "CEKpub: %v", err)
	}
	tok, err := s.issueJWT(in.GetTarget())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "JWT: %v", err)
	}
	wrapped, err := cai.WrapCredential(pub, []byte(tok))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "wrap: %v", err)
	}
	return &caapiv1.RetrieveCredentialResponse{WrappedCredential: wrapped}, nil
}

func (s *caapiServer) issueJWT(subject string) (string, error) {
	now := time.Now()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": "twium-cas",
		"sub": subject,
		"aud": jwtAudience,
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
	})
	return tok.SignedString(s.jwtKey)
}

func (s *caapiServer) verifyJWT(raw string) error {
	_, err := jwt.Parse(raw, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected signing method %v", t.Header["alg"])
		}
		return s.jwtKey, nil
	}, jwt.WithAudience(jwtAudience), jwt.WithIssuer("twium-cas"), jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
	return err
}

func modeFor(t caapiv1.CredentialType) (caapiv1.CredentialAcquisitionMode, error) {
	switch t {
	case caapiv1.CredentialType_CREDENTIAL_TYPE_X509, caapiv1.CredentialType_CREDENTIAL_TYPE_WIC:
		return caapiv1.CredentialAcquisitionMode_ACQUISITION_ENROLL, nil
	case caapiv1.CredentialType_CREDENTIAL_TYPE_JWT, caapiv1.CredentialType_CREDENTIAL_TYPE_PSK, caapiv1.CredentialType_CREDENTIAL_TYPE_API_KEY:
		return caapiv1.CredentialAcquisitionMode_ACQUISITION_RETRIEVE, nil
	case caapiv1.CredentialType_CREDENTIAL_TYPE_UNSPECIFIED:
		return 0, status.Error(codes.InvalidArgument, "Invalid Credential Type")
	default:
		return 0, status.Error(codes.InvalidArgument, "Unsupported Credential Type")
	}
}
