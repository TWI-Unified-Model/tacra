package cai

import (
	"context"
	"crypto/ecdsa"
	"fmt"

	caapiv1 "github.com/TWI-Unified-Model/tacra/gen/go/caapi/v1"
	"github.com/TWI-Unified-Model/tacra/platform"
	"github.com/veraison/eat"
	"google.golang.org/grpc"
)

// CredentialType and Mode are the CAAPI enums, re-exported so the
// Attester can depend on cai alone.
type (
	CredentialType = caapiv1.CredentialType
	Mode           = caapiv1.CredentialAcquisitionMode
)

const (
	CredentialTypeUnspecified CredentialType = caapiv1.CredentialType_CREDENTIAL_TYPE_UNSPECIFIED
	CredentialTypeJWT         CredentialType = caapiv1.CredentialType_CREDENTIAL_TYPE_JWT
	CredentialTypePSK         CredentialType = caapiv1.CredentialType_CREDENTIAL_TYPE_PSK
	CredentialTypeAPIKey      CredentialType = caapiv1.CredentialType_CREDENTIAL_TYPE_API_KEY
	CredentialTypeX509        CredentialType = caapiv1.CredentialType_CREDENTIAL_TYPE_X509
	CredentialTypeWIC         CredentialType = caapiv1.CredentialType_CREDENTIAL_TYPE_WIC
	CredentialTypeWIT         CredentialType = caapiv1.CredentialType_CREDENTIAL_TYPE_WIT

	ModeUnspecified Mode = caapiv1.CredentialAcquisitionMode_ACQUISITION_UNSPECIFIED
	ModeEnroll      Mode = caapiv1.CredentialAcquisitionMode_ACQUISITION_ENROLL
	ModeRetrieve    Mode = caapiv1.CredentialAcquisitionMode_ACQUISITION_RETRIEVE
)

// Credential is the document returned to the Attester.
type Credential struct {
	Type CredentialType
	Mode Mode
	// Document is the credential bytes (certificate, JWT, API key, …).
	Document []byte
	// PrivateKey is the CSK for Enrollment of proof-of-possession
	// credentials. Nil for Retrieval.
	PrivateKey *ecdsa.PrivateKey
}

// Client is the CAI implementation: one AcquireCredential call that drives
// CAAPI and the platform plug-in.
type Client struct {
	plugin platform.Plugin
	caapi  caapiv1.CredentialAcquisitionServiceClient
}

// New constructs a CAI client. plugin must run in the Attester TEE; caapi is
// the CAAPI gRPC client (CAS Client side).
func New(plugin platform.Plugin, caapi caapiv1.CredentialAcquisitionServiceClient) (*Client, error) {
	if plugin == nil {
		return nil, ErrNilPlugin
	}
	if caapi == nil {
		return nil, ErrNilCAAPI
	}
	return &Client{plugin: plugin, caapi: caapi}, nil
}

// Dial opens a gRPC connection to addr and returns a CAI client. The caller
// closes conn. opts must include transport credentials.
func Dial(addr string, plugin platform.Plugin, opts ...grpc.DialOption) (*Client, *grpc.ClientConn, error) {
	conn, err := grpc.NewClient(addr, opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("cai: dial %s: %w", addr, err)
	}
	c, err := New(plugin, caapiv1.NewCredentialAcquisitionServiceClient(conn))
	if err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	return c, conn, nil
}

// AcquireCredential obtains a credential for target of the requested type.
// The CAS selects Enrollment or Retrieval; the Attester does not.
func (c *Client) AcquireCredential(ctx context.Context, target string, credType CredentialType) (*Credential, error) {
	if c == nil {
		return nil, ErrNilClient
	}
	if target == "" {
		return nil, ErrInvalidTarget
	}
	if credType == CredentialTypeUnspecified {
		return nil, ErrInvalidCredentialType
	}

	initResp, err := c.caapi.InitiateRemoteAttestation(ctx, &caapiv1.InitiateCredentialAcquistionRequest{
		Target:         target,
		CredentialType: credType,
	})
	if err != nil {
		return nil, rpcError("InitiateRemoteAttestation", err)
	}

	handle := initResp.GetFreshnessHandle()
	if n := len(handle); n < eat.MinNonceSize || n > eat.MaxNonceSize {
		return nil, fmt.Errorf("%w: got %d", ErrInvalidFreshnessHandle, n)
	}

	switch initResp.GetMode() {
	case ModeRetrieve:
		return c.retrieve(ctx, target, credType, handle)
	case ModeEnroll:
		return c.enroll(ctx, target, credType, handle)
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedMode, initResp.GetMode())
	}
}

func (c *Client) retrieve(ctx context.Context, target string, credType CredentialType, handle []byte) (*Credential, error) {
	cek, err := c.plugin.GenerateCEK()
	if err != nil {
		return nil, fmt.Errorf("cai: generate CEK: %w", err)
	}
	ev, err := c.plugin.GenerateEvidence(platform.EvidenceRequest{
		FreshnessHandle: handle,
		BoundKey:        cek.Public(),
		BoundKeyUse:     platform.BoundKeyUseEncrypt,
	})
	if err != nil {
		return nil, fmt.Errorf("cai: generate evidence: %w", err)
	}
	resp, err := c.caapi.RetrieveCredential(ctx, &caapiv1.RetrieveCredentialRequest{
		Target:         target,
		CredentialType: credType,
		Evidence:       ev.Token,
	})
	if err != nil {
		return nil, rpcError("RetrieveCredential", err)
	}
	if len(resp.GetWrappedCredential()) == 0 {
		return nil, ErrEmptyCredential
	}
	doc, err := UnwrapCredential(cek.Private, resp.GetWrappedCredential())
	if err != nil {
		return nil, err
	}
	return &Credential{
		Type:     credType,
		Mode:     ModeRetrieve,
		Document: doc,
	}, nil
}

func (c *Client) enroll(ctx context.Context, target string, credType CredentialType, handle []byte) (*Credential, error) {
	csk, err := c.plugin.GenerateCSK()
	if err != nil {
		return nil, fmt.Errorf("cai: generate CSK: %w", err)
	}
	csr, err := createCSR(csk, target)
	if err != nil {
		return nil, err
	}
	ev, err := c.plugin.GenerateEvidence(platform.EvidenceRequest{
		FreshnessHandle: handle,
		BoundKey:        csk.Public(),
		CSR:             csr,
		BoundKeyUse:     platform.BoundKeyUseSign,
	})
	if err != nil {
		return nil, fmt.Errorf("cai: generate evidence: %w", err)
	}
	resp, err := c.caapi.EnrollCredential(ctx, &caapiv1.EnrollCredentialRequest{
		Target:         target,
		CredentialType: credType,
		Evidence:       ev.Token,
		Csr:            csr,
	})
	if err != nil {
		return nil, rpcError("EnrollCredential", err)
	}
	if len(resp.GetPlaintextCredential()) == 0 {
		return nil, ErrEmptyCredential
	}
	return &Credential{
		Type:       credType,
		Mode:       ModeEnroll,
		Document:   resp.GetPlaintextCredential(),
		PrivateKey: csk.Private,
	}, nil
}
