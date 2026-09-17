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

// CredentialType, Mode, and FreshnessKind are the CAAPI enums, re-exported
// so the Attester can depend on cai alone.
type (
	CredentialType = caapiv1.CredentialType
	Mode           = caapiv1.CredentialAcquisitionMode
	FreshnessKind  = caapiv1.FreshnessKind
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

	FreshnessUnspecified     FreshnessKind = caapiv1.FreshnessKind_FRESHNESS_KIND_UNSPECIFIED
	FreshnessAbsentNone      FreshnessKind = caapiv1.FreshnessKind_FRESHNESS_KIND_ABSENT_NONE
	FreshnessAbsentTimestamp FreshnessKind = caapiv1.FreshnessKind_FRESHNESS_KIND_ABSENT_TIMESTAMP
	FreshnessAbsentEpoch     FreshnessKind = caapiv1.FreshnessKind_FRESHNESS_KIND_ABSENT_EPOCH
	FreshnessPresentNonce    FreshnessKind = caapiv1.FreshnessKind_FRESHNESS_KIND_PRESENT_NONCE
	FreshnessPresentEpoch    FreshnessKind = caapiv1.FreshnessKind_FRESHNESS_KIND_PRESENT_EPOCH
)

// Credential is the document returned to the Attester.
type Credential struct {
	Type CredentialType
	// Document is the credential bytes (certificate, JWT, API key, …).
	Document []byte
	// PrivateKey is the CSK for Enrollment of proof-of-possession
	// credentials. Nil for Retrieval.
	PrivateKey *ecdsa.PrivateKey
}

// AcquisitionRequest is the CAS-chosen context for one enroll or retrieve
// exchange. Further fields (cipher suites, etc.) will be added here.
type AcquisitionRequest struct {
	Target string
	Type   CredentialType
	Hint   string
	Kind   FreshnessKind
	Handle []byte
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
func (c *Client) AcquireCredential(ctx context.Context, target string, credType CredentialType, credHint string) (*Credential, error) {
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

	handle, err := c.freshnessHandle(initResp)
	if err != nil {
		return nil, err
	}

	req := AcquisitionRequest{
		Target: target,
		Type:   credType,
		Hint:   credHint,
		Kind:   initResp.GetFreshnessKind(),
		Handle: handle,
	}
	switch initResp.GetMode() {
	case ModeRetrieve:
		return c.retrieve(ctx, req)
	case ModeEnroll:
		return c.enroll(ctx, req)
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedMode, initResp.GetMode())
	}
}

func (c *Client) retrieve(ctx context.Context, req AcquisitionRequest) (*Credential, error) {
	cek, err := c.plugin.GenerateCEK()
	if err != nil {
		return nil, fmt.Errorf("cai: generate CEK: %w", err)
	}
	ev, err := c.plugin.GenerateEvidence(platform.EvidenceRequest{
		FreshnessKind:   platform.FreshnessKind(req.Kind),
		FreshnessHandle: req.Handle,
		BoundKey:        cek.Public(),
		BoundKeyUse:     platform.BoundKeyUseEncrypt,
	})
	if err != nil {
		return nil, fmt.Errorf("cai: generate evidence: %w", err)
	}
	resp, err := c.caapi.RetrieveCredential(ctx, &caapiv1.RetrieveCredentialRequest{
		Target:         req.Target,
		CredentialType: req.Type,
		CredentialHint: optionalHint(req.Hint),
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
		Type:     req.Type,
		Document: doc,
	}, nil
}

func (c *Client) enroll(ctx context.Context, req AcquisitionRequest) (*Credential, error) {
	csk, err := c.plugin.GenerateCSK()
	if err != nil {
		return nil, fmt.Errorf("cai: generate CSK: %w", err)
	}
	csr, err := createCSR(csk, req.Target)
	if err != nil {
		return nil, err
	}
	ev, err := c.plugin.GenerateEvidence(platform.EvidenceRequest{
		FreshnessKind:   platform.FreshnessKind(req.Kind),
		FreshnessHandle: req.Handle,
		BoundKey:        csk.Public(),
		CSR:             csr,
		BoundKeyUse:     platform.BoundKeyUseSign,
	})
	if err != nil {
		return nil, fmt.Errorf("cai: generate evidence: %w", err)
	}
	resp, err := c.caapi.EnrollCredential(ctx, &caapiv1.EnrollCredentialRequest{
		Target:         req.Target,
		CredentialType: req.Type,
		CredentialHint: optionalHint(req.Hint),
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
		Type:       req.Type,
		Document:   resp.GetPlaintextCredential(),
		PrivateKey: csk.Private,
	}, nil
}

func optionalHint(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// freshnessHandle applies draft-novak-rats-tacra Freshness Kind rules.
// present-* kinds require a Handle that is embedded in Evidence.
// absent-* kinds return no Handle: absent-none and absent-timestamp omit
// eat_nonce (iat is the timestamp); absent-epoch uses a locally held epoch.
func (c *Client) freshnessHandle(resp *caapiv1.InitiateCredentialAcquisitionResponse) ([]byte, error) {
	kind := resp.GetFreshnessKind()
	handle := resp.GetFreshnessHandle()
	switch kind {
	case FreshnessPresentNonce, FreshnessPresentEpoch:
		if err := validatePresentHandle(handle); err != nil {
			return nil, err
		}
		return handle, nil
	case FreshnessAbsentNone, FreshnessAbsentTimestamp:
		if len(handle) != 0 {
			return nil, fmt.Errorf("%w: %s", ErrUnexpectedFreshnessHandle, kind)
		}
		return nil, nil
	case FreshnessAbsentEpoch:
		if len(handle) != 0 {
			return nil, fmt.Errorf("%w: %s", ErrUnexpectedFreshnessHandle, kind)
		}
		epoch := c.plugin.LocalEpoch()
		if len(epoch) == 0 {
			return nil, ErrNoLocalEpoch
		}
		if err := validatePresentHandle(epoch); err != nil {
			return nil, err
		}
		return epoch, nil
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedFreshnessKind, kind)
	}
}

func validatePresentHandle(h []byte) error {
	n := len(h)
	if n < eat.MinNonceSize || n > eat.MaxNonceSize {
		return fmt.Errorf("%w: got %d", ErrInvalidFreshnessHandle, n)
	}
	return nil
}
