package cai

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/TWI-Unified-Model/tacra/container"
	caapiv1 "github.com/TWI-Unified-Model/tacra/gen/go/caapi/v1"
	"github.com/TWI-Unified-Model/tacra/platform"
	"github.com/TWI-Unified-Model/tacra/platform/sim"
)

const testTarget = "https://server.example"

var (
	testHandle      = bytes.Repeat([]byte{0x0c}, 32)
	testMeasurement = sha256.Sum256([]byte("a measured program"))
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

func newTestCAI(t *testing.T, fake *fakeCAAPI) (*Client, *sim.Simulated) {
	t.Helper()
	p, err := sim.NewSimulated(sim.WithMeasurement(testMeasurement[:]))
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(p, fake)
	if err != nil {
		t.Fatal(err)
	}
	return c, p
}

// initiation answers Initiate-Credential-Acquisition with the given mode and
// the Freshness Kind present-nonce.
func initiation(mode Mode, signing SigningAlgorithm, encryption EncryptionAlgorithm) func(context.Context, *caapiv1.InitiateCredentialAcquistionRequest) (*caapiv1.InitiateCredentialAcquisitionResponse, error) {
	return func(context.Context, *caapiv1.InitiateCredentialAcquistionRequest) (*caapiv1.InitiateCredentialAcquisitionResponse, error) {
		resp := &caapiv1.InitiateCredentialAcquisitionResponse{Mode: mode, FreshnessKind: FreshnessPresentNonce, FreshnessHandle: testHandle}
		if signing != SigningAlgorithmUnspecified {
			resp.SigningAlgorithm = new(signing)
		}
		if encryption != EncryptionAlgorithmUnspecified {
			resp.EncryptionAlgorithm = new(encryption)
		}
		return resp, nil
	}
}

// boundNonce verifies the Evidence under the Attestation Key of the plug-in
// and returns the nonce of the token, which is the binding value.
func boundNonce(t *testing.T, p *sim.Simulated, evidence []byte) []byte {
	t.Helper()
	claims, err := sim.VerifyEvidence(evidence, p.AttestationPublicKey())
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := claims.GetNonce()
	if err != nil {
		t.Fatal(err)
	}
	return nonce
}

// seal is the Secret Vault of the tests: it seals one item to CEKpub of the
// request, under the associated data that the request names.
func seal(t *testing.T, in *caapiv1.RetrieveCredentialRequest, credential []byte, change func(*container.AAD, *container.Content)) []byte {
	t.Helper()
	notExportable := false
	aad := container.AAD{GroupID: "group", Target: container.B64(in.GetTarget()), Handle: in.GetFreshnessElement(), CredentialHint: in.GetCredentialHint()}
	content := container.Content{
		CredentialItems: []container.Item{{
			Type:       "jwt",
			Value:      base64.RawURLEncoding.EncodeToString(credential),
			Purpose:    []string{"authenticate"},
			Algorithm:  "ES256",
			Exportable: &notExportable,
		}},
		Metadata: map[string]any{"validity_seconds": 3600},
	}
	if change != nil {
		change(&aad, &content)
	}
	sealed, err := container.Seal(in.GetCekPub(), aad, content)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(sealed)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestAcquireCredentialRetrieve(t *testing.T) {
	for _, algorithm := range []EncryptionAlgorithm{EncryptionAlgorithmECDHP256, EncryptionAlgorithmMLKEM768P256} {
		t.Run(algorithm.String(), func(t *testing.T) {
			var p *sim.Simulated
			fake := &fakeCAAPI{init: initiation(ModeRetrieve, SigningAlgorithmUnspecified, algorithm)}
			fake.retrieve = func(_ context.Context, in *caapiv1.RetrieveCredentialRequest) (*caapiv1.RetrieveCredentialResponse, error) {
				if in.GetTarget() != testTarget || in.GetCredentialType() != CredentialTypeJWT || in.GetCredentialHint() != "hint" {
					t.Fatalf("request names %q, %v, %q", in.GetTarget(), in.GetCredentialType(), in.GetCredentialHint())
				}
				if in.GetFreshnessKind() != FreshnessPresentNonce || !bytes.Equal(in.GetFreshnessElement(), testHandle) {
					t.Fatal("the request does not carry the Freshness Kind and the Handle as the freshness element")
				}
				if in.GetEvidenceProfile() != sim.MediaTypePSAToken || in.GetEncryptionAlgorithm() != algorithm {
					t.Fatalf("Evidence media type %q, CEK algorithm %v", in.GetEvidenceProfile(), in.GetEncryptionAlgorithm())
				}
				expected := platform.BindingValue(testHandle, testTarget, in.GetCekPub())
				if !bytes.Equal(boundNonce(t, p, in.GetEvidence()), expected[:]) {
					t.Fatal("the Evidence does not bind the Handle, the Target and CEKpub of the request")
				}
				return &caapiv1.RetrieveCredentialResponse{WrappedCredential: seal(t, in, []byte("header.payload.signature"), nil)}, nil
			}
			var c *Client
			c, p = newTestCAI(t, fake)

			cred, err := c.AcquireCredential(context.Background(), testTarget, CredentialTypeJWT, "hint")
			if err != nil {
				t.Fatal(err)
			}
			if cred.Type != CredentialTypeJWT || string(cred.Document) != "header.payload.signature" || cred.PrivateKey != nil {
				t.Fatalf("credential %+v", cred)
			}
		})
	}
}

func TestAcquireCredentialRetrieveRefusals(t *testing.T) {
	exportable := true
	for _, tt := range []struct {
		name      string
		algorithm EncryptionAlgorithm
		answer    func(*testing.T, *caapiv1.RetrieveCredentialRequest) []byte
		expected  error
	}{
		{
			name: "a container for another Target", algorithm: EncryptionAlgorithmECDHP256, expected: ErrUnwrap,
			answer: func(t *testing.T, in *caapiv1.RetrieveCredentialRequest) []byte {
				return seal(t, in, []byte("secret"), func(aad *container.AAD, _ *container.Content) { aad.Target = container.B64("https://other.example") })
			},
		},
		{
			name: "a container for another freshness element", algorithm: EncryptionAlgorithmECDHP256, expected: ErrUnwrap,
			answer: func(t *testing.T, in *caapiv1.RetrieveCredentialRequest) []byte {
				return seal(t, in, []byte("secret"), func(aad *container.AAD, _ *container.Content) { aad.Handle = bytes.Repeat([]byte{0x01}, 32) })
			},
		},
		{
			name: "an item that may leave the TEE", algorithm: EncryptionAlgorithmECDHP256, expected: ErrUnwrap,
			answer: func(t *testing.T, in *caapiv1.RetrieveCredentialRequest) []byte {
				return seal(t, in, []byte("secret"), func(_ *container.AAD, content *container.Content) {
					content.CredentialItems[0].Exportable = &exportable
				})
			},
		},
		{
			name: "a validity longer than the CAI accepts", algorithm: EncryptionAlgorithmECDHP256, expected: ErrUnwrap,
			answer: func(t *testing.T, in *caapiv1.RetrieveCredentialRequest) []byte {
				return seal(t, in, []byte("secret"), func(_ *container.AAD, content *container.Content) {
					content.Metadata["validity_seconds"] = MaxValiditySeconds + 1
				})
			},
		},
		{
			name: "no item", algorithm: EncryptionAlgorithmECDHP256, expected: ErrEmptyCredential,
			answer: func(t *testing.T, in *caapiv1.RetrieveCredentialRequest) []byte {
				return seal(t, in, nil, func(_ *container.AAD, content *container.Content) { content.CredentialItems = nil })
			},
		},
		{
			name: "octets that are no container", algorithm: EncryptionAlgorithmECDHP256, expected: ErrUnwrap,
			answer: func(*testing.T, *caapiv1.RetrieveCredentialRequest) []byte { return []byte("not a container") },
		},
		{
			name: "no container", algorithm: EncryptionAlgorithmECDHP256, expected: ErrEmptyCredential,
			answer: func(*testing.T, *caapiv1.RetrieveCredentialRequest) []byte { return nil },
		},
		{
			name: "an RSA CEK, which opens no hpke-base container", algorithm: EncryptionAlgorithmRSA2048, expected: ErrUnwrap,
			answer: func(*testing.T, *caapiv1.RetrieveCredentialRequest) []byte {
				return []byte(`{"container":"hpke-base"}`)
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fake := &fakeCAAPI{init: initiation(ModeRetrieve, SigningAlgorithmUnspecified, tt.algorithm)}
			fake.retrieve = func(_ context.Context, in *caapiv1.RetrieveCredentialRequest) (*caapiv1.RetrieveCredentialResponse, error) {
				return &caapiv1.RetrieveCredentialResponse{WrappedCredential: tt.answer(t, in)}, nil
			}
			c, _ := newTestCAI(t, fake)
			if _, err := c.AcquireCredential(context.Background(), testTarget, CredentialTypeJWT, ""); !errors.Is(err, tt.expected) {
				t.Fatalf("got %v, expected %v", err, tt.expected)
			}
		})
	}
}

func TestAcquireCredentialEnroll(t *testing.T) {
	for _, tt := range []struct {
		name string
		hint string
	}{
		{name: "with a Credential Hint", hint: "payments"},
		{name: "without a Credential Hint"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var p *sim.Simulated
			var requested *x509.CertificateRequest
			fake := &fakeCAAPI{init: initiation(ModeEnroll, SigningAlgorithmECDSAP256, EncryptionAlgorithmUnspecified)}
			fake.enroll = func(_ context.Context, in *caapiv1.EnrollCredentialRequest) (*caapiv1.EnrollCredentialResponse, error) {
				csr, err := x509.ParseCertificateRequest(in.GetCsr())
				if err != nil {
					t.Fatal(err)
				}
				if err := csr.CheckSignature(); err != nil {
					t.Fatalf("the CSR does not prove possession of its key: %v", err)
				}
				requested = csr
				if in.GetFreshnessKind() != FreshnessPresentNonce || !bytes.Equal(in.GetFreshnessElement(), testHandle) || in.GetEvidenceProfile() != sim.MediaTypePSAToken {
					t.Fatal("the request does not carry the Freshness Kind, the freshness element and the media type of the Evidence")
				}
				if in.GetSigningAlgorithm() != SigningAlgorithmECDSAP256 || in.GetCredentialHint() != tt.hint {
					t.Fatalf("CSK algorithm %v, Credential Hint %q", in.GetSigningAlgorithm(), in.GetCredentialHint())
				}
				expected := platform.BindingValue(testHandle, testTarget, in.GetCsr())
				if !bytes.Equal(boundNonce(t, p, in.GetEvidence()), expected[:]) {
					t.Fatal("the Evidence does not bind the Handle, the Target and the CSR of the request")
				}
				return &caapiv1.EnrollCredentialResponse{PlaintextCredential: []byte("a certificate")}, nil
			}
			var c *Client
			c, p = newTestCAI(t, fake)

			cred, err := c.AcquireCredential(context.Background(), testTarget, CredentialTypeX509, tt.hint)
			if err != nil {
				t.Fatal(err)
			}
			if cred.Type != CredentialTypeX509 || string(cred.Document) != "a certificate" || cred.PrivateKey == nil {
				t.Fatalf("credential %+v", cred)
			}
			// The CSR carries the key of the credential and names nothing but the Credential Hint.
			requestedKey, err := x509.MarshalPKIXPublicKey(requested.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			returnedKey, err := x509.MarshalPKIXPublicKey(cred.PrivateKey.Public())
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(requestedKey, returnedKey) {
				t.Fatal("the CSR does not carry the public key of the CSK that the CAI returned")
			}
			if requested.Subject.CommonName != tt.hint || len(requested.DNSNames)+len(requested.URIs)+len(requested.IPAddresses)+len(requested.EmailAddresses) != 0 {
				t.Fatalf("the CSR names %q and %d alternative names", requested.Subject.CommonName, len(requested.DNSNames)+len(requested.URIs))
			}
		})
	}
}

func TestAcquireCredentialModeAndAlgorithms(t *testing.T) {
	for _, tt := range []struct {
		name       string
		mode       Mode
		signing    SigningAlgorithm
		encryption EncryptionAlgorithm
		expected   error
	}{
		{name: "Retrieval with a CSK algorithm", mode: ModeRetrieve, signing: SigningAlgorithmECDSAP256, encryption: EncryptionAlgorithmECDHP256, expected: ErrUnexpectedSigningAlgorithm},
		{name: "Retrieval without a CEK algorithm", mode: ModeRetrieve, expected: ErrMissingEncryptionAlgorithm},
		{name: "Enrollment with a CEK algorithm", mode: ModeEnroll, signing: SigningAlgorithmECDSAP256, encryption: EncryptionAlgorithmECDHP256, expected: ErrUnexpectedEncryptionAlgorithm},
		{name: "Enrollment without a CSK algorithm", mode: ModeEnroll, expected: ErrMissingSigningAlgorithm},
		{name: "no mode", mode: ModeUnspecified, expected: ErrUnsupportedMode},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := newTestCAI(t, &fakeCAAPI{init: initiation(tt.mode, tt.signing, tt.encryption)})
			if _, err := c.AcquireCredential(context.Background(), testTarget, CredentialTypeX509, ""); !errors.Is(err, tt.expected) {
				t.Fatalf("got %v, expected %v", err, tt.expected)
			}
		})
	}
}

func TestAcquireCredentialValidation(t *testing.T) {
	c, p := newTestCAI(t, &fakeCAAPI{})
	if _, err := c.AcquireCredential(context.Background(), "", CredentialTypeX509, ""); !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("got %v, expected ErrInvalidTarget", err)
	}
	if _, err := c.AcquireCredential(context.Background(), testTarget, CredentialTypeUnspecified, ""); !errors.Is(err, ErrInvalidCredentialType) {
		t.Fatalf("got %v, expected ErrInvalidCredentialType", err)
	}
	var none *Client
	if _, err := none.AcquireCredential(context.Background(), testTarget, CredentialTypeX509, ""); !errors.Is(err, ErrNilClient) {
		t.Fatalf("got %v, expected ErrNilClient", err)
	}
	if _, err := New(nil, &fakeCAAPI{}); !errors.Is(err, ErrNilPlugin) {
		t.Fatalf("got %v, expected ErrNilPlugin", err)
	}
	if _, err := New(p, nil); !errors.Is(err, ErrNilCAAPI) {
		t.Fatalf("got %v, expected ErrNilCAAPI", err)
	}
}

func TestAcquireCredentialCASError(t *testing.T) {
	var hint string
	fake := &fakeCAAPI{init: func(_ context.Context, in *caapiv1.InitiateCredentialAcquistionRequest) (*caapiv1.InitiateCredentialAcquisitionResponse, error) {
		hint = in.GetCredentialHint()
		return nil, status.Error(codes.PermissionDenied, "the Target is not served")
	}}
	c, _ := newTestCAI(t, fake)
	_, err := c.AcquireCredential(context.Background(), testTarget, CredentialTypeX509, "payments")
	var failure *Error
	if !errors.As(err, &failure) || status.Code(err) != codes.PermissionDenied {
		t.Fatalf("got %v, expected a CAAPI error with the code PermissionDenied", err)
	}
	if hint != "payments" {
		t.Fatalf("Initiate-Credential-Acquisition carried the Credential Hint %q", hint)
	}
}

func TestAcquireCredentialFreshness(t *testing.T) {
	for _, tt := range []struct {
		name     string
		kind     FreshnessKind
		handle   []byte
		expected error
		element  func(*sim.Simulated, *caapiv1.RetrieveCredentialRequest) bool
	}{
		{name: "present-nonce", kind: FreshnessPresentNonce, handle: testHandle, element: func(_ *sim.Simulated, in *caapiv1.RetrieveCredentialRequest) bool {
			return bytes.Equal(in.GetFreshnessElement(), testHandle)
		}},
		{name: "present-epoch", kind: FreshnessPresentEpoch, handle: testHandle, element: func(_ *sim.Simulated, in *caapiv1.RetrieveCredentialRequest) bool {
			return bytes.Equal(in.GetFreshnessElement(), testHandle)
		}},
		{name: "absent-epoch", kind: FreshnessAbsentEpoch, element: func(p *sim.Simulated, in *caapiv1.RetrieveCredentialRequest) bool {
			return bytes.Equal(in.GetFreshnessElement(), p.LocalEpoch())
		}},
		{name: "absent-timestamp", kind: FreshnessAbsentTimestamp, element: func(_ *sim.Simulated, in *caapiv1.RetrieveCredentialRequest) bool {
			return len(in.GetFreshnessElement()) == platform.TimestampElementSize
		}},
		{name: "absent-none", kind: FreshnessAbsentNone, element: func(_ *sim.Simulated, in *caapiv1.RetrieveCredentialRequest) bool {
			return len(in.GetFreshnessElement()) == 0
		}},
		{name: "present-nonce without a Handle", kind: FreshnessPresentNonce, expected: ErrInvalidFreshnessHandle},
		{name: "present-nonce with a Handle of 7 octets", kind: FreshnessPresentNonce, handle: make([]byte, 7), expected: ErrInvalidFreshnessHandle},
		{name: "absent-none with a Handle", kind: FreshnessAbsentNone, handle: testHandle, expected: ErrUnexpectedFreshnessHandle},
		{name: "absent-epoch with a Handle", kind: FreshnessAbsentEpoch, handle: testHandle, expected: ErrUnexpectedFreshnessHandle},
		{name: "no Freshness Kind", kind: FreshnessUnspecified, expected: ErrUnsupportedFreshnessKind},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var p *sim.Simulated
			fake := &fakeCAAPI{init: func(context.Context, *caapiv1.InitiateCredentialAcquistionRequest) (*caapiv1.InitiateCredentialAcquisitionResponse, error) {
				return &caapiv1.InitiateCredentialAcquisitionResponse{Mode: ModeRetrieve, FreshnessKind: tt.kind, FreshnessHandle: tt.handle, EncryptionAlgorithm: new(EncryptionAlgorithmECDHP256)}, nil
			}}
			fake.retrieve = func(_ context.Context, in *caapiv1.RetrieveCredentialRequest) (*caapiv1.RetrieveCredentialResponse, error) {
				if in.GetFreshnessKind() != tt.kind || !tt.element(p, in) {
					t.Fatalf("the request carries the Freshness Kind %v and a freshness element of %d octets", in.GetFreshnessKind(), len(in.GetFreshnessElement()))
				}
				expected := platform.BindingValue(in.GetFreshnessElement(), testTarget, in.GetCekPub())
				if !bytes.Equal(boundNonce(t, p, in.GetEvidence()), expected[:]) {
					t.Fatal("the Evidence does not bind the freshness element that the request carries")
				}
				return &caapiv1.RetrieveCredentialResponse{WrappedCredential: seal(t, in, []byte("secret"), nil)}, nil
			}
			var c *Client
			c, p = newTestCAI(t, fake)
			cred, err := c.AcquireCredential(context.Background(), testTarget, CredentialTypeAPIKey, "")
			if tt.expected != nil {
				if !errors.Is(err, tt.expected) {
					t.Fatalf("got %v, expected %v", err, tt.expected)
				}
				return
			}
			if err != nil || string(cred.Document) != "secret" {
				t.Fatalf("credential %+v, %v", cred, err)
			}
		})
	}
}
