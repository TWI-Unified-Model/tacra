// Package sim is the simulated TACRA Platform Plug-In: it runs without
// hardware, generates P-256 keys in process and signs its Evidence, an RFC 9711
// Entity Attestation Token as a tagged COSE_Sign1, with an in-memory
// Attestation Key. It is a module of its own, so that the hardware back-ends
// of the platform module bring no dependency of the simulator to the Workloads
// that import them.
package sim

import (
	"github.com/TWI-Unified-Model/tacra/platform"

	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	_ "crypto/sha256" // SHA-256 for COSE ES256
	"encoding/hex"
	"fmt"
	"time"

	"github.com/veraison/eat"
	"github.com/veraison/go-cose"
)

const (
	defaultIssuer = "tacra-sim"
	defaultSWName = "tacra-sim"
	defaultHW     = "tacra-sim"
)

// Simulated is a software Platform Plug-In for the PoC. It generates P-256
// keys in process and signs platform.Evidence with an in-memory Attestation Key.
// It does not talk to TDX, SEV-SNP, or any other hardware ABI.
type Simulated struct {
	ak       *ecdsa.PrivateKey
	ueid     eat.UEID
	hwModel  []byte
	bootSeed []byte
	issuer   string
	swName   string
}

// SimOption configures a Simulated plug-in.
type SimOption func(*Simulated) error

// WithAttestationKey uses a caller-supplied AK instead of generating one.
func WithAttestationKey(key *ecdsa.PrivateKey) SimOption {
	return func(s *Simulated) error {
		if key == nil || key.Curve != elliptic.P256() {
			return fmt.Errorf("sim: attestation key must be a P-256 ECDSA private key")
		}
		s.ak = key
		return nil
	}
}

// WithUEID sets a pre-provisioned EAT UEID (must pass eat.UEID.Validate).
func WithUEID(ueid []byte) SimOption {
	return func(s *Simulated) error {
		u := eat.UEID(ueid)
		if err := u.Validate(); err != nil {
			return fmt.Errorf("sim: UEID: %w", err)
		}
		s.ueid = u
		return nil
	}
}

// WithHardwareModel sets the EAT hwmodel claim.
func WithHardwareModel(model []byte) SimOption {
	return func(s *Simulated) error {
		if len(model) == 0 {
			return fmt.Errorf("sim: hardware model must not be empty")
		}
		s.hwModel = append([]byte(nil), model...)
		return nil
	}
}

// WithIssuer sets the CWT iss claim.
func WithIssuer(iss string) SimOption {
	return func(s *Simulated) error {
		if iss == "" {
			return fmt.Errorf("sim: issuer must not be empty")
		}
		s.issuer = iss
		return nil
	}
}

// NewSimulated constructs a software-simulated platform plug-in.
func NewSimulated(opts ...SimOption) (*Simulated, error) {
	s := &Simulated{
		hwModel: []byte(defaultHW),
		issuer:  defaultIssuer,
		swName:  defaultSWName,
	}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt(s); err != nil {
			return nil, err
		}
	}
	if s.ak == nil {
		kp, err := platform.NewP256KeyPair()
		if err != nil {
			return nil, err
		}
		priv, ok := kp.Private.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("sim: attestation key is %T, want P-256 ECDSA", kp.Private)
		}
		s.ak = priv
	}
	if len(s.ueid) == 0 {
		ueid, err := generateUEID()
		if err != nil {
			return nil, err
		}
		s.ueid = ueid
	}
	if len(s.bootSeed) == 0 {
		seed, err := generateBootSeed()
		if err != nil {
			return nil, err
		}
		s.bootSeed = seed
	}
	return s, nil
}

// Name implements platform.Plugin.
func (s *Simulated) Name() string { return "simulated" }

// GenerateCEK implements platform.Plugin.
func (s *Simulated) GenerateCEK(alg platform.EncryptionAlgorithm) (*platform.KeyPair, error) {
	switch alg {
	case platform.EncryptionAlgorithmECDHP256:
		return platform.NewP256KeyPair()
	case platform.EncryptionAlgorithmRSA2048:
		return platform.NewRSA2048KeyPair()
	default:
		return nil, fmt.Errorf("%w: %d", platform.ErrUnsupportedEncryptionAlgorithm, alg)
	}
}

// GenerateCSK implements platform.Plugin.
func (s *Simulated) GenerateCSK(alg platform.SigningAlgorithm) (*platform.KeyPair, error) {
	switch alg {
	case platform.SigningAlgorithmUnspecified, platform.SigningAlgorithmECDSAP256:
		return platform.NewP256KeyPair()
	case platform.SigningAlgorithmRSA2048:
		return platform.NewRSA2048KeyPair()
	default:
		return nil, fmt.Errorf("%w: %d", platform.ErrUnsupportedSigningAlgorithm, alg)
	}
}

// LocalEpoch implements platform.Plugin. The simulated platform uses the boot seed
// as a locally held epoch identifier.
func (s *Simulated) LocalEpoch() []byte {
	if s == nil || len(s.bootSeed) == 0 {
		return nil
	}
	return append([]byte(nil), s.bootSeed...)
}

// AttestationPublicKey implements platform.Plugin.
func (s *Simulated) AttestationPublicKey() *ecdsa.PublicKey {
	if s == nil || s.ak == nil {
		return nil
	}
	return &s.ak.PublicKey
}

// AttestationPublicPKIX returns the PKIX encoding of the AK, for CoRIM
// trust-anchor provisioning.
func (s *Simulated) AttestationPublicPKIX() ([]byte, error) {
	pub := s.AttestationPublicKey()
	if pub == nil {
		return nil, platform.ErrNilPlugin
	}
	kp := &platform.KeyPair{Private: s.ak}
	return kp.PublicPKIX()
}

// GenerateEvidence implements platform.Plugin.
func (s *Simulated) GenerateEvidence(req platform.EvidenceRequest) (*platform.Evidence, error) {
	if s == nil || s.ak == nil {
		return nil, platform.ErrNilPlugin
	}
	if err := validateFreshnessHandle(req.FreshnessHandle); err != nil {
		return nil, err
	}
	coseKey, err := encodeCOSEKey(req.BoundKey)
	if err != nil {
		return nil, err
	}

	var nonce *eat.Nonce
	if len(req.FreshnessHandle) > 0 {
		n := eat.Nonce{}
		if err := n.Add(req.FreshnessHandle); err != nil {
			return nil, fmt.Errorf("sim: nonce: %w", err)
		}
		nonce = &n
	}

	profile, err := eat.NewProfile(ProfileURI)
	if err != nil {
		return nil, fmt.Errorf("sim: eat profile: %w", err)
	}

	var sw eat.StringOrURI
	if err := sw.FromString(s.swName); err != nil {
		return nil, fmt.Errorf("sim: software name: %w", err)
	}

	oemBoot := true
	dbg := eat.Debug(eat.DebugDisabledSinceBoot)
	bootCount := uint(1)
	use := platform.ResolveKeyUse(req)

	claims := &Claims{
		Issuer:        s.issuer,
		Subject:       hex.EncodeToString(s.ueid),
		IssuedAt:      time.Now().Unix(),
		Cnf:           &Confirmation{COSEKey: coseKey},
		Nonce:         nonce,
		UEID:          s.ueid,
		HardwareModel: s.hwModel,
		OemBoot:       &oemBoot,
		DebugStatus:   &dbg,
		Profile:       profile,
		BootCount:     &bootCount,
		BootSeed:      s.bootSeed,
		SoftwareName:  &sw,
		CSR:           append([]byte(nil), req.CSR...),
		BoundKeyUse:   use,
	}

	payload, err := encodeClaims(claims)
	if err != nil {
		return nil, fmt.Errorf("sim: encode EAT claims: %w", err)
	}

	token, err := s.signEAT(payload)
	if err != nil {
		return nil, err
	}

	return &platform.Evidence{
		Token:     token,
		MediaType: MediaTypeEATProfile,
		Claims:    payload,
	}, nil
}

func (s *Simulated) signEAT(claims []byte) ([]byte, error) {
	kid := kidFromPublic(&s.ak.PublicKey)
	signer, err := cose.NewSigner(cose.AlgorithmES256, s.ak)
	if err != nil {
		return nil, fmt.Errorf("sim: COSE signer: %w", err)
	}
	headers := cose.Headers{
		Protected: cose.ProtectedHeader{
			cose.HeaderLabelAlgorithm:   cose.AlgorithmES256,
			cose.HeaderLabelContentType: MediaTypeEAT,
		},
		Unprotected: cose.UnprotectedHeader{
			cose.HeaderLabelKeyID: kid,
		},
	}
	token, err := cose.Sign1(rand.Reader, signer, headers, claims, nil)
	if err != nil {
		return nil, fmt.Errorf("sim: COSE_Sign1: %w", err)
	}
	return token, nil
}

func validateFreshnessHandle(h []byte) error {
	if len(h) == 0 {
		return nil
	}
	n := len(h)
	if n < eat.MinNonceSize || n > eat.MaxNonceSize {
		return fmt.Errorf("%w: got %d", platform.ErrInvalidFreshnessHandle, n)
	}
	return nil
}
