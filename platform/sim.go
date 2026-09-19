package platform

import (
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
// keys in process and signs Evidence with an in-memory Attestation Key.
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
			return fmt.Errorf("platform: attestation key must be a P-256 ECDSA private key")
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
			return fmt.Errorf("platform: UEID: %w", err)
		}
		s.ueid = u
		return nil
	}
}

// WithHardwareModel sets the EAT hwmodel claim.
func WithHardwareModel(model []byte) SimOption {
	return func(s *Simulated) error {
		if len(model) == 0 {
			return fmt.Errorf("platform: hardware model must not be empty")
		}
		s.hwModel = append([]byte(nil), model...)
		return nil
	}
}

// WithIssuer sets the CWT iss claim.
func WithIssuer(iss string) SimOption {
	return func(s *Simulated) error {
		if iss == "" {
			return fmt.Errorf("platform: issuer must not be empty")
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
		kp, err := generateP256()
		if err != nil {
			return nil, err
		}
		priv, ok := kp.Private.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("platform: attestation key is %T, want P-256 ECDSA", kp.Private)
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

// Name implements Plugin.
func (s *Simulated) Name() string { return "simulated" }

// GenerateCEK implements Plugin.
func (s *Simulated) GenerateCEK(alg EncryptionAlgorithm) (*KeyPair, error) {
	switch alg {
	case EncryptionAlgorithmECDHP256:
		return generateP256()
	case EncryptionAlgorithmRSA2048:
		return generateRSA2048()
	default:
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedEncryptionAlgorithm, alg)
	}
}

// GenerateCSK implements Plugin.
func (s *Simulated) GenerateCSK(alg SigningAlgorithm) (*KeyPair, error) {
	switch alg {
	case SigningAlgorithmUnspecified, SigningAlgorithmECDSAP256:
		return generateP256()
	case SigningAlgorithmRSA2048:
		return generateRSA2048()
	default:
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedSigningAlgorithm, alg)
	}
}

// LocalEpoch implements Plugin. The simulated platform uses the boot seed
// as a locally held epoch identifier.
func (s *Simulated) LocalEpoch() []byte {
	if s == nil || len(s.bootSeed) == 0 {
		return nil
	}
	return append([]byte(nil), s.bootSeed...)
}

// AttestationPublicKey implements Plugin.
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
		return nil, ErrNilPlugin
	}
	kp := &KeyPair{Private: s.ak}
	return kp.PublicPKIX()
}

// GenerateEvidence implements Plugin.
func (s *Simulated) GenerateEvidence(req EvidenceRequest) (*Evidence, error) {
	if s == nil || s.ak == nil {
		return nil, ErrNilPlugin
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
			return nil, fmt.Errorf("platform: nonce: %w", err)
		}
		nonce = &n
	}

	profile, err := eat.NewProfile(ProfileURI)
	if err != nil {
		return nil, fmt.Errorf("platform: eat profile: %w", err)
	}

	var sw eat.StringOrURI
	if err := sw.FromString(s.swName); err != nil {
		return nil, fmt.Errorf("platform: software name: %w", err)
	}

	oemBoot := true
	dbg := eat.Debug(eat.DebugDisabledSinceBoot)
	bootCount := uint(1)
	use := resolveKeyUse(req)

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
		return nil, fmt.Errorf("platform: encode EAT claims: %w", err)
	}

	token, err := s.signEAT(payload)
	if err != nil {
		return nil, err
	}

	return &Evidence{
		Token:     token,
		MediaType: MediaTypeEATProfile,
		Claims:    payload,
	}, nil
}

func (s *Simulated) signEAT(claims []byte) ([]byte, error) {
	kid := kidFromPublic(&s.ak.PublicKey)
	signer, err := cose.NewSigner(cose.AlgorithmES256, s.ak)
	if err != nil {
		return nil, fmt.Errorf("platform: COSE signer: %w", err)
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
		return nil, fmt.Errorf("platform: COSE_Sign1: %w", err)
	}
	return token, nil
}

func validateFreshnessHandle(h []byte) error {
	if len(h) == 0 {
		return nil
	}
	n := len(h)
	if n < eat.MinNonceSize || n > eat.MaxNonceSize {
		return fmt.Errorf("%w: got %d", ErrInvalidFreshnessHandle, n)
	}
	return nil
}
