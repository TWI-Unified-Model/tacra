// Package sim is the simulated TACRA Platform Plug-In: it runs without
// confidential hardware. Its Evidence is a PSA attestation token, a COSE_Sign1
// that the Attestation Key of the simulated platform signs, with the binding
// value of TACRA as the nonce. A Verifier appraises the token as the token of
// any PSA Root of Trust: the signature under the Attestation Key that the
// operator of the Verifier endorsed for the platform, and the measurement of
// the software against a Reference Value.
//
// The simulated platform protects nothing. Its Attestation Key is an ordinary
// key in memory or in a file, and the measurement is the SHA-256 that the
// plug-in computes of the program that holds it. The plug-in exists to run the
// protocol on a computer without a TEE.
//
// It is a module of its own, so that the hardware back-ends of the platform
// module bring no dependency of the simulator to the Workloads that import
// them.
package sim

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
	"github.com/veraison/psatoken"

	"github.com/TWI-Unified-Model/tacra/platform"
)

// ProfileName is the profile of the PSA attestation token that the simulated
// platform emits.
const ProfileName = psatoken.Profile2Name

// MediaTypePSAToken is the media type of the Evidence of the simulated
// platform.
const MediaTypePSAToken = "application/psa-attestation-token"

// MeasurementType labels the one software component of the token: the program
// that holds the plug-in.
const MeasurementType = "Workload"

// clientID is the PSA Client ID of the caller of the attestation service: a
// positive value, the range of the secure partitions.
const clientID = 1

// componentVersion is the version that the token reports for its software
// component. The simulated platform knows no version of the measured program;
// the measurement alone identifies the program, and the psa-iot scheme of
// Veraison reads the field of every component.
const componentVersion = "0.0.0"

// ErrMeasurement is returned for a measurement that is not a SHA-256 digest.
var ErrMeasurement = errors.New("sim: the measurement must be 32 octets")

// Simulated is the software Platform Plug-In. It does not talk to TDX,
// SEV-SNP or any other hardware ABI.
type Simulated struct {
	attestationKey *ecdsa.PrivateKey // signs the Evidence
	instanceID     []byte            // names the Attestation Key in the token
	signerID       []byte            // the signer of the measured software in the token
	measurement    []byte            // SHA-256 of the measured program
	bootSeed       []byte            // random for each instance of the plug-in
	clock          func() time.Time
}

// Option configures a Simulated plug-in.
type Option func(*Simulated) error

// WithAttestationKey uses the given Attestation Key instead of a new one. The
// operator of a Verifier endorses the public half for the platform, so a
// platform that a Verifier is to appraise keeps its key.
func WithAttestationKey(key *ecdsa.PrivateKey) Option {
	return func(s *Simulated) error {
		if key == nil || key.Curve != elliptic.P256() {
			return errors.New("sim: the Attestation Key must be an ECDSA P-256 private key")
		}
		s.attestationKey = key
		return nil
	}
}

// WithMeasurement sets the measurement that the token reports, 32 octets, in
// place of the SHA-256 of the running program.
func WithMeasurement(measurement []byte) Option {
	return func(s *Simulated) error {
		if len(measurement) != MeasurementSize {
			return ErrMeasurement
		}
		s.measurement = append([]byte(nil), measurement...)
		return nil
	}
}

// WithClock sets the clock used for the absent-timestamp freshness element.
func WithClock(clock func() time.Time) Option {
	return func(s *Simulated) error {
		s.clock = clock
		return nil
	}
}

// NewSimulated constructs the simulated Platform Plug-In.
func NewSimulated(opts ...Option) (*Simulated, error) {
	s := &Simulated{clock: time.Now}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt(s); err != nil {
			return nil, err
		}
	}
	if s.attestationKey == nil {
		pair, err := platform.NewP256KeyPair()
		if err != nil {
			return nil, err
		}
		key, ok := pair.Private.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("sim: the Attestation Key is %T, not an ECDSA P-256 key", pair.Private)
		}
		s.attestationKey = key
	}
	var err error
	if s.instanceID, err = InstanceID(&s.attestationKey.PublicKey); err != nil {
		return nil, err
	}
	if s.signerID, err = SignerID(&s.attestationKey.PublicKey); err != nil {
		return nil, err
	}
	if s.measurement == nil {
		if s.measurement, err = MeasureProgram(); err != nil {
			return nil, err
		}
	}
	if s.bootSeed, err = randomOctets(bootSeedSize); err != nil {
		return nil, err
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
	case platform.EncryptionAlgorithmMLKEM768P256:
		return platform.NewMLKEM768P256KeyPair()
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

// LocalEpoch implements platform.Plugin. The simulated platform uses its boot
// seed as the epoch identifier that it holds.
func (s *Simulated) LocalEpoch() []byte {
	if s == nil || len(s.bootSeed) == 0 {
		return nil
	}
	return append([]byte(nil), s.bootSeed...)
}

// AttestationPublicKey implements platform.Plugin.
func (s *Simulated) AttestationPublicKey() *ecdsa.PublicKey {
	if s == nil || s.attestationKey == nil {
		return nil
	}
	return &s.attestationKey.PublicKey
}

// Measurement returns the measurement that the token reports.
func (s *Simulated) Measurement() []byte {
	return append([]byte(nil), s.measurement...)
}

// GenerateEvidence implements platform.Plugin. The nonce of the token is the
// binding value over the freshness element, the Target and the subject (the
// CSR, or CEKpub). Claims carries, unsigned, what the Relying Party needs to
// recompute the binding value, under the same keys as the hardware back-ends.
func (s *Simulated) GenerateEvidence(req platform.EvidenceRequest) (*platform.Evidence, error) {
	if s == nil || s.attestationKey == nil {
		return nil, platform.ErrNilPlugin
	}
	element, err := platform.FreshnessElement(req, s.clock())
	if err != nil {
		return nil, err
	}
	subject, err := platform.Subject(req)
	if err != nil {
		return nil, err
	}
	bindingValue := platform.BindingValue(element, req.Target, subject)

	token, err := s.sign(bindingValue[:])
	if err != nil {
		return nil, err
	}
	claims, err := cbor.Marshal(map[string]any{
		platform.TSMClaimFreshnessKind:    int32(req.FreshnessKind),
		platform.TSMClaimFreshnessElement: element,
		platform.TSMClaimTarget:           req.Target,
		platform.TSMClaimBindingValue:     bindingValue[:],
	})
	if err != nil {
		return nil, fmt.Errorf("sim: claims CBOR: %w", err)
	}
	return &platform.Evidence{Token: token, MediaType: MediaTypePSAToken, Claims: claims}, nil
}

// sign builds the PSA attestation token with the given nonce and signs it with
// the Attestation Key.
func (s *Simulated) sign(nonce []byte) ([]byte, error) {
	component := &psatoken.SwComponent{}
	if err := component.SetMeasurementType(MeasurementType); err != nil {
		return nil, fmt.Errorf("sim: measurement type: %w", err)
	}
	if err := component.SetMeasurementValue(s.measurement); err != nil {
		return nil, fmt.Errorf("sim: measurement: %w", err)
	}
	if err := component.SetSignerID(s.signerID); err != nil {
		return nil, fmt.Errorf("sim: signer ID: %w", err)
	}
	if err := component.SetVersion(componentVersion); err != nil {
		return nil, fmt.Errorf("sim: version: %w", err)
	}

	claims, err := psatoken.NewClaims(ProfileName)
	if err != nil {
		return nil, fmt.Errorf("sim: profile: %w", err)
	}
	for _, set := range []func() error{
		func() error { return claims.SetClientID(clientID) },
		func() error { return claims.SetSecurityLifeCycle(psatoken.SecurityLifecycleSecuredMin) },
		func() error { return claims.SetImplID(ImplementationID()) },
		func() error { return claims.SetInstID(s.instanceID) },
		func() error { return claims.SetBootSeed(s.bootSeed) },
		func() error { return claims.SetSoftwareComponents([]psatoken.ISwComponent{component}) },
		func() error { return claims.SetNonce(nonce) },
	} {
		if err := set(); err != nil {
			return nil, fmt.Errorf("sim: token claims: %w", err)
		}
	}

	signer, err := cose.NewSigner(cose.AlgorithmES256, s.attestationKey)
	if err != nil {
		return nil, fmt.Errorf("sim: COSE signer: %w", err)
	}
	evidence := psatoken.Evidence{}
	if err := evidence.SetClaims(claims); err != nil {
		return nil, fmt.Errorf("sim: token claims: %w", err)
	}
	token, err := evidence.ValidateAndSign(signer)
	if err != nil {
		return nil, fmt.Errorf("sim: COSE_Sign1: %w", err)
	}
	return token, nil
}
