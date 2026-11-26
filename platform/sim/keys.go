package sim

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/veraison/psatoken"
)

const (
	// MeasurementSize is the length in octets of the measurement: a SHA-256 digest.
	MeasurementSize = sha256.Size

	bootSeedSize = 32
)

// implementationID names the simulated platform, as the Implementation ID of a
// PSA Root of Trust names its immutable part: the SHA-256 of a fixed label.
var implementationID = sha256.Sum256([]byte("TACRA simulated platform 1"))

// ImplementationID returns the Implementation ID of the simulated platform, 32
// octets, the same for every instance. An Endorsement names the platform by it.
func ImplementationID() []byte {
	return append([]byte(nil), implementationID[:]...)
}

// InstanceID returns the Instance ID that names an Attestation Key in the
// token and in the Endorsement of the key: the octet 0x01 and the SHA-256 of
// the SubjectPublicKeyInfo of the key, 33 octets.
func InstanceID(attestationKey *ecdsa.PublicKey) ([]byte, error) {
	digest, err := keyDigest(attestationKey)
	if err != nil {
		return nil, err
	}
	return append([]byte{0x01}, digest...), nil
}

// SignerID returns the signer of the measured software that the token reports.
// The simulated platform has no signing authority of its own for software, so
// the value comes from the Attestation Key: the first 16 octets of the SHA-256
// of its SubjectPublicKeyInfo, in lowercase hexadecimal. Those 32 octets are
// text, and the JSON template of an Endorsement carries them as they are.
func SignerID(attestationKey *ecdsa.PublicKey) ([]byte, error) {
	digest, err := keyDigest(attestationKey)
	if err != nil {
		return nil, err
	}
	return []byte(hex.EncodeToString(digest[:16])), nil
}

func keyDigest(attestationKey *ecdsa.PublicKey) ([]byte, error) {
	if attestationKey == nil {
		return nil, errors.New("sim: no Attestation Key")
	}
	spki, err := x509.MarshalPKIXPublicKey(attestationKey)
	if err != nil {
		return nil, fmt.Errorf("sim: Attestation Key: %w", err)
	}
	digest := sha256.Sum256(spki)
	return digest[:], nil
}

// MeasureFile returns the measurement of a program: the SHA-256 of its file.
func MeasureFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("sim: measure: %w", err)
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return nil, fmt.Errorf("sim: measure %s: %w", path, err)
	}
	return hash.Sum(nil), nil
}

// MeasureProgram returns the measurement of the running program.
func MeasureProgram() ([]byte, error) {
	path, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("sim: measure: %w", err)
	}
	return MeasureFile(path)
}

// NewAttestationKey generates an Attestation Key for a simulated platform.
func NewAttestationKey() (*ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("sim: generate the Attestation Key: %w", err)
	}
	return key, nil
}

// MarshalAttestationKey encodes an Attestation Key as a PEM block of PKCS #8.
func MarshalAttestationKey(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("sim: Attestation Key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// MarshalAttestationPublicKey encodes the public half of an Attestation Key
// as a PEM block of SubjectPublicKeyInfo: what a party that verifies the
// Evidence of the platform holds.
func MarshalAttestationPublicKey(key *ecdsa.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, fmt.Errorf("sim: public Attestation Key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// ParseAttestationKey decodes an Attestation Key from a PEM block of PKCS #8.
func ParseAttestationKey(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("sim: the Attestation Key is not a PEM block of type PRIVATE KEY")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("sim: Attestation Key: %w", err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, errors.New("sim: the Attestation Key must be an ECDSA P-256 private key")
	}
	return key, nil
}

// ParseEvidence decodes the PSA attestation token without verifying its
// signature.
func ParseEvidence(token []byte) (psatoken.IClaims, error) {
	evidence, err := psatoken.DecodeAndValidateEvidenceFromCOSE(token)
	if err != nil {
		return nil, fmt.Errorf("sim: decode the token: %w", err)
	}
	return evidence.Claims, nil
}

// VerifyEvidence checks the signature of the PSA attestation token with the
// public Attestation Key of the simulated platform and returns the claims.
func VerifyEvidence(token []byte, attestationKey crypto.PublicKey) (psatoken.IClaims, error) {
	evidence, err := psatoken.DecodeAndValidateEvidenceFromCOSE(token)
	if err != nil {
		return nil, fmt.Errorf("sim: decode the token: %w", err)
	}
	if err := evidence.Verify(attestationKey); err != nil {
		return nil, fmt.Errorf("sim: signature of the token: %w", err)
	}
	return evidence.Claims, nil
}

func randomOctets(n int) ([]byte, error) {
	octets := make([]byte, n)
	if _, err := rand.Read(octets); err != nil {
		return nil, fmt.Errorf("sim: random octets: %w", err)
	}
	return octets, nil
}
