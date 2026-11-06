package sim

import (
	"github.com/TWI-Unified-Model/tacra/platform"

	"crypto"
	_ "crypto/sha256" // SHA-256 for COSE ES256
	"fmt"

	"github.com/veraison/go-cose"
)

func unmarshalSign1(token []byte) (*cose.Sign1Message, error) {
	if len(token) == 0 {
		return nil, fmt.Errorf("sim: empty evidence token")
	}
	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(token); err != nil {
		return nil, fmt.Errorf("sim: decode COSE_Sign1: %w", err)
	}
	return &msg, nil
}

// ParseEvidence decodes a CBOR COSE_Sign1 EAT without verifying the signature.
func ParseEvidence(token []byte) (*Claims, error) {
	msg, err := unmarshalSign1(token)
	if err != nil {
		return nil, err
	}
	claims, err := decodeClaims(msg.Payload)
	if err != nil {
		return nil, fmt.Errorf("sim: decode EAT claims: %w", err)
	}
	return claims, nil
}

// VerifyEvidence checks the COSE_Sign1 signature with ak and returns the claims.
func VerifyEvidence(token []byte, ak crypto.PublicKey) (*Claims, error) {
	msg, err := unmarshalSign1(token)
	if err != nil {
		return nil, err
	}
	verifier, err := cose.NewVerifier(cose.AlgorithmES256, ak)
	if err != nil {
		return nil, fmt.Errorf("sim: COSE verifier: %w", err)
	}
	if err := msg.Verify(nil, verifier); err != nil {
		return nil, fmt.Errorf("sim: evidence signature: %w", err)
	}
	claims, err := decodeClaims(msg.Payload)
	if err != nil {
		return nil, fmt.Errorf("sim: decode EAT claims: %w", err)
	}
	return claims, nil
}

// Verify verifies the Token of the Evidence with ak and returns the claims.
func Verify(e *platform.Evidence, ak crypto.PublicKey) (*Claims, error) {
	if e == nil {
		return nil, fmt.Errorf("sim: nil evidence")
	}
	return VerifyEvidence(e.Token, ak)
}
