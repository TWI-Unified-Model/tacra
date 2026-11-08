package platform

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hpke"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

// NewP256KeyPair generates an ECDSA P-256 key pair: a CSK, or a CEK for ECDH.
func NewP256KeyPair() (*KeyPair, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("platform: generate P-256 key: %w", err)
	}
	return &KeyPair{Private: priv}, nil
}

// NewRSA2048KeyPair generates an RSA-2048 key pair: a CSK, or a CEK.
func NewRSA2048KeyPair() (*KeyPair, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("platform: generate RSA-2048 key: %w", err)
	}
	return &KeyPair{Private: priv}, nil
}

// NewMLKEM768P256KeyPair generates a CEK of the hybrid KEM of the hpke-base
// container, MLKEM768-P256.
func NewMLKEM768P256KeyPair() (*KeyPair, error) {
	sk, err := hpke.MLKEM768P256().GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("platform: generate MLKEM768-P256 key: %w", err)
	}
	return &KeyPair{Private: sk}, nil
}
