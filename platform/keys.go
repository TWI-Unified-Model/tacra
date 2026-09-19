package platform

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"

	"github.com/veraison/eat"
)

const (
	ueidRANDLen = 32 // EAT RAND UEID payload: 16, 24, or 32 bytes
	bootSeedLen = 32
)

func generateP256() (*KeyPair, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("platform: generate P-256 key: %w", err)
	}
	return &KeyPair{Private: priv}, nil
}

func generateRSA2048() (*KeyPair, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("platform: generate RSA-2048 key: %w", err)
	}
	return &KeyPair{Private: priv}, nil
}

func generateUEID() (eat.UEID, error) {
	payload := make([]byte, ueidRANDLen)
	if _, err := rand.Read(payload); err != nil {
		return nil, fmt.Errorf("platform: UEID: %w", err)
	}
	ueid := make(eat.UEID, 1+ueidRANDLen)
	ueid[0] = eat.UEIDTypeRAND
	copy(ueid[1:], payload)
	if err := ueid.Validate(); err != nil {
		return nil, fmt.Errorf("platform: UEID: %w", err)
	}
	return ueid, nil
}

func generateBootSeed() ([]byte, error) {
	seed := make([]byte, bootSeedLen)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("platform: boot seed: %w", err)
	}
	return seed, nil
}

func kidFromPublic(pub *ecdsa.PublicKey) []byte {
	pkix, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil
	}
	sum := sha256.Sum256(pkix)
	return sum[:8]
}
