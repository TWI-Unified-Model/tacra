package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
)

const minRSABits = 2048

// jsonWebKey is the subset of RFC 7517 / RFC 8037 public-key members the RUP uses.
type jsonWebKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid,omitempty"`
	Use string `json:"use,omitempty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
}

type publicKey struct {
	kid string
	key crypto.PublicKey
}

func loadJWKS(files []string) ([]publicKey, error) {
	var keys []publicKey
	for _, file := range files {
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("rup: JWKS: %w", err)
		}
		var set struct {
			Keys []jsonWebKey `json:"keys"`
		}
		if err := json.Unmarshal(b, &set); err != nil {
			return nil, fmt.Errorf("rup: JWKS %s: %w", file, err)
		}
		for i, k := range set.Keys {
			if k.Use != "" && k.Use != "sig" {
				continue
			}
			pub, err := k.publicKey()
			if err != nil {
				return nil, fmt.Errorf("rup: JWKS %s key %d: %w", file, i, err)
			}
			keys = append(keys, publicKey{kid: k.Kid, key: pub})
		}
	}
	return keys, nil
}

func parseJWK(m map[string]any) (crypto.PublicKey, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	var k jsonWebKey
	if err := json.Unmarshal(b, &k); err != nil {
		return nil, err
	}
	return k.publicKey()
}

func (k jsonWebKey) publicKey() (crypto.PublicKey, error) {
	switch k.Kty {
	case "EC":
		var curve elliptic.Curve
		switch k.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported EC curve %q", k.Crv)
		}
		size := (curve.Params().BitSize + 7) / 8
		x, err := b64Fixed(k.X, size)
		if err != nil {
			return nil, fmt.Errorf("EC x: %w", err)
		}
		y, err := b64Fixed(k.Y, size)
		if err != nil {
			return nil, fmt.Errorf("EC y: %w", err)
		}
		point := append(append([]byte{0x04}, x...), y...)
		return ecdsa.ParseUncompressedPublicKey(curve, point)
	case "OKP":
		if k.Crv != "Ed25519" {
			return nil, fmt.Errorf("unsupported OKP curve %q", k.Crv)
		}
		x, err := b64Fixed(k.X, ed25519.PublicKeySize)
		if err != nil {
			return nil, fmt.Errorf("OKP x: %w", err)
		}
		return ed25519.PublicKey(x), nil
	case "RSA":
		n, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil || len(n) == 0 {
			return nil, errors.New("invalid RSA modulus")
		}
		e, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil || len(e) == 0 || len(e) > 4 {
			return nil, errors.New("invalid RSA exponent")
		}
		pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
		if pub.N.BitLen() < minRSABits {
			return nil, fmt.Errorf("RSA key smaller than %d bits", minRSABits)
		}
		return pub, nil
	default:
		return nil, fmt.Errorf("unsupported key type %q", k.Kty)
	}
}

func b64Fixed(s string, size int) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != size {
		return nil, fmt.Errorf("want %d octets, got %d", size, len(b))
	}
	return b, nil
}
