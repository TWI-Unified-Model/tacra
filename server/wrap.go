package main

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"io"

	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/hkdf"
)

// PoC stand-in for the Credential Vault. Must match cai unwrap
// (tacra/cai/cek-wrap/v1): ephemeral P-256 ECDH, HKDF-SHA256, AES-256-GCM.
const (
	wrapVersion = 1
	wrapInfo    = "tacra/cai/cek-wrap/v1"
	wrapNonce   = 12
	wrapKeyLen  = 32
)

type wrappedV1 struct {
	_          struct{} `cbor:",toarray"`
	Version    uint64
	Ephemeral  []byte
	Nonce      []byte
	Ciphertext []byte
}

func wrapCredential(pub crypto.PublicKey, plaintext []byte) ([]byte, error) {
	if pub == nil {
		return nil, fmt.Errorf("wrap: nil CEK public key")
	}
	peer, err := publicToECDH(pub)
	if err != nil {
		return nil, fmt.Errorf("wrap: %w", err)
	}
	eph, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("wrap: ephemeral key: %w", err)
	}
	secret, err := eph.ECDH(peer)
	if err != nil {
		return nil, fmt.Errorf("wrap: ECDH: %w", err)
	}
	key, err := deriveWrapKey(secret)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("wrap: AES: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("wrap: GCM: %w", err)
	}
	nonce := make([]byte, wrapNonce)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("wrap: nonce: %w", err)
	}
	ephDER, err := x509.MarshalPKIXPublicKey(eph.Public())
	if err != nil {
		return nil, fmt.Errorf("wrap: ephemeral SPKI: %w", err)
	}
	w := wrappedV1{
		Version:    wrapVersion,
		Ephemeral:  ephDER,
		Nonce:      nonce,
		Ciphertext: aead.Seal(nil, nonce, plaintext, nil),
	}
	b, err := cbor.Marshal(w)
	if err != nil {
		return nil, fmt.Errorf("wrap: CBOR: %w", err)
	}
	return b, nil
}

func publicToECDH(pub crypto.PublicKey) (*ecdh.PublicKey, error) {
	switch k := pub.(type) {
	case *ecdh.PublicKey:
		return k, nil
	case *ecdsa.PublicKey:
		return k.ECDH()
	default:
		return nil, fmt.Errorf("key type %T", pub)
	}
}

func deriveWrapKey(secret []byte) ([]byte, error) {
	r := hkdf.New(sha256.New, secret, nil, []byte(wrapInfo))
	key := make([]byte, wrapKeyLen)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("wrap: HKDF: %w", err)
	}
	return key, nil
}
