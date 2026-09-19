package cai

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"io"

	"github.com/fxamacker/cbor/v2"
)

// wrapCredential is a test-only stand-in for the Credential Vault. CAI never
// encrypts; retrieve tests need a matching blob to exercise UnwrapCredential.
func wrapCredential(pub crypto.PublicKey, plaintext []byte) ([]byte, error) {
	if pub == nil {
		return nil, fmt.Errorf("cai: wrap: nil CEK public key")
	}
	peer, err := publicToECDH(pub)
	if err != nil {
		return nil, fmt.Errorf("cai: wrap: %w", err)
	}
	eph, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("cai: wrap: ephemeral key: %w", err)
	}
	secret, err := eph.ECDH(peer)
	if err != nil {
		return nil, fmt.Errorf("cai: wrap: ECDH: %w", err)
	}
	key, err := deriveWrapKey(secret)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("cai: wrap: AES: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cai: wrap: GCM: %w", err)
	}
	nonce := make([]byte, wrapNonce)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("cai: wrap: nonce: %w", err)
	}
	ephDER, err := x509.MarshalPKIXPublicKey(eph.Public())
	if err != nil {
		return nil, fmt.Errorf("cai: wrap: ephemeral SPKI: %w", err)
	}
	w := wrappedV1{
		Version:    wrapVersion,
		Ephemeral:  ephDER,
		Nonce:      nonce,
		Ciphertext: aead.Seal(nil, nonce, plaintext, nil),
	}
	b, err := cbor.Marshal(w)
	if err != nil {
		return nil, fmt.Errorf("cai: wrap: CBOR: %w", err)
	}
	return b, nil
}
