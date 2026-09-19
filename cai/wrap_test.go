package cai

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"io"

	"github.com/fxamacker/cbor/v2"
)

// wrapCEK encrypts to a CEKpub from Evidence. COSE decodes P-256 as
// *ecdsa.PublicKey; wrapCredential itself only accepts RSA or ECDH.
func wrapCEK(pub crypto.PublicKey, plaintext []byte) ([]byte, error) {
	if _, ok := pub.(*rsa.PublicKey); !ok {
		var err error
		pub, err = publicToECDH(pub)
		if err != nil {
			return nil, err
		}
	}
	return wrapCredential(pub, plaintext)
}

// wrapCredential is a test-only stand-in for the Credential Vault. CAI never
// encrypts; retrieve tests need a matching blob to exercise UnwrapCredential.
func wrapCredential(pub crypto.PublicKey, plaintext []byte) ([]byte, error) {
	if pub == nil {
		return nil, fmt.Errorf("cai: wrap: nil CEK public key")
	}
	key := make([]byte, wrapKeyLen)
	var version uint64
	var material []byte
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			return nil, fmt.Errorf("cai: wrap: AES key: %w", err)
		}
		enc, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, k, key, []byte(wrapInfo))
		if err != nil {
			return nil, fmt.Errorf("cai: wrap: RSA-OAEP: %w", err)
		}
		version = wrapVersionRSA
		material = enc
	case *ecdh.PublicKey:
		eph, err := ecdh.P256().GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("cai: wrap: ephemeral key: %w", err)
		}
		secret, err := eph.ECDH(k)
		if err != nil {
			return nil, fmt.Errorf("cai: wrap: ECDH: %w", err)
		}
		key, err = deriveWrapKey(secret)
		if err != nil {
			return nil, err
		}
		ephDER, err := x509.MarshalPKIXPublicKey(eph.Public())
		if err != nil {
			return nil, fmt.Errorf("cai: wrap: ephemeral SPKI: %w", err)
		}
		version = wrapVersionECDH
		material = ephDER
	default:
		return nil, fmt.Errorf("cai: wrap: CEK public key is %T, want RSA or P-256 ECDH", pub)
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
	w := wrappedV1{
		Version:    version,
		Ephemeral:  material,
		Nonce:      nonce,
		Ciphertext: aead.Seal(nil, nonce, plaintext, nil),
	}
	b, err := cbor.Marshal(w)
	if err != nil {
		return nil, fmt.Errorf("cai: wrap: CBOR: %w", err)
	}
	return b, nil
}
