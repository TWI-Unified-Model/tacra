package cai

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"io"

	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/hkdf"
)

const (
	wrapVersion = 1
	wrapInfo    = "tacra/cai/cek-wrap/v1"
	wrapNonce   = 12
	wrapKeyLen  = 32
)

// wrappedV1 is the CBOR encoding of Retrieve-Credential's wrapped_credential.
// CAS encrypts to CEKpub; CAI decrypts with CEKpri.
type wrappedV1 struct {
	_          struct{} `cbor:",toarray"`
	Version    uint64
	Ephemeral  []byte // PKIX SPKI of the ephemeral P-256 public key
	Nonce      []byte
	Ciphertext []byte
}

// UnwrapCredential decrypts a wrapped_credential blob with CEKpri.
func UnwrapCredential(priv crypto.PrivateKey, wrapped []byte) ([]byte, error) {
	if priv == nil {
		return nil, fmt.Errorf("%w: nil CEK private key", ErrUnwrap)
	}
	if len(wrapped) == 0 {
		return nil, fmt.Errorf("%w: empty blob", ErrUnwrap)
	}
	var w wrappedV1
	if err := cbor.Unmarshal(wrapped, &w); err != nil {
		return nil, fmt.Errorf("%w: CBOR: %v", ErrUnwrap, err)
	}
	if w.Version != wrapVersion {
		return nil, fmt.Errorf("%w: unsupported version %d", ErrUnwrap, w.Version)
	}
	if len(w.Nonce) != wrapNonce {
		return nil, fmt.Errorf("%w: bad nonce length", ErrUnwrap)
	}
	ephAny, err := x509.ParsePKIXPublicKey(w.Ephemeral)
	if err != nil {
		return nil, fmt.Errorf("%w: ephemeral key: %v", ErrUnwrap, err)
	}
	ephECDH, err := publicToECDH(ephAny)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnwrap, err)
	}
	cekECDH, err := privateToECDH(priv)
	if err != nil {
		return nil, fmt.Errorf("%w: CEK: %v", ErrUnwrap, err)
	}
	secret, err := cekECDH.ECDH(ephECDH)
	if err != nil {
		return nil, fmt.Errorf("%w: ECDH: %v", ErrUnwrap, err)
	}
	key, err := deriveWrapKey(secret)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnwrap, err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("%w: AES: %v", ErrUnwrap, err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: GCM: %v", ErrUnwrap, err)
	}
	plain, err := aead.Open(nil, w.Nonce, w.Ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: decrypt: %v", ErrUnwrap, err)
	}
	return plain, nil
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

func privateToECDH(priv crypto.PrivateKey) (*ecdh.PrivateKey, error) {
	switch k := priv.(type) {
	case *ecdh.PrivateKey:
		return k, nil
	case *ecdsa.PrivateKey:
		return k.ECDH()
	default:
		return nil, fmt.Errorf("key type %T", priv)
	}
}

func deriveWrapKey(secret []byte) ([]byte, error) {
	r := hkdf.New(sha256.New, secret, nil, []byte(wrapInfo))
	key := make([]byte, wrapKeyLen)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("cai: wrap: HKDF: %w", err)
	}
	return key, nil
}
