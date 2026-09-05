package cai

import (
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

const (
	wrapVersion = 1
	wrapInfo    = "twium/cai/cek-wrap/v1"
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

// WrapCredential encrypts plaintext to pub (CEKpub) using ephemeral P-256 ECDH,
// HKDF-SHA256, and AES-256-GCM. The result is the CAAPI wrapped_credential blob.
func WrapCredential(pub *ecdsa.PublicKey, plaintext []byte) ([]byte, error) {
	if pub == nil {
		return nil, fmt.Errorf("cai: wrap: nil CEK public key")
	}
	peer, err := pub.ECDH()
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

// UnwrapCredential decrypts a wrapped_credential blob with CEKpri.
func UnwrapCredential(priv *ecdsa.PrivateKey, wrapped []byte) ([]byte, error) {
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
	cekECDH, err := priv.ECDH()
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

func publicToECDH(pub any) (*ecdh.PublicKey, error) {
	switch k := pub.(type) {
	case *ecdh.PublicKey:
		return k, nil
	case *ecdsa.PublicKey:
		return k.ECDH()
	default:
		return nil, fmt.Errorf("ephemeral key type %T", pub)
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
