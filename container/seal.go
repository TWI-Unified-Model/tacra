package container

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hpke"
	"crypto/x509"
	"errors"
)

// ErrCEKPub is returned when CEKpub is in the encoding of neither suite of the container.
var ErrCEKPub = errors.New("container: CEKpub is neither an MLKEM768-P256 encapsulation key nor the SubjectPublicKeyInfo of a P-256 key")

// publicKeyOf reads CEKpub as the request carries it. The encoding names the
// suite: the encapsulation key of MLKEM768-P256, or the DER
// SubjectPublicKeyInfo of a P-256 key for DHKEM(P-256, HKDF-SHA256).
func publicKeyOf(cekPub []byte) (baseSuite, hpke.PublicKey, error) {
	if pk, err := baseSuites[0].kem.NewPublicKey(cekPub); err == nil {
		return baseSuites[0], pk, nil
	}
	pub, err := x509.ParsePKIXPublicKey(cekPub)
	if err != nil {
		return baseSuite{}, nil, ErrCEKPub
	}
	var e *ecdh.PublicKey
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if k.Curve == elliptic.P256() {
			e, _ = k.ECDH()
		}
	case *ecdh.PublicKey:
		if k.Curve() == ecdh.P256() {
			e = k
		}
	}
	if e == nil {
		return baseSuite{}, nil, ErrCEKPub
	}
	pk, err := hpke.NewDHKEMPublicKey(e)
	if err != nil {
		return baseSuite{}, nil, ErrCEKPub
	}
	return baseSuites[1], pk, nil
}

// SuiteOfCEKPub returns the suite that the encoding of cekPub names.
func SuiteOfCEKPub(cekPub []byte) (Suite, error) {
	s, _, err := publicKeyOf(cekPub)
	if err != nil {
		return Suite{}, err
	}
	return s.suite, nil
}

// Seal seals content to cekPub in HPKE base mode, under the suite that the
// encoding of cekPub names. The associated data is aad, and the freshness
// element is aad.Handle. The container carries no origin member.
func Seal(cekPub []byte, aad AAD, content Content) (*Bundle, error) {
	s, pk, err := publicKeyOf(cekPub)
	if err != nil {
		return nil, err
	}
	kdf, aead := kdfAEAD()
	enc, sender, err := hpke.NewSender(pk, kdf, aead, InfoBase(string(aad.Target), aad.Handle))
	if err != nil {
		return nil, err
	}
	aadBytes, err := Canonical(aad)
	if err != nil {
		return nil, err
	}
	plaintext, err := Canonical(content)
	if err != nil {
		return nil, err
	}
	ciphertext, err := sender.Seal(aadBytes, plaintext)
	if err != nil {
		return nil, err
	}
	return &Bundle{Container: ContainerBase, Suite: s.suite, Enc: enc, Ciphertext: ciphertext, AAD: aad}, nil
}
