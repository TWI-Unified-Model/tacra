package platform

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"math/big"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/eat"
	"github.com/veraison/go-cose"
)

// EAT profile URI identifying this PoC's simulated-platform token.
const ProfileURI = "https://twi.confidentialcomputing.io/tacra-sim/1.0.0"

// MediaTypeEAT is the COSE protected-header content type.
const MediaTypeEAT = "application/eat+cwt"

// MediaTypeEATProfile is the type a Veraison-class verifier uses to dispatch
// this token. Matches the eat+cwt; eat_profile=... form used by PSA_IOT.
const MediaTypeEATProfile = `application/eat+cwt; eat_profile="` + ProfileURI + `"`

// Profile-specific CWT claim keys (private use, defined by ProfileURI).
const (
	ClaimCSR         int64 = -70001 // PKCS#10 CSR bytes
	ClaimBoundKeyUse int64 = -70002 // BoundKeyUseEncrypt or BoundKeyUseSign
)

// Claims is the RFC 9711 EAT claims set signed as the COSE_Sign1 payload.
type Claims struct {
	Issuer        string           `cbor:"1,keyasint,omitempty"`
	Subject       string           `cbor:"2,keyasint,omitempty"`
	IssuedAt      int64            `cbor:"6,keyasint,omitempty"`
	Cnf           *Confirmation    `cbor:"8,keyasint,omitempty"`
	Nonce         *eat.Nonce       `cbor:"10,keyasint,omitempty"`
	UEID          eat.UEID         `cbor:"256,keyasint,omitempty"`
	HardwareModel []byte           `cbor:"259,keyasint,omitempty"`
	OemBoot       *bool            `cbor:"262,keyasint,omitempty"`
	DebugStatus   *eat.Debug       `cbor:"263,keyasint,omitempty"`
	Profile       *eat.Profile     `cbor:"265,keyasint,omitempty"`
	BootCount     *uint            `cbor:"267,keyasint,omitempty"`
	BootSeed      []byte           `cbor:"268,keyasint,omitempty"`
	SoftwareName  *eat.StringOrURI `cbor:"270,keyasint,omitempty"`
	CSR           []byte           `cbor:"-70001,keyasint,omitempty"`
	BoundKeyUse   BoundKeyUse      `cbor:"-70002,keyasint,omitempty"`
}

// Confirmation is the CWT cnf claim (RFC 8747): a COSE_Key of the bound
// CEKpub or CSKpub.
type Confirmation struct {
	COSEKey cbor.RawMessage `cbor:"1,keyasint"`
}

// BoundPublicKey decodes the cnf COSE_Key to a Go public key
// (*ecdsa.PublicKey or *rsa.PublicKey).
func (c *Confirmation) BoundPublicKey() (crypto.PublicKey, error) {
	if c == nil || len(c.COSEKey) == 0 {
		return nil, fmt.Errorf("platform: missing cnf COSE_Key")
	}
	var key cose.Key
	if err := key.UnmarshalCBOR(c.COSEKey); err == nil {
		if pub, err := key.PublicKey(); err == nil {
			return pub, nil
		}
	}
	return parseRSACOSEKey(c.COSEKey)
}

// coseRSAKey is RFC 8230: kty=3, n=-1, e=-2.
type coseRSAKey struct {
	Kty int    `cbor:"1,keyasint"`
	N   []byte `cbor:"-1,keyasint"`
	E   []byte `cbor:"-2,keyasint"`
}

func parseRSACOSEKey(raw []byte) (*rsa.PublicKey, error) {
	var k coseRSAKey
	if err := decMode.Unmarshal(raw, &k); err != nil {
		return nil, fmt.Errorf("platform: cnf COSE_Key: %w", err)
	}
	if k.Kty != 3 || len(k.N) == 0 || len(k.E) == 0 {
		return nil, fmt.Errorf("platform: cnf COSE_Key is not ECDSA or RSA")
	}
	e := new(big.Int).SetBytes(k.E)
	if !e.IsInt64() {
		return nil, fmt.Errorf("platform: RSA exponent overflow")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(k.N), E: int(e.Int64())}, nil
}

func encodeCOSEKey(pub crypto.PublicKey) (cbor.RawMessage, error) {
	if pub == nil {
		return nil, ErrMissingBoundKey
	}
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return nil, fmt.Errorf("%w: curve %s", ErrUnsupportedKey, k.Curve.Params().Name)
		}
		key, err := cose.NewKeyFromPublic(k)
		if err != nil {
			return nil, fmt.Errorf("platform: COSE_Key from public key: %w", err)
		}
		b, err := key.MarshalCBOR()
		if err != nil {
			return nil, fmt.Errorf("platform: marshal COSE_Key: %w", err)
		}
		return b, nil
	case *rsa.PublicKey:
		if k.N == nil || k.N.BitLen() < 2048 {
			bits := 0
			if k.N != nil {
				bits = k.N.BitLen()
			}
			return nil, fmt.Errorf("%w: RSA %d bits", ErrUnsupportedKey, bits)
		}
		b, err := encMode.Marshal(coseRSAKey{
			Kty: 3,
			N:   k.N.Bytes(),
			E:   big.NewInt(int64(k.E)).Bytes(),
		})
		if err != nil {
			return nil, fmt.Errorf("platform: marshal RSA COSE_Key: %w", err)
		}
		return b, nil
	default:
		return nil, fmt.Errorf("%w: %T", ErrUnsupportedKey, pub)
	}
}
