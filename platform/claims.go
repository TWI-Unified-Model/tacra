package platform

import (
	"crypto/ecdsa"
	"fmt"

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

// BoundPublicKey decodes the cnf COSE_Key to a Go public key.
func (c *Confirmation) BoundPublicKey() (*ecdsa.PublicKey, error) {
	if c == nil || len(c.COSEKey) == 0 {
		return nil, fmt.Errorf("platform: missing cnf COSE_Key")
	}
	var key cose.Key
	if err := key.UnmarshalCBOR(c.COSEKey); err != nil {
		return nil, fmt.Errorf("platform: decode cnf COSE_Key: %w", err)
	}
	pub, err := key.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("platform: cnf COSE_Key to public key: %w", err)
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("platform: cnf COSE_Key is %T, want *ecdsa.PublicKey", pub)
	}
	return ec, nil
}

func encodeCOSEKey(pub *ecdsa.PublicKey) (cbor.RawMessage, error) {
	key, err := cose.NewKeyFromPublic(pub)
	if err != nil {
		return nil, fmt.Errorf("platform: COSE_Key from public key: %w", err)
	}
	b, err := key.MarshalCBOR()
	if err != nil {
		return nil, fmt.Errorf("platform: marshal COSE_Key: %w", err)
	}
	return b, nil
}
