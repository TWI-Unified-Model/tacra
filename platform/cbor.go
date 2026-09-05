package platform

import "github.com/fxamacker/cbor/v2"

// Canonical CBOR matching github.com/veraison/eat so Veraison can decode
// the claims map with eat.Eat.FromCBOR.
var (
	encMode cbor.EncMode
	decMode cbor.DecMode
)

func init() {
	em, err := cbor.EncOptions{
		Sort:          cbor.SortCanonical,
		IndefLength:   cbor.IndefLengthForbidden,
		TimeTag:       cbor.EncTagRequired,
		ShortestFloat: cbor.ShortestFloat16,
	}.EncMode()
	if err != nil {
		panic(err)
	}
	dm, err := cbor.DecOptions{
		IndefLength: cbor.IndefLengthForbidden,
	}.DecMode()
	if err != nil {
		panic(err)
	}
	encMode = em
	decMode = dm
}

func encodeClaims(c *Claims) ([]byte, error) {
	return encMode.Marshal(c)
}

func decodeClaims(b []byte) (*Claims, error) {
	var c Claims
	if err := decMode.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	return &c, nil
}
