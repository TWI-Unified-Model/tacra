package platform

import (
	"crypto/sha512"
	"encoding/binary"
)

// BindingInput is the octet string of the TACRA section "Binding Credential
// Keys to Evidence", which the EST profile (draft-novak-lamps-tacra-est,
// "Binding Input") also uses: each value preceded by its length as a 32-bit
// big-endian integer, the Target before the Relying Party identifier.
//
//	binding_input = len32(handle) || handle || len32(target) || target
//	             || len32(rrp_id) || rrp_id || len32(subject) || subject
//
// handle is the freshness element (the Freshness Handle, the epoch marker or
// the 8-octet timestamp; empty only for absent-none), target the Target,
// rrp_id the RATS Relying Party identifier, and subject the DER CSR
// (Enrollment) or the DER SubjectPublicKeyInfo of CEKpub (Retrieval).
func BindingInput(handle []byte, target, rrpID string, subject []byte) []byte {
	var out []byte
	for _, v := range [][]byte{handle, []byte(target), []byte(rrpID), subject} {
		out = binary.BigEndian.AppendUint32(out, uint32(len(v)))
		out = append(out, v...)
	}
	return out
}

// BindingValue is SHA-512 of BindingInput: the 64 octets a hardware back-end
// writes into its guest-chosen report field (REPORT_DATA on AMD SEV-SNP).
func BindingValue(handle []byte, target, rrpID string, subject []byte) [sha512.Size]byte {
	return sha512.Sum512(BindingInput(handle, target, rrpID, subject))
}

// TimestampElementSize is the length in octets of the absent-timestamp freshness
// element.
const TimestampElementSize = 8

// TimestampElement is the absent-timestamp freshness element: seconds since
// 1970-01-01T00:00:00Z as an 8-octet big-endian unsigned integer.
func TimestampElement(unixSeconds int64) []byte {
	return binary.BigEndian.AppendUint64(nil, uint64(unixSeconds))
}
