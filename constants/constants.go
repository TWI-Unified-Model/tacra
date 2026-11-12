// Package constants holds the names and the bounds that TACRA sets and that
// every implementation shares: the Credential Types, the Freshness Kinds, the
// Credential Acquisition Modes, the RATS models, the bounds of a present-nonce
// Freshness Handle, and the names of the method and of the hash of the
// Binding.
package constants

// CredentialType is a Credential Type of TACRA, by the name that a Credential
// Acquisition Mechanism carries.
type CredentialType string

// The Credential Types of TACRA.
const (
	// CredentialTypeX509 is a PKIX certificate.
	CredentialTypeX509 CredentialType = "x509"
	// CredentialTypeWIC is a WIMSE Workload Identity Certificate.
	CredentialTypeWIC CredentialType = "wic"
	// CredentialTypeWIT is a WIMSE Workload Identity Token.
	CredentialTypeWIT CredentialType = "wit"
	// CredentialTypeJWT is a JSON Web Token used as a bearer token.
	CredentialTypeJWT CredentialType = "jwt"
	// CredentialTypeAPIKey is an API key.
	CredentialTypeAPIKey CredentialType = "api-key"
	// CredentialTypePSK is a pre-shared symmetric key.
	CredentialTypePSK CredentialType = "psk"
)

// CredentialTypes returns the Credential Types of TACRA in a slice that the
// caller owns.
func CredentialTypes() []CredentialType {
	return []CredentialType{
		CredentialTypeX509,
		CredentialTypeWIC,
		CredentialTypeWIT,
		CredentialTypeJWT,
		CredentialTypeAPIKey,
		CredentialTypePSK,
	}
}

// FreshnessKind is a Freshness Kind of TACRA: how the freshness element of a
// credential-acquisition exchange is produced, and by whom.
type FreshnessKind string

// The Freshness Kinds of TACRA.
const (
	// FreshnessKindPresentNonce is the Freshness Kind in which the Freshness
	// Handle is a single-use nonce.
	FreshnessKindPresentNonce FreshnessKind = "present-nonce"
	// FreshnessKindPresentEpoch is the Freshness Kind in which the Freshness
	// Handle is the current epoch marker.
	FreshnessKindPresentEpoch FreshnessKind = "present-epoch"
	// FreshnessKindAbsentTimestamp is the Freshness Kind in which no Freshness
	// Handle is returned and the Attester binds a timestamp from a trusted
	// clock.
	FreshnessKindAbsentTimestamp FreshnessKind = "absent-timestamp"
	// FreshnessKindAbsentEpoch is the Freshness Kind in which no Freshness
	// Handle is returned and the Attester binds an epoch marker that it
	// already holds.
	FreshnessKindAbsentEpoch FreshnessKind = "absent-epoch"
	// FreshnessKindAbsentNone is the Freshness Kind in which no Freshness
	// Handle is returned and the Evidence carries no freshness claim.
	FreshnessKindAbsentNone FreshnessKind = "absent-none"
)

// CredentialAcquisitionMode is a Credential Acquisition Mode of TACRA.
type CredentialAcquisitionMode string

// The Credential Acquisition Modes of TACRA.
const (
	// CredentialAcquisitionModeEnroll is Credential Enrollment: a new
	// proof-of-possession credential is minted.
	CredentialAcquisitionModeEnroll CredentialAcquisitionMode = "enroll"
	// CredentialAcquisitionModeRetrieve is Credential Retrieval: an existing
	// credential of any Credential Type is retrieved.
	CredentialAcquisitionModeRetrieve CredentialAcquisitionMode = "retrieve"
)

// RATSModel is a RATS model of TACRA.
type RATSModel string

// The RATS models of TACRA.
const (
	// RATSModelPassport is the Passport model.
	RATSModelPassport RATSModel = "passport"
	// RATSModelBackgroundCheck is the Background Check model.
	RATSModelBackgroundCheck RATSModel = "background-check"
)

// The bounds of a present-nonce Freshness Handle, in octets. The minimum holds
// the 128 bits of entropy that TACRA requires of such a Handle.
const (
	PresentNonceHandleMinimumOctets = 16
	PresentNonceHandleMaximumOctets = 64
)

// The names of the method and of the hash of the TACRA Binding (Binding
// Credential Keys to Evidence), as a Credential Acquisition Mechanism carries
// them: the freshness input of the Evidence holds SHA-512 of the binding
// input.
const (
	BindingMethod = "binding-input"
	BindingHash   = "sha512"
)
