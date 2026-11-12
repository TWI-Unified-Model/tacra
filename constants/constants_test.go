package constants_test

import (
	"slices"
	"testing"

	"github.com/TWI-Unified-Model/tacra/constants"
)

// TestNames pins every name that a Credential Acquisition Mechanism carries: a
// change of one of them changes what every implementation sends and accepts.
func TestNames(t *testing.T) {
	names := []struct {
		name     string
		expected string
	}{
		{string(constants.CredentialTypeX509), "x509"},
		{string(constants.CredentialTypeWIC), "wic"},
		{string(constants.CredentialTypeWIT), "wit"},
		{string(constants.CredentialTypeJWT), "jwt"},
		{string(constants.CredentialTypeAPIKey), "api-key"},
		{string(constants.CredentialTypePSK), "psk"},
		{string(constants.CredentialTypePrivateKey), "private-key"},
		{string(constants.FreshnessKindPresentNonce), "present-nonce"},
		{string(constants.FreshnessKindPresentEpoch), "present-epoch"},
		{string(constants.FreshnessKindAbsentTimestamp), "absent-timestamp"},
		{string(constants.FreshnessKindAbsentEpoch), "absent-epoch"},
		{string(constants.FreshnessKindAbsentNone), "absent-none"},
		{string(constants.CredentialAcquisitionModeEnroll), "enroll"},
		{string(constants.CredentialAcquisitionModeRetrieve), "retrieve"},
		{string(constants.RATSModelPassport), "passport"},
		{string(constants.RATSModelBackgroundCheck), "background-check"},
		{constants.BindingMethod, "binding-input"},
		{constants.BindingHash, "sha512"},
	}
	for _, entry := range names {
		if entry.name != entry.expected {
			t.Errorf("the name %q differs from the expected %q", entry.name, entry.expected)
		}
	}
}

// TestCredentialTypes checks that the list holds every Credential Type once,
// and that a caller who changes its slice does not change the next one.
func TestCredentialTypes(t *testing.T) {
	expected := []constants.CredentialType{
		constants.CredentialTypeX509,
		constants.CredentialTypeWIC,
		constants.CredentialTypeWIT,
		constants.CredentialTypeJWT,
		constants.CredentialTypeAPIKey,
		constants.CredentialTypePSK,
		constants.CredentialTypePrivateKey,
	}
	credentialTypes := constants.CredentialTypes()
	if !slices.Equal(credentialTypes, expected) {
		t.Fatalf("the Credential Types are %v, expected %v", credentialTypes, expected)
	}
	credentialTypes[0] = "changed"
	if next := constants.CredentialTypes(); !slices.Equal(next, expected) {
		t.Errorf("a change of a returned slice reached the next call: %v", next)
	}
}

// TestPresentNonceHandleBounds checks that the minimum holds the 128 bits of
// entropy that TACRA requires, and that it does not exceed the maximum.
func TestPresentNonceHandleBounds(t *testing.T) {
	minimum, maximum := constants.PresentNonceHandleMinimumOctets, constants.PresentNonceHandleMaximumOctets
	if bits := minimum * 8; bits < 128 {
		t.Errorf("the minimum holds %d bits, fewer than 128", bits)
	}
	if minimum > maximum {
		t.Errorf("the minimum of %d octets exceeds the maximum of %d octets", minimum, maximum)
	}
}
