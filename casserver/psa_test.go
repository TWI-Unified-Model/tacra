package casserver

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const psaTokenMediaType = "application/psa-attestation-token"

var (
	psaImplementationID = bytes.Repeat([]byte{0x1d}, 32)
	psaMeasurement      = bytes.Repeat([]byte{0x3e}, 32)
)

// psaAnnotated is what the psa-iot scheme of Veraison annotates: the claims of
// the PSA attestation token as JSON, byte strings in base64.
func psaAnnotated(measurements ...[]byte) map[string]any {
	components := make([]any, 0, len(measurements))
	for _, m := range measurements {
		components = append(components, map[string]any{
			"measurement-type":  "Workload",
			"measurement-value": base64.StdEncoding.EncodeToString(m),
			"signer-id":         base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x51}, 32)),
			"version":           "0.0.0",
		})
	}
	return map[string]any{
		"eat-profile":             "http://arm.com/psa/2.0.0",
		"psa-implementation-id":   base64.StdEncoding.EncodeToString(psaImplementationID),
		"psa-security-lifecycle":  12288,
		"psa-software-components": components,
	}
}

func TestRouteByMediaType(t *testing.T) {
	f := newMockVerifier(t)
	verifiers := newTestVerifiers(f, nil, resultsWindow{})
	verifiers["psa"] = &veraisonVerifier{name: "psa", mediaTypes: []string{psaTokenMediaType}, submods: []string{"PSA_IOT"}}
	token := []byte{0xd2, 0x84} // the first octets of a COSE_Sign1: no TSM report, no provider

	t.Run("the Verifier that lists the media type of the Evidence", func(t *testing.T) {
		v, err := route(verifiers, token, psaTokenMediaType, []string{"veraison", "psa"})
		require.NoError(t, err)
		require.Equal(t, "psa", v.Name())
	})
	t.Run("a Verifier the policy does not name receives nothing", func(t *testing.T) {
		_, err := route(verifiers, token, psaTokenMediaType, []string{"veraison", "tdx"})
		require.ErrorIs(t, err, ErrNoVerifier)
	})
	t.Run("Evidence of a media type no Verifier lists has no Verifier", func(t *testing.T) {
		_, err := route(verifiers, token, "application/other", []string{"veraison", "psa"})
		require.ErrorIs(t, err, ErrNoVerifier)
	})
	t.Run("Evidence in a TSM report is still routed by its provider", func(t *testing.T) {
		v, err := route(verifiers, testEvidence(t, "sev_guest"), "application/vnd.veraison.tsm-report+cbor", []string{"veraison", "psa"})
		require.NoError(t, err)
		require.Equal(t, "veraison", v.Name())
	})
}

func TestVeraisonVerifyPSA(t *testing.T) {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	key := newTestKey(t)
	nonce := bytes.Repeat([]byte{0x42}, 64)
	window := resultsWindow{maxAge: 2 * time.Minute, skew: 5 * time.Second, now: func() time.Time { return now }}
	v := &veraisonVerifier{name: "psa", key: &key.PublicKey, mediaTypes: []string{psaTokenMediaType}, submods: []string{"PSA_IOT"}, window: window}

	t.Run("affirming results give the measurement of the software component", func(t *testing.T) {
		res, err := v.Verify(signEAR(t, key, nonce, now, "PSA_IOT", "affirming", psaAnnotated(psaMeasurement)), nonce)
		require.NoError(t, err)
		require.Equal(t, familyPSA, res.Family)
		require.Equal(t, psaMeasurement, res.Measurement)
		require.NotNil(t, res.PSA)
		require.Equal(t, psaImplementationID, res.PSA.implementationID)
	})
	t.Run("results that are not affirming are refused", func(t *testing.T) {
		_, err := v.Verify(signEAR(t, key, nonce, now, "PSA_IOT", "warning", psaAnnotated(psaMeasurement)), nonce)
		require.ErrorIs(t, err, ErrEARNotAffirming)
	})
	t.Run("a token with two software components has no single measurement", func(t *testing.T) {
		res, err := v.Verify(signEAR(t, key, nonce, now, "PSA_IOT", "affirming", psaAnnotated(psaMeasurement, psaMeasurement)), nonce)
		require.NoError(t, err)
		require.Nil(t, res.PSA)
		require.ErrorIs(t, res.PSAErr, ErrPSAClaims)
		require.Empty(t, res.Measurement)
	})
	t.Run("the kind accepts the submodule in its configuration", func(t *testing.T) {
		require.NoError(t, veraisonKind{}.Validate(&VerifierConfig{URL: "https://verifier.example", EARKeyPath: "key", Submods: []string{"PSA_IOT"}, EvidenceMediaTypes: []string{psaTokenMediaType}}))
	})
}

func TestPlatformRulePSA(t *testing.T) {
	entry := func(ids ...string) json.RawMessage {
		raw, err := json.Marshal(map[string]any{"implementation_ids": ids})
		require.NoError(t, err)
		return raw
	}
	rule, err := psaModule{}.ParseRule(entry(hex.EncodeToString(psaImplementationID)))
	require.NoError(t, err)

	t.Run("a platform whose Implementation ID the rule lists is admitted", func(t *testing.T) {
		waived, err := rule.Check(&attestationResults{Family: familyPSA, PSA: &psaClaims{implementationID: psaImplementationID, measurement: psaMeasurement}})
		require.NoError(t, err)
		require.Empty(t, waived)
	})
	t.Run("another Implementation ID is refused", func(t *testing.T) {
		_, err := rule.Check(&attestationResults{Family: familyPSA, PSA: &psaClaims{implementationID: bytes.Repeat([]byte{0x99}, 32)}})
		require.ErrorIs(t, err, ErrPlatform)
	})
	t.Run("results without readable claims are refused", func(t *testing.T) {
		_, err := rule.Check(&attestationResults{Family: familyPSA, PSAErr: ErrPSAClaims})
		require.ErrorIs(t, err, ErrPlatform)
		require.ErrorIs(t, err, ErrPSAClaims)
	})
	t.Run("an entry without Implementation IDs, or with one that is not hex, is refused", func(t *testing.T) {
		_, err := psaModule{}.ParseRule(entry())
		require.ErrorContains(t, err, "implementation_ids is required")
		_, err = psaModule{}.ParseRule(entry("not hex"))
		require.ErrorContains(t, err, "is not hex")
		_, err = psaModule{}.ParseRule(json.RawMessage(`{"unknown": 1}`))
		require.Error(t, err)
	})
}
