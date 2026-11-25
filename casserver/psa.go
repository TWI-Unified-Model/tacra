package casserver

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// psaClaims is what the Server reads from the claims of a PSA attestation
// token, as the Verifier annotates them in its Attestation Results: the
// Implementation ID, which names the platform, and the measurement of its
// software.
type psaClaims struct {
	implementationID []byte
	measurement      []byte
}

// ErrPSAClaims is returned when the Attestation Results of a PSA platform do
// not carry the claims the Server reads.
var ErrPSAClaims = errors.New("the Attestation Results carry no readable claims of the PSA attestation token")

// parsePSAClaims reads the claims of the PSA attestation token. The token of
// the platform must report one software component: its measurement is the
// launch measurement that the policy for a Target admits. A token with several
// components has no single measurement, and this Server refuses it.
func parsePSAClaims(annotated json.RawMessage) (*psaClaims, error) {
	var claims struct {
		ImplementationID string `json:"psa-implementation-id"`
		Components       []struct {
			Measurement string `json:"measurement-value"`
		} `json:"psa-software-components"`
	}
	if err := json.Unmarshal(annotated, &claims); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPSAClaims, err)
	}
	implementationID, err := base64.StdEncoding.DecodeString(claims.ImplementationID)
	if err != nil || len(implementationID) == 0 {
		return nil, fmt.Errorf("%w: psa-implementation-id", ErrPSAClaims)
	}
	if len(claims.Components) != 1 {
		return nil, fmt.Errorf("%w: %d software components, and this Server reads the measurement of one", ErrPSAClaims, len(claims.Components))
	}
	measurement, err := base64.StdEncoding.DecodeString(claims.Components[0].Measurement)
	if err != nil || len(measurement) == 0 {
		return nil, fmt.Errorf("%w: measurement-value", ErrPSAClaims)
	}
	return &psaClaims{implementationID: implementationID, measurement: measurement}, nil
}

// psaModule is the platform module for PSA: the platforms whose Evidence is a
// PSA attestation token.
type psaModule struct{}

// PSARule is the entry of PSA in the platform rule.
type PSARule struct {
	// ImplementationIDs lists the Implementation IDs of the platforms the rule
	// admits, in hex. The Implementation ID names the immutable part of a
	// platform; a platform that reports another is refused.
	ImplementationIDs []string `json:"implementation_ids"`

	admitted [][]byte
}

func (psaModule) Family() string { return familyPSA }

// ParseRule parses and validates the entry of PSA.
func (psaModule) ParseRule(raw json.RawMessage) (familyRule, error) {
	rule := &PSARule{}
	if err := decodeEntry(raw, rule); err != nil {
		return nil, fmt.Errorf("platform rule: %s: %w", familyPSA, err)
	}
	if len(rule.ImplementationIDs) == 0 {
		return nil, fmt.Errorf("platform rule: %s: implementation_ids is required", familyPSA)
	}
	for _, id := range rule.ImplementationIDs {
		octets, err := hex.DecodeString(strings.TrimSpace(id))
		if err != nil || len(octets) == 0 {
			return nil, fmt.Errorf("platform rule: %s: implementation_ids: %q is not hex", familyPSA, id)
		}
		rule.admitted = append(rule.admitted, octets)
	}
	return rule, nil
}

// Check admits the Attestation Results of a platform whose Implementation ID
// the rule lists.
func (r *PSARule) Check(res *attestationResults) ([]string, error) {
	if res.PSA == nil {
		return nil, fmt.Errorf("%w: %w", ErrPlatform, cmpOr(res.PSAErr, ErrPSAClaims))
	}
	if !slices.ContainsFunc(r.admitted, func(id []byte) bool { return slices.Equal(id, res.PSA.implementationID) }) {
		return nil, fmt.Errorf("%w: the Implementation ID %x is not one the rule lists", ErrPlatform, res.PSA.implementationID)
	}
	return nil, nil
}

func cmpOr(err, fallback error) error {
	if err != nil {
		return err
	}
	return fallback
}
