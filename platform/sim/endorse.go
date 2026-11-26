package sim

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
)

// EndorsementProfile is the CoRIM profile of the Endorsements of a PSA
// platform, and EndorsementMediaType the media type under which a Verifier
// accepts a CoRIM of that profile.
const (
	EndorsementProfile   = "tag:arm.com,2025:psa#1.0.0"
	EndorsementMediaType = `application/rim+cbor; profile="` + EndorsementProfile + `"`
)

// softwareComponentKey is the measurement key of a software component in the
// CoRIM profile of PSA.
const softwareComponentKey = "psa.software-component"

// Endorsements are the templates from which the cocli tool of the Veraison
// project builds the CoRIM that endorses one simulated platform to a Verifier:
// the Attestation Key as the trust anchor of the platform, and the measurement
// of the admitted program as its Reference Value.
type Endorsements struct {
	TrustAnchor     []byte // template of the CoMID with the Attestation Key
	ReferenceValues []byte // template of the CoMID with the Reference Value
	CoRIM           []byte // template of the CoRIM that carries the two CoMIDs
}

// NewEndorsements writes the templates for the platform that signs with
// attestationKey and whose admitted program has the given measurement.
func NewEndorsements(attestationKey *ecdsa.PublicKey, measurement []byte) (*Endorsements, error) {
	if len(measurement) != MeasurementSize {
		return nil, ErrMeasurement
	}
	instance, err := InstanceID(attestationKey)
	if err != nil {
		return nil, err
	}
	signer, err := SignerID(attestationKey)
	if err != nil {
		return nil, err
	}
	spki, err := x509.MarshalPKIXPublicKey(attestationKey)
	if err != nil {
		return nil, fmt.Errorf("sim: Attestation Key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki})

	b64 := base64.StdEncoding.EncodeToString
	class := map[string]any{"id": map[string]any{"type": "bytes", "value": b64(ImplementationID())}}
	entities := []any{map[string]any{
		"name":  "TACRA simulated platform",
		"regid": "https://github.com/TWI-Unified-Model/tacra",
		"roles": []string{"tagCreator", "creator", "maintainer"},
	}}

	trustAnchor := map[string]any{
		"lang":         "en-US",
		"tag-identity": map[string]any{"id": tagID("trust anchor", instance), "version": 0},
		"entities":     entities,
		"triples": map[string]any{
			"attester-verification-keys": []any{map[string]any{
				"environment": map[string]any{
					"class":    class,
					"instance": map[string]any{"type": "ueid", "value": b64(instance)},
				},
				"verification-keys": []any{map[string]any{"type": "pkix-base64-key", "value": string(keyPEM)}},
			}},
		},
	}
	referenceValues := map[string]any{
		"lang":         "en-US",
		"tag-identity": map[string]any{"id": tagID("reference values", instance, measurement), "version": 0},
		"entities":     entities,
		"triples": map[string]any{
			"reference-values": []any{map[string]any{
				"environment": map[string]any{"class": class},
				"measurements": []any{map[string]any{
					"key": map[string]any{"type": "string", "value": softwareComponentKey},
					"value": map[string]any{
						"digests":    []string{"sha-256:" + b64(measurement)},
						"cryptokeys": []any{map[string]any{"type": "bytes", "value": string(signer)}},
						"name":       MeasurementType,
					},
				}},
			}},
		},
	}
	corim := map[string]any{
		"corim-id": tagID("corim", instance, measurement),
		"profile":  EndorsementProfile,
	}

	e := &Endorsements{}
	if e.TrustAnchor, err = json.MarshalIndent(trustAnchor, "", "  "); err != nil {
		return nil, err
	}
	if e.ReferenceValues, err = json.MarshalIndent(referenceValues, "", "  "); err != nil {
		return nil, err
	}
	if e.CoRIM, err = json.MarshalIndent(corim, "", "  "); err != nil {
		return nil, err
	}
	return e, nil
}

// tagID derives the identifier of a tag from what the tag describes, so that
// the same platform and measurement give the same tags again. The form is
// that of a UUID.
func tagID(label string, parts ...[]byte) string {
	hash := sha256.New()
	hash.Write([]byte(label))
	for _, part := range parts {
		hash.Write(part)
	}
	u := hash.Sum(nil)[:16]
	u[6] = u[6]&0x0f | 0x80 // version 8: the value is of the application
	u[8] = u[8]&0x3f | 0x80 // variant of RFC 9562
	return fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
}
