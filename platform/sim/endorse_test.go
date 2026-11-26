package sim

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestEndorsements(t *testing.T) {
	key, err := NewAttestationKey()
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewEndorsements(&key.PublicKey, testMeasurement[:])
	if err != nil {
		t.Fatal(err)
	}
	instance, _ := InstanceID(&key.PublicKey)

	var trustAnchor struct {
		Triples struct {
			Keys []struct {
				Environment struct {
					Class struct {
						ID struct{ Type, Value string }
					}
					Instance struct{ Type, Value string }
				}
				VerificationKeys []struct{ Type, Value string } `json:"verification-keys"`
			} `json:"attester-verification-keys"`
		}
	}
	if err := json.Unmarshal(e.TrustAnchor, &trustAnchor); err != nil {
		t.Fatal(err)
	}
	if len(trustAnchor.Triples.Keys) != 1 {
		t.Fatalf("%d trust anchors, expected one", len(trustAnchor.Triples.Keys))
	}
	anchor := trustAnchor.Triples.Keys[0]
	if anchor.Environment.Class.ID.Value != base64.StdEncoding.EncodeToString(ImplementationID()) {
		t.Fatal("the trust anchor does not name the Implementation ID of the simulated platform")
	}
	if anchor.Environment.Instance.Type != "ueid" || anchor.Environment.Instance.Value != base64.StdEncoding.EncodeToString(instance) {
		t.Fatal("the trust anchor does not name the Instance ID of the Attestation Key")
	}
	if len(anchor.VerificationKeys) != 1 || !strings.HasPrefix(anchor.VerificationKeys[0].Value, "-----BEGIN PUBLIC KEY-----") {
		t.Fatal("the trust anchor carries no public key in PEM")
	}

	var referenceValues struct {
		Triples struct {
			Values []struct {
				Measurements []struct {
					Key   struct{ Value string }
					Value struct {
						Digests    []string
						Name       string
						CryptoKeys []struct{ Type, Value string } `json:"cryptokeys"`
					}
				}
			} `json:"reference-values"`
		}
	}
	if err := json.Unmarshal(e.ReferenceValues, &referenceValues); err != nil {
		t.Fatal(err)
	}
	measurement := referenceValues.Triples.Values[0].Measurements[0]
	if measurement.Key.Value != "psa.software-component" || measurement.Value.Name != MeasurementType {
		t.Fatalf("Reference Value %+v", measurement)
	}
	if measurement.Value.Digests[0] != "sha-256:"+base64.StdEncoding.EncodeToString(testMeasurement[:]) {
		t.Fatal("the Reference Value does not carry the measurement")
	}
	signer, _ := SignerID(&key.PublicKey)
	if len(signer) != 32 || len(measurement.Value.CryptoKeys) != 1 || measurement.Value.CryptoKeys[0].Value != string(signer) {
		t.Fatalf("the Reference Value does not carry the signer ID of the token: %+v", measurement.Value.CryptoKeys)
	}

	var corim struct {
		ID      string `json:"corim-id"`
		Profile string
	}
	if err := json.Unmarshal(e.CoRIM, &corim); err != nil {
		t.Fatal(err)
	}
	if corim.Profile != EndorsementProfile || len(corim.ID) != 36 {
		t.Fatalf("CoRIM %+v", corim)
	}

	// The same platform and measurement give the same templates again.
	again, err := NewEndorsements(&key.PublicKey, testMeasurement[:])
	if err != nil {
		t.Fatal(err)
	}
	if string(again.TrustAnchor) != string(e.TrustAnchor) || string(again.ReferenceValues) != string(e.ReferenceValues) || string(again.CoRIM) != string(e.CoRIM) {
		t.Fatal("the templates of one platform and measurement differ between two calls")
	}

	if _, err := NewEndorsements(&key.PublicKey, []byte("short")); !errors.Is(err, ErrMeasurement) {
		t.Fatalf("got %v, expected ErrMeasurement", err)
	}
	if _, err := NewEndorsements(nil, testMeasurement[:]); err == nil {
		t.Fatal("Endorsements without an Attestation Key were written")
	}
}
