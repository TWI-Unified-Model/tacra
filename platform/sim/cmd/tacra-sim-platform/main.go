// Command tacra-sim-platform prepares a simulated platform for a Verifier: it
// creates the Attestation Key of the platform, measures the program that will
// hold the plug-in, and writes the templates from which the cocli tool of the
// Veraison project builds the Endorsements. It also produces one piece of
// Evidence, to check a Verifier before any Workload runs.
package main

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/TWI-Unified-Model/tacra/platform"
	"github.com/TWI-Unified-Model/tacra/platform/sim"
)

const usage = `Usage:
  tacra-sim-platform keygen -key FILE
      Create the Attestation Key of a simulated platform. An existing file is kept.
  tacra-sim-platform public -key FILE -out FILE
      Write the public half of the Attestation Key, for a party that verifies the Evidence.
  tacra-sim-platform measure PROGRAM
      Print the measurement of a program: the SHA-256 of its file, in hex.
  tacra-sim-platform endorsements -key FILE -measurement HEX -out DIR
      Write comid-trust-anchor.json, comid-reference-values.json and corim.json to DIR.
  tacra-sim-platform evidence -key FILE -measurement HEX -target TARGET -handle HEX -out FILE
      Write Evidence of a Retrieval for TARGET with the Freshness Kind present-nonce,
      and print the binding value, which is the nonce of the Evidence.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = keygen(os.Args[2:])
	case "public":
		err = public(os.Args[2:])
	case "measure":
		err = measure(os.Args[2:])
	case "endorsements":
		err = endorsements(os.Args[2:])
	case "evidence":
		err = evidence(os.Args[2:])
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "tacra-sim-platform: %v\n", err)
		os.Exit(1)
	}
}

func keygen(args []string) error {
	flags := flag.NewFlagSet("keygen", flag.ContinueOnError)
	path := flags.String("key", "", "file of the Attestation Key")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *path == "" {
		return errors.New("keygen needs -key")
	}
	if _, err := os.Stat(*path); err == nil {
		fmt.Printf("kept the Attestation Key in %s\n", *path)
		return nil
	}
	key, err := sim.NewAttestationKey()
	if err != nil {
		return err
	}
	encoded, err := sim.MarshalAttestationKey(key)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*path, encoded, 0o600); err != nil {
		return err
	}
	fmt.Printf("created the Attestation Key in %s\n", *path)
	return nil
}

func measure(args []string) error {
	if len(args) != 1 {
		return errors.New("measure needs one program")
	}
	measurement, err := sim.MeasureFile(args[0])
	if err != nil {
		return err
	}
	fmt.Println(hex.EncodeToString(measurement))
	return nil
}

func public(args []string) error {
	flags := flag.NewFlagSet("public", flag.ContinueOnError)
	path := flags.String("key", "", "file of the Attestation Key")
	out := flags.String("out", "", "file for the public key")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *path == "" || *out == "" {
		return errors.New("public needs -key and -out")
	}
	key, err := readKey(*path)
	if err != nil {
		return err
	}
	encoded, err := sim.MarshalAttestationPublicKey(&key.PublicKey)
	if err != nil {
		return err
	}
	return os.WriteFile(*out, encoded, 0o644)
}

func readKey(path string) (*ecdsa.PrivateKey, error) {
	if path == "" {
		return nil, errors.New("-key is required")
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return sim.ParseAttestationKey(encoded)
}

func readMeasurement(value string) ([]byte, error) {
	measurement, err := hex.DecodeString(value)
	if err != nil || len(measurement) != sim.MeasurementSize {
		return nil, fmt.Errorf("-measurement must be %d octets in hex", sim.MeasurementSize)
	}
	return measurement, nil
}

func endorsements(args []string) error {
	flags := flag.NewFlagSet("endorsements", flag.ContinueOnError)
	keyPath := flags.String("key", "", "file of the Attestation Key")
	measurementHex := flags.String("measurement", "", "measurement of the admitted program, in hex")
	out := flags.String("out", "", "directory for the templates")
	if err := flags.Parse(args); err != nil {
		return err
	}
	key, err := readKey(*keyPath)
	if err != nil {
		return err
	}
	measurement, err := readMeasurement(*measurementHex)
	if err != nil {
		return err
	}
	if *out == "" {
		return errors.New("endorsements needs -out")
	}
	templates, err := sim.NewEndorsements(&key.PublicKey, measurement)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		return err
	}
	for name, content := range map[string][]byte{
		"comid-trust-anchor.json":     templates.TrustAnchor,
		"comid-reference-values.json": templates.ReferenceValues,
		"corim.json":                  templates.CoRIM,
	} {
		if err := os.WriteFile(filepath.Join(*out, name), append(content, '\n'), 0o644); err != nil {
			return err
		}
	}
	fmt.Printf("wrote the templates to %s; media type of the CoRIM: %s\n", *out, sim.EndorsementMediaType)
	return nil
}

func evidence(args []string) error {
	flags := flag.NewFlagSet("evidence", flag.ContinueOnError)
	keyPath := flags.String("key", "", "file of the Attestation Key")
	measurementHex := flags.String("measurement", "", "measurement that the Evidence reports, in hex")
	target := flags.String("target", "", "Target")
	handleHex := flags.String("handle", "", "Freshness Handle, in hex")
	out := flags.String("out", "", "file for the Evidence")
	if err := flags.Parse(args); err != nil {
		return err
	}
	key, err := readKey(*keyPath)
	if err != nil {
		return err
	}
	measurement, err := readMeasurement(*measurementHex)
	if err != nil {
		return err
	}
	handle, err := hex.DecodeString(*handleHex)
	if err != nil {
		return errors.New("-handle must be hex")
	}
	if *out == "" {
		return errors.New("evidence needs -out")
	}
	plugin, err := sim.NewSimulated(sim.WithAttestationKey(key), sim.WithMeasurement(measurement))
	if err != nil {
		return err
	}
	cek, err := plugin.GenerateCEK(platform.EncryptionAlgorithmECDHP256)
	if err != nil {
		return err
	}
	cekPub, err := platform.CEKPub(cek.Public())
	if err != nil {
		return err
	}
	produced, err := plugin.GenerateEvidence(platform.EvidenceRequest{
		FreshnessKind:   platform.FreshnessKindPresentNonce,
		FreshnessHandle: handle,
		BoundKey:        cek.Public(),
		BoundKeyUse:     platform.BoundKeyUseEncrypt,
		Target:          *target,
	})
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, produced.Token, 0o644); err != nil {
		return err
	}
	bindingValue := platform.BindingValue(handle, *target, cekPub)
	fmt.Printf("media-type: %s\n", produced.MediaType)
	fmt.Printf("binding-value: %s\n", base64.URLEncoding.EncodeToString(bindingValue[:]))
	return nil
}
