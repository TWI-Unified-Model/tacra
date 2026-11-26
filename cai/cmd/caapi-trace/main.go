// Command caapi-trace reports the calls of CAAPI that a CAI sidecar recorded
// (CAI_TRACE_DIR): what the sidecar asked and what the CAS Client answered.
// For a PSA attestation token it computes the TACRA binding value from the
// request and compares it with the nonce of the token, and with the public
// Attestation Key of the platform it verifies the signature of the token.
//
//	caapi-trace [-after N] [-attestation-key FILE] [-reference-measurement HEX] [-indent TEXT] DIRECTORY
//
// The command ends with status 1 when a check does not hold.
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"github.com/TWI-Unified-Model/tacra/cai/trace"
)

func main() {
	after := flag.Int("after", 0, "report the records after this many")
	keyPath := flag.String("attestation-key", "", "public Attestation Key of the platform, PEM")
	reference := flag.String("reference-measurement", "", "the measurement that the Verifier holds as the Reference Value, hex")
	indent := flag.String("indent", "", "text written before every line")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: caapi-trace [-after N] [-attestation-key FILE] [-reference-measurement HEX] [-indent TEXT] DIRECTORY")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	opts := trace.Options{Indent: *indent}
	if *keyPath != "" {
		encoded, err := os.ReadFile(*keyPath)
		if err != nil {
			fail("%v", err)
		}
		if opts.AttestationKey, err = trace.ParsePublicKey(encoded); err != nil {
			fail("%s: %v", *keyPath, err)
		}
	}
	if *reference != "" {
		measurement, err := hex.DecodeString(*reference)
		if err != nil {
			fail("-reference-measurement: %v", err)
		}
		opts.ReferenceMeasurement = measurement
	}
	records, err := trace.Read(flag.Arg(0), *after)
	if err != nil {
		fail("%v", err)
	}
	failed, err := trace.Report(os.Stdout, records, opts)
	if err != nil {
		fail("%v", err)
	}
	if failed == 1 {
		fail("one check of the trace did not hold")
	}
	if failed > 1 {
		fail("%d checks of the trace did not hold", failed)
	}
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "caapi-trace: "+format+"\n", args...)
	os.Exit(1)
}
