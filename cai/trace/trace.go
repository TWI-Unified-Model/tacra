// Package trace records the calls of CAAPI that a CAI sidecar makes and
// reports what crossed the wire.
//
// Nothing secret crosses CAAPI. The keys of the Workload never leave the
// sidecar: a request carries the CSR or CEKpub, the Freshness Element and the
// Evidence. A certificate is public, and a released credential travels sealed
// to the CEK. A trace is therefore safe to keep and to show.
//
// The report does more than print. For Evidence that it can read, a PSA
// attestation token, it computes the TACRA binding value from the request
// itself, SHA-512 over the Freshness Element, the Target and the CSR or
// CEKpub, and compares it with the nonce of the token; with the Attestation
// Key of the platform it verifies the signature of the token.
package trace

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/TWI-Unified-Model/tacra/container"
	caapiv1 "github.com/TWI-Unified-Model/tacra/gen/go/caapi/v1"
	"github.com/TWI-Unified-Model/tacra/platform"
	"github.com/TWI-Unified-Model/tacra/platform/sim"
)

// The names of the three calls of CAAPI, as a record carries them.
const (
	MethodInitiate = "InitiateRemoteAttestation"
	MethodEnroll   = "EnrollCredential"
	MethodRetrieve = "RetrieveCredential"
)

// Record is one call of CAAPI as the sidecar made it.
type Record struct {
	Sequence     int             `json:"sequence"`
	Method       string          `json:"method"`
	Request      json.RawMessage `json:"request"`            // the request, in the JSON form of Protocol Buffers
	Response     json.RawMessage `json:"response,omitempty"` // the response; absent when the call failed
	Error        string          `json:"error,omitempty"`    // the refusal, as the CAS Client returned it
	Milliseconds float64         `json:"milliseconds"`       // how long the CAS Client took to answer
}

// Interceptor returns a client interceptor that writes one file into dir for
// each call it sees. The files continue the sequence of those already there.
func Interceptor(dir string) (grpc.UnaryClientInterceptor, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	existing, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, err
	}
	var mu sync.Mutex
	sequence := len(existing)
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		start := time.Now()
		callErr := invoker(ctx, method, req, reply, cc, opts...)
		record := Record{Method: path.Base(method), Milliseconds: float64(time.Since(start).Microseconds()) / 1000}
		if message, ok := req.(proto.Message); ok {
			record.Request, _ = protojson.Marshal(message)
		}
		if callErr != nil {
			record.Error = callErr.Error()
		} else if message, ok := reply.(proto.Message); ok {
			record.Response, _ = protojson.Marshal(message)
		}
		mu.Lock()
		defer mu.Unlock()
		sequence++
		record.Sequence = sequence
		// A trace that cannot be written never fails the call it records.
		_ = write(dir, record)
		return callErr
	}, nil
}

func write(dir string, record Record) error {
	encoded, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	name := filepath.Join(dir, fmt.Sprintf("%06d-%s.json", record.Sequence, record.Method))
	// Written beside and renamed, so that a reader never finds half a record.
	if err := os.WriteFile(name+".part", append(encoded, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(name+".part", name)
}

// Read returns the records of dir after the first `after` of them, in order.
func Read(dir string, after int) ([]Record, error) {
	names, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	var records []Record
	for _, name := range names {
		encoded, err := os.ReadFile(name)
		if err != nil {
			return nil, err
		}
		var record Record
		if err := json.Unmarshal(encoded, &record); err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Base(name), err)
		}
		if record.Sequence > after {
			records = append(records, record)
		}
	}
	return records, nil
}

// Options are what the report knows beside the records.
type Options struct {
	// AttestationKey is the public Attestation Key of the platform. With it
	// the report verifies the signature of a PSA attestation token.
	AttestationKey crypto.PublicKey
	// ReferenceMeasurement is the measurement that the Verifier holds as the
	// Reference Value. With it the report says whether the Evidence carries it.
	ReferenceMeasurement []byte
	// Indent is written before every line.
	Indent string
}

// Report writes the account of the records to w and returns the number of
// checks that did not hold: a signature that does not verify, or a nonce that
// is not the binding value of the request.
func Report(w io.Writer, records []Record, opts Options) (int, error) {
	failed := 0
	var shown []byte // the measurement that the report has printed last
	for _, record := range records {
		var lines []string
		var err error
		switch record.Method {
		case MethodInitiate:
			lines, err = initiate(record)
		case MethodEnroll:
			var req caapiv1.EnrollCredentialRequest
			if err = protojson.Unmarshal(record.Request, &req); err == nil {
				var n int
				lines, n = evidence(req.GetEvidence(), req.GetEvidenceProfile(), req.GetFreshnessElement(), req.GetTarget(), req.GetCsr(), "CSR", opts, &shown)
				failed += n
				lines = append(lines, enrolled(record)...)
			}
		case MethodRetrieve:
			var req caapiv1.RetrieveCredentialRequest
			if err = protojson.Unmarshal(record.Request, &req); err == nil {
				var n int
				lines, n = evidence(req.GetEvidence(), req.GetEvidenceProfile(), req.GetFreshnessElement(), req.GetTarget(), req.GetCekPub(), "CEKpub", opts, &shown)
				failed += n
				lines = append(lines, retrieved(record)...)
			}
		default:
			lines = []string{record.Method}
		}
		if err != nil {
			return failed, fmt.Errorf("record %d (%s): %w", record.Sequence, record.Method, err)
		}
		if refusal := strings.TrimSpace(record.Error); refusal != "" {
			lines = append(lines, "<- refused: "+refusal)
		}
		name := map[string]string{MethodInitiate: "Initiate", MethodEnroll: "Enroll", MethodRetrieve: "Retrieve"}[record.Method]
		for i, line := range lines {
			head := ""
			if i == 0 {
				head = name
			}
			if i == len(lines)-1 {
				line = fmt.Sprintf("%s  (%.0f ms)", line, record.Milliseconds)
			}
			if _, err := fmt.Fprintf(w, "%s%-10s %s\n", opts.Indent, head, line); err != nil {
				return failed, err
			}
		}
	}
	return failed, nil
}

func initiate(record Record) ([]string, error) {
	var req caapiv1.InitiateCredentialAcquistionRequest
	if err := protojson.Unmarshal(record.Request, &req); err != nil {
		return nil, err
	}
	asked := fmt.Sprintf("%s for %s", credentialType(req.GetCredentialType()), req.GetTarget())
	if hint := req.GetCredentialHint(); hint != "" {
		asked += fmt.Sprintf(", Credential Hint %q", hint)
	}
	lines := []string{asked}
	if len(record.Response) == 0 {
		return lines, nil
	}
	var resp caapiv1.InitiateCredentialAcquisitionResponse
	if err := protojson.Unmarshal(record.Response, &resp); err != nil {
		return nil, err
	}
	answer := fmt.Sprintf("<- %s, %s", mode(resp.GetMode()), kind(resp.GetFreshnessKind()))
	if n := len(resp.GetFreshnessHandle()); n > 0 {
		answer += fmt.Sprintf(", Freshness Handle of %d octets", n)
	}
	if resp.SigningAlgorithm != nil {
		answer += ", CSK " + enum(resp.GetSigningAlgorithm().String(), "SIGNING_ALGORITHM_")
	}
	if resp.EncryptionAlgorithm != nil {
		answer += ", CEK " + enum(resp.GetEncryptionAlgorithm().String(), "ENCRYPTION_ALGORITHM_")
	}
	return append(lines, answer), nil
}

// evidence reports the Evidence of a request and checks what it can check.
// The measurement is printed when it differs from the one printed last.
func evidence(token []byte, profile string, element []byte, target string, subject []byte, subjectName string, opts Options, shown *[]byte) ([]string, int) {
	if profile != sim.MediaTypePSAToken {
		return []string{fmt.Sprintf("Evidence: %s, %d octets", profile, len(token))}, 0
	}
	failed := 0
	first := fmt.Sprintf("Evidence: PSA attestation token, %d octets", len(token))
	claims, err := sim.ParseEvidence(token)
	if err != nil {
		return []string{first, "the token does not decode: " + err.Error()}, 1
	}
	if opts.AttestationKey != nil {
		if _, err := sim.VerifyEvidence(token, opts.AttestationKey); err != nil {
			first += "; signature of the Attestation Key: DOES NOT VERIFY"
			failed++
		} else {
			first += "; signature of the Attestation Key: valid"
		}
	}
	lines := []string{first}

	expected := platform.BindingValue(element, target, subject)
	nonce, err := claims.GetNonce()
	switch {
	case err != nil:
		lines = append(lines, "the token carries no nonce: "+err.Error())
		failed++
	case bytes.Equal(nonce, expected[:]):
		lines = append(lines, fmt.Sprintf("nonce of the token = SHA-512(Freshness Element, Target, %s): equal  (%x...)", subjectName, expected[:8]))
	default:
		lines = append(lines, fmt.Sprintf("nonce of the token = SHA-512(Freshness Element, Target, %s): DIFFERENT  (%x... in the token, %x... from the request)", subjectName, nonce[:min(8, len(nonce))], expected[:8]))
		failed++
	}

	if components, err := claims.GetSoftwareComponents(); err == nil && len(components) > 0 {
		if measurement, err := components[0].GetMeasurementValue(); err == nil && !bytes.Equal(measurement, *shown) {
			*shown = measurement
			line := "measurement " + hex.EncodeToString(measurement)
			switch {
			case len(opts.ReferenceMeasurement) == 0:
			case bytes.Equal(measurement, opts.ReferenceMeasurement):
				line += ": the Reference Value"
			default:
				line += ": NOT the Reference Value"
			}
			lines = append(lines, line)
		}
	}
	return lines, failed
}

func enrolled(record Record) []string {
	if len(record.Response) == 0 {
		return nil
	}
	var resp caapiv1.EnrollCredentialResponse
	if err := protojson.Unmarshal(record.Response, &resp); err != nil {
		return []string{"<- a response that does not decode: " + err.Error()}
	}
	block, _ := pem.Decode(resp.GetPlaintextCredential())
	if block == nil {
		return []string{fmt.Sprintf("<- a credential of %d octets", len(resp.GetPlaintextCredential()))}
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return []string{"<- a certificate that does not parse: " + err.Error()}
	}
	subject := certificate.Subject.CommonName
	if len(certificate.URIs) > 0 {
		subject = certificate.URIs[0].String()
	}
	return []string{fmt.Sprintf("<- X.509 certificate for %s, issued by %q, valid until %s",
		subject, issuerName(certificate), certificate.NotAfter.UTC().Format(time.RFC3339))}
}

// issuerName is the name by which a reader knows the issuer: its common name,
// or its organization, or the whole distinguished name.
func issuerName(certificate *x509.Certificate) string {
	switch {
	case certificate.Issuer.CommonName != "":
		return certificate.Issuer.CommonName
	case len(certificate.Issuer.Organization) > 0:
		return certificate.Issuer.Organization[0]
	}
	return certificate.Issuer.String()
}

func retrieved(record Record) []string {
	if len(record.Response) == 0 {
		return nil
	}
	var resp caapiv1.RetrieveCredentialResponse
	if err := protojson.Unmarshal(record.Response, &resp); err != nil {
		return []string{"<- a response that does not decode: " + err.Error()}
	}
	var bundle container.Bundle
	if err := json.Unmarshal(resp.GetWrappedCredential(), &bundle); err != nil {
		return []string{fmt.Sprintf("<- a sealed credential of %d octets", len(resp.GetWrappedCredential()))}
	}
	return []string{fmt.Sprintf("<- %s container, %s, %d octets of ciphertext: only the CEK of the Workload opens it",
		bundle.Container, bundle.Suite.KEM, len(bundle.Ciphertext))}
}

func credentialType(t caapiv1.CredentialType) string {
	return strings.ToLower(strings.TrimPrefix(t.String(), "CREDENTIAL_TYPE_"))
}

func mode(m caapiv1.CredentialAcquisitionMode) string {
	return strings.ToLower(strings.TrimPrefix(m.String(), "ACQUISITION_"))
}

func kind(k caapiv1.FreshnessKind) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimPrefix(k.String(), "FRESHNESS_KIND_")), "_", "-")
}

func enum(name, prefix string) string {
	return strings.ReplaceAll(strings.TrimPrefix(name, prefix), "_", "-")
}

// ParsePublicKey reads a public key in PEM, as the Attestation Key of the
// simulated platform is published.
func ParsePublicKey(encoded []byte) (crypto.PublicKey, error) {
	block, _ := pem.Decode(encoded)
	if block == nil {
		return nil, errors.New("trace: no PEM block in the public key")
	}
	return x509.ParsePKIXPublicKey(block.Bytes)
}
