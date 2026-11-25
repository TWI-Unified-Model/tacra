package trace

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/TWI-Unified-Model/tacra/container"
	caapiv1 "github.com/TWI-Unified-Model/tacra/gen/go/caapi/v1"
	"github.com/TWI-Unified-Model/tacra/platform"
	"github.com/TWI-Unified-Model/tacra/platform/sim"
)

const testTarget = "https://server.example"

var testHandle = bytes.Repeat([]byte{0x0a}, 32)

// The interceptor writes one file for each call, with the request, the
// response or the refusal, and continues the sequence of the directory.
func TestInterceptor(t *testing.T) {
	dir := t.TempDir()
	record, err := Interceptor(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	answer := &caapiv1.InitiateCredentialAcquisitionResponse{Mode: caapiv1.CredentialAcquisitionMode_ACQUISITION_ENROLL, FreshnessHandle: testHandle}
	invoker := func(_ context.Context, _ string, _, reply any, _ *grpc.ClientConn, _ ...grpc.CallOption) error {
		proto.Merge(reply.(proto.Message), answer)
		return nil
	}
	req := &caapiv1.InitiateCredentialAcquistionRequest{Target: testTarget, CredentialType: caapiv1.CredentialType_CREDENTIAL_TYPE_X509}
	if err := record(ctx, "/caapi.v1.CredentialAcquisitionService/InitiateRemoteAttestation", req, &caapiv1.InitiateCredentialAcquisitionResponse{}, nil, invoker); err != nil {
		t.Fatal(err)
	}
	refusal := errors.New("remote attestation failed")
	refuse := func(context.Context, string, any, any, *grpc.ClientConn, ...grpc.CallOption) error { return refusal }
	if err := record(ctx, "/caapi.v1.CredentialAcquisitionService/EnrollCredential", &caapiv1.EnrollCredentialRequest{Target: testTarget}, &caapiv1.EnrollCredentialResponse{}, nil, refuse); !errors.Is(err, refusal) {
		t.Fatalf("the interceptor must return the error of the call, got %v", err)
	}

	records, err := Read(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || records[0].Method != MethodInitiate || records[1].Method != MethodEnroll || records[0].Sequence != 1 || records[1].Sequence != 2 {
		t.Fatalf("records: %+v", records)
	}
	var got caapiv1.InitiateCredentialAcquisitionResponse
	if err := protojson.Unmarshal(records[0].Response, &got); err != nil || !proto.Equal(&got, answer) {
		t.Fatalf("the response of the first record: %v, %v", &got, err)
	}
	if records[1].Error != "remote attestation failed" || len(records[1].Response) != 0 {
		t.Fatalf("the refusal of the second record: %+v", records[1])
	}
	if later, err := Read(dir, 1); err != nil || len(later) != 1 || later[0].Sequence != 2 {
		t.Fatalf("the records after the first: %+v, %v", later, err)
	}

	// A second sidecar on the same directory continues the sequence.
	again, err := Interceptor(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := again(ctx, "/caapi.v1.CredentialAcquisitionService/InitiateRemoteAttestation", req, &caapiv1.InitiateCredentialAcquisitionResponse{}, nil, invoker); err != nil {
		t.Fatal(err)
	}
	if names, _ := filepath.Glob(filepath.Join(dir, "000003-*.json")); len(names) != 1 {
		t.Fatalf("the third record is missing: %v", names)
	}
	if parts, _ := filepath.Glob(filepath.Join(dir, "*.part")); len(parts) != 0 {
		t.Fatalf("a half-written record was left: %v", parts)
	}
}

// exchange is an Enrollment and a Retrieval as a sidecar on the simulated
// platform makes them, as records.
type exchange struct {
	key         *ecdsa.PrivateKey
	measurement []byte
	enroll      Record
	retrieve    Record
}

func newExchange(t *testing.T) *exchange {
	t.Helper()
	key, err := sim.NewAttestationKey()
	if err != nil {
		t.Fatal(err)
	}
	measurement := sha256.Sum256([]byte("the program of the sidecar"))
	plugin, err := sim.NewSimulated(sim.WithAttestationKey(key), sim.WithMeasurement(measurement[:]))
	if err != nil {
		t.Fatal(err)
	}

	csk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "workload"}}, csk)
	if err != nil {
		t.Fatal(err)
	}
	enrollEvidence, err := plugin.GenerateEvidence(platform.EvidenceRequest{
		FreshnessKind: platform.FreshnessKindPresentNonce, FreshnessHandle: testHandle, Target: testTarget,
		BoundKey: &csk.PublicKey, CSR: csr, BoundKeyUse: platform.BoundKeyUseSign,
	})
	if err != nil {
		t.Fatal(err)
	}
	spiffeID, _ := url.Parse("spiffe://example.org/workload")
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "workload"}, URIs: []*url.URL{spiffeID},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC),
	}
	issuer := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{Organization: []string{"Example CA"}}}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, &csk.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	// The CEK and CEKpub as the CAI library makes them for the hybrid suite.
	cek, err := plugin.GenerateCEK(platform.EncryptionAlgorithmMLKEM768P256)
	if err != nil {
		t.Fatal(err)
	}
	cekPub, err := platform.CEKPub(cek.Public())
	if err != nil {
		t.Fatal(err)
	}
	retrieveEvidence, err := plugin.GenerateEvidence(platform.EvidenceRequest{
		FreshnessKind: platform.FreshnessKindPresentNonce, FreshnessHandle: testHandle, Target: testTarget,
		BoundKey: cek.Public(), BoundKeyUse: platform.BoundKeyUseEncrypt,
	})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := container.Seal(cekPub, container.AAD{GroupID: "group", Target: container.B64(testTarget), Handle: container.B64(testHandle)},
		container.Content{})
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := json.Marshal(sealed)
	if err != nil {
		t.Fatal(err)
	}

	e := &exchange{key: key, measurement: measurement[:]}
	e.enroll = record(t, 1, MethodEnroll, &caapiv1.EnrollCredentialRequest{
		Target: testTarget, CredentialType: caapiv1.CredentialType_CREDENTIAL_TYPE_X509,
		FreshnessKind: caapiv1.FreshnessKind_FRESHNESS_KIND_PRESENT_NONCE, FreshnessElement: testHandle,
		Csr: csr, Evidence: enrollEvidence.Token, EvidenceProfile: proto.String(sim.MediaTypePSAToken),
	}, &caapiv1.EnrollCredentialResponse{PlaintextCredential: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})})
	e.retrieve = record(t, 2, MethodRetrieve, &caapiv1.RetrieveCredentialRequest{
		Target: testTarget, CredentialType: caapiv1.CredentialType_CREDENTIAL_TYPE_JWT,
		FreshnessKind: caapiv1.FreshnessKind_FRESHNESS_KIND_PRESENT_NONCE, FreshnessElement: testHandle,
		CekPub: cekPub, Evidence: retrieveEvidence.Token, EvidenceProfile: proto.String(sim.MediaTypePSAToken),
	}, &caapiv1.RetrieveCredentialResponse{WrappedCredential: bundle})
	return e
}

func record(t *testing.T, sequence int, method string, req, resp proto.Message) Record {
	t.Helper()
	request, err := protojson.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	response, err := protojson.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	return Record{Sequence: sequence, Method: method, Request: request, Response: response, Milliseconds: 12}
}

func report(t *testing.T, opts Options, records ...Record) (string, int) {
	t.Helper()
	var out bytes.Buffer
	failed, err := Report(&out, records, opts)
	if err != nil {
		t.Fatal(err)
	}
	return out.String(), failed
}

// The report recomputes the binding value from the request and finds it in
// the token, verifies the signature of the token, and names what came back.
func TestReport(t *testing.T) {
	e := newExchange(t)
	out, failed := report(t, Options{AttestationKey: &e.key.PublicKey, ReferenceMeasurement: e.measurement}, e.enroll, e.retrieve)
	if failed != 0 {
		t.Fatalf("%d checks failed:\n%s", failed, out)
	}
	if strings.Count(out, "measurement ") != 1 {
		t.Errorf("the measurement of both pieces of Evidence is the same and is printed once:\n%s", out)
	}
	for _, expected := range []string{
		"Enroll     Evidence: PSA attestation token,",
		"signature of the Attestation Key: valid",
		"nonce of the token = SHA-512(Freshness Element, Target, CSR): equal",
		"nonce of the token = SHA-512(Freshness Element, Target, CEKpub): equal",
		": the Reference Value",
		`<- X.509 certificate for spiffe://example.org/workload, issued by "Example CA", valid until 2030-01-02T03:04:05Z`,
		"<- hpke-base container, MLKEM768-P256,",
		"(12 ms)",
	} {
		if !strings.Contains(out, expected) {
			t.Errorf("the report lacks %q:\n%s", expected, out)
		}
	}
}

// A request whose CSR is not the CSR that the Evidence is bound to: the
// report says so and counts it.
func TestReportFindsEvidenceBoundToAnotherKey(t *testing.T) {
	e := newExchange(t)
	var req caapiv1.EnrollCredentialRequest
	if err := protojson.Unmarshal(e.enroll.Request, &req); err != nil {
		t.Fatal(err)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if req.Csr, err = x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "workload"}}, other); err != nil {
		t.Fatal(err)
	}
	if e.enroll.Request, err = protojson.Marshal(&req); err != nil {
		t.Fatal(err)
	}
	out, failed := report(t, Options{AttestationKey: &e.key.PublicKey}, e.enroll)
	if failed != 1 || !strings.Contains(out, "SHA-512(Freshness Element, Target, CSR): DIFFERENT") {
		t.Fatalf("%d checks failed:\n%s", failed, out)
	}
}

// Evidence signed by another Attestation Key, and a measurement that is not
// the Reference Value.
func TestReportFindsAnotherPlatformAndAnotherProgram(t *testing.T) {
	e := newExchange(t)
	other, err := sim.NewAttestationKey()
	if err != nil {
		t.Fatal(err)
	}
	out, failed := report(t, Options{AttestationKey: &other.PublicKey, ReferenceMeasurement: bytes.Repeat([]byte{1}, 32)}, e.enroll)
	if failed != 1 || !strings.Contains(out, "signature of the Attestation Key: DOES NOT VERIFY") || !strings.Contains(out, ": NOT the Reference Value") {
		t.Fatalf("%d checks failed:\n%s", failed, out)
	}
}

// A refusal, an initiation, and Evidence of a platform that the report does
// not read.
func TestReportOfOtherRecords(t *testing.T) {
	initiate := record(t, 1, MethodInitiate,
		&caapiv1.InitiateCredentialAcquistionRequest{Target: testTarget, CredentialType: caapiv1.CredentialType_CREDENTIAL_TYPE_JWT, CredentialHint: "db"},
		&caapiv1.InitiateCredentialAcquisitionResponse{
			Mode: caapiv1.CredentialAcquisitionMode_ACQUISITION_RETRIEVE, FreshnessKind: caapiv1.FreshnessKind_FRESHNESS_KIND_PRESENT_NONCE,
			FreshnessHandle: testHandle, EncryptionAlgorithm: caapiv1.EncryptionAlgorithm_ENCRYPTION_ALGORITHM_MLKEM768_P256.Enum(),
		})
	request, err := protojson.Marshal(&caapiv1.EnrollCredentialRequest{Target: testTarget, Evidence: []byte{1, 2, 3}, EvidenceProfile: proto.String("application/vnd.example")})
	if err != nil {
		t.Fatal(err)
	}
	refused := Record{Sequence: 2, Method: MethodEnroll, Request: request, Error: "rpc error: code = PermissionDenied desc = remote attestation failed"}
	out, failed := report(t, Options{Indent: "  "}, initiate, refused)
	if failed != 0 {
		t.Fatalf("%d checks failed:\n%s", failed, out)
	}
	for _, expected := range []string{
		`  Initiate   jwt for https://server.example, Credential Hint "db"`,
		"<- retrieve, present-nonce, Freshness Handle of 32 octets, CEK MLKEM768-P256",
		"  Enroll     Evidence: application/vnd.example, 3 octets",
		"<- refused: rpc error: code = PermissionDenied desc = remote attestation failed",
	} {
		if !strings.Contains(out, expected) {
			t.Errorf("the report lacks %q:\n%s", expected, out)
		}
	}
}

func TestParsePublicKey(t *testing.T) {
	key, err := sim.NewAttestationKey()
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	encoded, _ := os.ReadFile(path)
	parsed, err := ParsePublicKey(encoded)
	if err != nil || !key.PublicKey.Equal(parsed) {
		t.Fatalf("the parsed key: %v, %v", parsed, err)
	}
	if _, err := ParsePublicKey([]byte("not PEM")); err == nil {
		t.Fatal("text that is not PEM must be refused")
	}
}
