# EST integration test

This directory contains a standalone Go integration test for the EST server
deployed by the TWI workspace. The test uses the EST client from the local
`globalsign-est` checkout and exercises the five EST operations implemented by
that client and server:

- `CACerts`
- `CSRAttrs`
- `Enroll`
- `Reenroll`
- `ServerKeyGen`

`TPMEnroll` is intentionally excluded from this proof of concept because it
requires TPM enrollment inputs that are not provided by the local mock server.

## EST protocol

Enrollment over Secure Transport (EST), defined primarily by RFC 7030, uses
HTTPS and PKCS#10 certificate signing requests to enroll clients with a CA.
The EST server exposes well-known resources below its configured base path:

| Client method | EST resource | Purpose | Test result |
| --- | --- | --- | --- |
| `CACerts` | `GET /.well-known/est/cacerts` | Retrieves the CA certificate chain used to validate the EST service and issued certificates. | At least one CA certificate is returned. |
| `CSRAttrs` | `GET /.well-known/est/csrattrs` | Retrieves CA-specific CSR requirements. | The response is decoded and its OID and attribute counts are logged. The local mock configuration currently returns zero of each. |
| `Enroll` | `POST /.well-known/est/simpleenroll` | Submits a PKCS#10 CSR for initial certificate issuance. | A certificate with the requested Common Name is returned and verified against the local CA. |
| `Reenroll` | `POST /.well-known/est/simplereenroll` | Renews an existing certificate using mutual TLS and a matching CSR. | A new certificate with a different serial number is returned and verified. |
| `ServerKeyGen` | `POST /.well-known/est/serverkeygen` | Asks the server to generate a private key and issue a certificate for its public key. | A certificate and PKCS#8 private key are returned; the key matches the certificate public key. |

The exact URL construction, TLS handling, request encoding, response parsing,
and CSR signing are provided by the `github.com/globalsign/est` client
library. The test does not implement the EST wire protocol itself.

## Workspace components

The workspace has two relevant `globalsign-est` roles:

| Component | Workspace location | Role |
| --- | --- | --- |
| EST client library | [`../../globalsign-est`](../../globalsign-est) | Provides `est.Client` and the `CACerts`, `CSRAttrs`, `Enroll`, `Reenroll`, `ServerKeyGen`, and `TPMEnroll` methods. |
| EST server implementation | [`../../globalsign-est`](../../globalsign-est) | Provides the HTTPS server, EST handlers, and local mock CA used by the Docker image. |

The module file uses a local replacement so the test compiles against the
workspace checkout rather than a downloaded copy:

```text
replace github.com/globalsign/est => ../../globalsign-est
```

The `est` module is also included in [`../go.work`](../go.work), so it can be
used as part of the TACRA workspace.

## Starting the EST server

From the workspace root, build and deploy the EST component with:

```bash
./tacra/deploy/components.sh build --components globalsign-est
./tacra/deploy/components.sh deploy --components globalsign-est
```

The deployment script starts a container named `twi-globalsign-est` using the
local configuration under:

```text
tacra/deploy/config/local/globalsign-est
```

The server listens on port `8443` inside the container. The script publishes
that port as host port `9444`:

```text
host localhost:9444 -> container :8443
```

The test runs on the host, so it uses `localhost:9444` by default. It does not
need to join the Docker `twi-local` network. That network is only needed for
container-to-container name resolution.

Check the container before running the test:

```bash
docker ps --filter name=twi-globalsign-est
```

## Running the test

Run from this directory:

```bash
cd tacra/est
go test -v -count=1 ./...
```

`-count=1` disables Go test-result caching. This matters because the test
communicates with a live Docker container.

The test uses a 60-second context timeout and runs the subtests sequentially.
`Reenroll` depends on the certificate and key produced by `Enroll`; it is
skipped if enrollment fails.

## Test cases

### CACerts

Input:

- EST server address: `localhost:9444`
- Local CA trust anchor: `../deploy/config/local/globalsign-est/certs/ca-certificates.pem`
- No client certificate

Expected output:

- The server returns one or more CA certificates.
- Each returned certificate subject and `IsCA` value is logged.

### CSRAttrs

Input:

- No CSR is required.
- The request is sent without a client certificate.

Expected output:

- The response is successfully decoded as `est.CSRAttrs`.
- The test logs the number of returned OIDs and attributes.
- The current local mock server returns `0 OIDs, 0 attributes`; this is a
  successful empty response, not a test failure.

### Enroll

Input:

- A newly generated ECDSA P-256 private key.
- A PKCS#10 CSR.
- Default subject Common Name: `twi-unified-model-client`.
- Optional DNS SANs from `EST_SANS`.
- No client certificate is required by the local server for this operation.

Expected output:

- A certificate is returned with the CSR subject.
- The certificate Common Name equals `twi-unified-model-client` by default.
- The certificate chains to the configured local EST CA.
- The certificate and original CSR/key are retained for `Reenroll`.

The mock CA signs the issued certificate with the same local CA that signed
the EST server certificate. Its certificate template includes both
`serverAuth` and `clientAuth` extended key usages.

### Reenroll

Input:

- The certificate and private key returned by `Enroll`.
- The identical CSR used for `Enroll`.
- Mutual TLS using the enrolled certificate.

Expected output:

- A new certificate is returned.
- The Common Name remains `twi-unified-model-client` by default.
- The new certificate chains to the local EST CA.
- The new certificate has a different serial number.

The original CSR is deliberately reused because RFC 7030 requires the subject
and subject alternative name information in the reenrollment CSR to match the
certificate presented by the client.

### ServerKeyGen

Input:

- A newly generated PKCS#10 CSR.
- Optional `Bit-Size` header from `EST_BIT_SIZE`.
- No client certificate is required by the local server for this operation.

Expected output:

- A certificate is returned for the generated key.
- The certificate chains to the local EST CA.
- The returned private key is valid PKCS#8 DER.
- The returned private key's public key matches the certificate public key.

The local test run normally returns an RSA private key. Set
`EST_BIT_SIZE=2048`, `3072`, or `4096` to request a supported RSA key size.

## Configuration overrides

The test reads overrides from the process environment. Empty values fall back
to the defaults shown below.

| Environment variable | Default | Description |
| --- | --- | --- |
| `EST_HOST` | `localhost:9444` | Host and port of the EST server. |
| `EST_CN` | `twi-unified-model-client` | Common Name placed in generated CSRs. |
| `EST_CA_CERT` | `../deploy/config/local/globalsign-est/certs/ca-certificates.pem` | PEM CA certificate used as the explicit TLS and certificate-verification anchor. |
| `EST_APS` | empty | Additional EST path segment passed to the client library. |
| `EST_SANS` | empty | Comma-separated DNS names placed in generated CSRs. |
| `EST_BIT_SIZE` | empty | Value of the `Bit-Size` header sent for `ServerKeyGen`. |

Example:

```bash
EST_CN=my-workload \
EST_SANS=localhost,my-workload \
EST_BIT_SIZE=3072 \
go test -v -count=1 ./...
```

The test does not use the server `/healthcheck` endpoint and therefore does
not require its basic-auth password.

## Troubleshooting

If the test reports a connection error, confirm that the container is running
and that host port `9444` is published:

```bash
docker ps --filter name=twi-globalsign-est
docker logs twi-globalsign-est
```

Without local EST configuration or a running `twi-globalsign-est` container,
`go test` skips `TestESTOperations` instead of failing. Set `EST_CA_CERT` to an
explicit path only when the file should already exist; a missing explicit path
is still a failure.

If the local CA files are missing or expired, regenerate the local EST
configuration from the workspace root:

```bash
./tacra/deploy/init-local-est-config.sh
```

Then recreate the EST container so it uses the regenerated certificates:

```bash
./tacra/deploy/components.sh deploy --components globalsign-est
```