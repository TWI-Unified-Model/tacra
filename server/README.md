# Demo RATS-unaware Relying Party (`tacra/server`)

`tacra/server` is the PoC's **RATS-unaware Relying Party (RUP)**, the Target in
`draft-novak-rats-tacra`. An Attester authenticates to it with a credential
that a Credential Authority issued or a Secret Vault released through TACRA.

The draft gives the RUP no RATS role and leaves the RUP's role and
implementation unchanged. The RUP never sees Evidence or Attestation Results.
It does not use CAAPI and does not know which Credential Acquisition System
(CAS) protocol, platform, or Verifier was involved. It authenticates its
clients in the usual way by using trust anchors from its configuration.

> **Status:** demo/PoC code. The init script generates a disposable TLS
> identity. Do not treat this as a production relying party.

## What it authenticates

The RUP selects a verification method based on how the client presents the
credential. It does not use a credential-type field.

| Format | Presentation | Verification |
| --- | --- | --- |
| **X.509** | mTLS client certificate | The certificate chains to `x509.ca_files`, has `clientAuth` extended key usage, and is within its validity period. Its subject is the CN. |
| **WIC** | mTLS client certificate with a WIMSE URI SAN | The certificate chains to `wic.ca_files`. It has exactly one URI SAN whose scheme is in `wic.uri_schemes` (`spiffe`, `wimse`). Its trust domain (the URI host) is in `wic.trust_domains`; an empty list accepts any domain. Its subject is that URI. |
| **WIT** | `Workload-Identity-Token` header, bound to the mTLS client key | The token has `typ: wit+jwt` and uses an asymmetric algorithm in `wit.algorithms`. It is signed by a configured public key, has `iss` in `wit.issuers`, and has `sub` and `exp`. Its `cnf.jwk` equals the public key of the TLS client certificate. That certificate does not need to chain to a trusted CA. |
| **Bearer JWT** | `Authorization: Bearer <jwt>` | The token uses an **asymmetric** algorithm in `jwt.algorithms` (for example, `ES256`). It is signed by a configured public key, has `iss` in `jwt.issuers`, `aud` equal to `audience`, and `exp`. |

The RUP stores **public verification keys only**, from JWKS files and/or PEM
`PUBLIC KEY` (SubjectPublicKeyInfo) files. It cannot mint any credential that
it accepts. HMAC algorithms are rejected in configuration and at verification,
which also prevents public-key-as-HMAC-secret key confusion. This follows the
draft's Credential Scope section: the RUP enforces credential scope in the
usual way, for example through a JWT's `aud` claim.

### Security rules

- **Any failed credential rejects the request.** The RUP does not ignore an
  invalid credential because another credential is valid.
- **Bearer downgrade is blocked.** A `wit+jwt` token presented as a bearer
  JWT is refused.
- **Unsafe algorithms are rejected.** `none` and `HS*` are refused, and RSA
  keys must be at least 2048 bits.
- **Client certificates are requested, then checked by format.** The TLS
  configuration uses `tls.RequestClientCert`. The RUP verifies certificate
  chains separately for each format so it can accept a WIT bound to an
  untrusted key. Go's TLS server still verifies `CertificateVerify`, so a
  presented certificate proves key possession.
- **Failures are generic.** Failures return a generic `401 unauthorized`. The
  server logs the reason, but never token contents.
- **Successful responses identify the format.** They include
  `X-RUP-Credential-Format`, for example `x509,jwt`.

### Acceptance policy

`accept` lists credential combinations. A request is authorized when its
verified formats include every format in at least one combination. The
generated default is `[["x509"], ["wic"], ["wit"], ["jwt"]]`, so any one
format is sufficient.

The draft supports bearer tokens but discourages them. To require proof of
possession, remove `["jwt"]`. To require several credentials together, list
them in one combination; for example, `[["x509", "jwt"]]` requires both an
X.509 client certificate and a bearer JWT.

## Configuration

`main.go` loads only `RUP_CONFIG`. The default is
`deploy/config/local/tacra-rup/rup.json`, relative to `tacra/`. Unknown fields
are rejected. Relative paths are resolved from the configuration file's
directory. See [testdata/rup.json](testdata/rup.json) for a complete example.

| Environment variable | Default | Meaning |
| --- | --- | --- |
| `RUP_CONFIG` | `deploy/config/local/tacra-rup/rup.json` | RUP configuration |
| `HTTPS_ADDR` | `:8443` | Listen address |

### Generating a local configuration

[`deploy/init-local-rup-config.sh`](../deploy/init-local-rup-config.sh)
follows the pattern of `init-local-est-config.sh`. It creates a 30-day
development CA and server certificate for the RUP's own TLS identity. It also
writes `rup.json` under `deploy/config/local/tacra-rup/`, which is ignored by
Git. The script **never generates client trust anchors**. Supply the issuer's
trust material:

```sh
cd tacra
RUP_CLIENT_CA_FILE=/path/to/issuing-ca.pem \
RUP_WIC_TRUST_DOMAIN=example.org \
RUP_JWT_ISSUER=https://issuer.example RUP_JWT_PUBLIC_KEY_FILE=/path/to/es256-pub.pem \
RUP_WIT_ISSUER=https://wit.example RUP_WIT_JWKS_FILE=/path/to/wit-jwks.json \
  ./deploy/init-local-rup-config.sh
make server && ./bin/server
```

- **Other overrides:** `RUP_AUDIENCE` (default `https://localhost:8443`),
  `RUP_SERVER_SANS`, `RUP_CERT_DAYS`, `RUP_CLOCK_SKEW_SECONDS`, and
  `DEPLOY_CONFIG_DIR`.
- **No trust anchors:** without trust anchors, the RUP starts but rejects every
  request.
- **Existing configuration:** if `rup.json` already exists, the script leaves
  it unchanged. To regenerate it, remove `deploy/config/local/tacra-rup/`.

### Client trust in the RUP

The client authenticates the RUP through `RUP_CA_FILE`, for example
`deploy/config/local/tacra-rup/certs/rup-ca.pem`. This identity is independent
of the CA that issued the client's credential. If `RUP_CA_FILE` is unset,
`tacra/client` falls back to the CA in its acquired certificate chain.

## Testing

```sh
cd tacra/server && go test ./...
```

The tests in `rup_test.go` create their own CAs, certificates, ES256 issuer
keys (JWKS and PEM), WITs, and JWKS files. They cover:

- **Successful authentication:**
  - X.509, and X.509 combined with JWT.
  - Bearer JWT signed with an ES256 key from JWKS or from a PEM file.
  - WICs using `spiffe` and `wimse` identifiers.
  - WITs bound to an untrusted self-signed or a trusted client certificate.
  - The combination policy.
- **Rejections:**
  - JWTs that are expired, have no `exp`, or have the wrong audience or issuer.
  - JWTs that use a disallowed algorithm, an unknown key, or HMAC signing,
    including a public key used as an HMAC secret.
  - Malformed JWTs, and WITs presented as bearer tokens.
  - An unsupported `Authorization` scheme.
  - WICs with the wrong trust domain or two identifiers.
  - WICs from an untrusted CA, or when no WIC trust anchors are configured.
  - WITs without a client certificate, bound to another key, with the wrong
    `typ`, signed by an unknown key, expired, from an untrusted issuer, or
    missing `cnf` or `sub`.
  - An untrusted certificate presented alone.
- **Supporting behavior:**
  - Middleware response codes and headers.
  - Configuration loading.
  - Validation of `none` and HMAC algorithms, unreadable keys, and files that
    contain a private key instead of a public key.
  - JWK parsing.

The standalone binary was also exercised over real TLS with configuration from
the init script and an operator CA:

- A client certificate from that operator CA returned `200` with
  `X-RUP-Credential-Format: x509`.
- A request with no credentials returned `401`.
- An HS256 bearer token returned `401`.

## Limitations

- **The full flow cannot run end to end.** This workspace has no CAAPI
  server, so the CAI sidecar has nothing to call. A CAS client implementation,
  such as a CAAPI-to-EST bridge, is needed before the client can acquire
  credentials for the RUP.
- **WIC and WIT were tested only in unit tests.** No issuer in the workspace
  currently produces them.
- **WITs must be mTLS-bound.** A WIT is accepted only when its `cnf.jwk` equals
  the TLS client key. The WIMSE proof-token presentation is not implemented.
- **API keys and pre-shared keys are not supported.** They are listed in the
  draft's Design Goal 2 but are deferred. Go's `crypto/tls` has no TLS
  external-PSK support.
- **The RUP runs in its own binary.** It still uses the `server` directory and
  `bin/server` name.
