#!/usr/bin/env bash
# Generates disposable local configuration for the demo RATS-unaware Relying
# Party (tacra/server): its own TLS server identity and a rup.json whose client
# trust anchors are operator-supplied files. Nothing here is a production default.
set -euo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly CONFIG_DIR="${DEPLOY_CONFIG_DIR:-${SCRIPT_DIR}/config/local}/tacra-rup"
readonly CERT_DIR="${CONFIG_DIR}/certs"

readonly CERT_DAYS="${RUP_CERT_DAYS:-30}"
readonly SERVER_SANS="${RUP_SERVER_SANS:-DNS:localhost,DNS:tacra-server,DNS:host.docker.internal,IP:127.0.0.1,IP:::1}"
readonly AUDIENCE="${RUP_AUDIENCE:-https://localhost:8443}"
readonly CLOCK_SKEW_SECONDS="${RUP_CLOCK_SKEW_SECONDS:-30}"

# Operator-supplied client trust anchors; each is optional and may be empty.
readonly CLIENT_CA_FILE="${RUP_CLIENT_CA_FILE:-}"
readonly WIC_TRUST_DOMAIN="${RUP_WIC_TRUST_DOMAIN:-}"
readonly JWT_ISSUER="${RUP_JWT_ISSUER:-}"
readonly JWT_PUBLIC_KEY_FILE="${RUP_JWT_PUBLIC_KEY_FILE:-}"
readonly JWT_JWKS_FILE="${RUP_JWT_JWKS_FILE:-}"
readonly WIT_ISSUER="${RUP_WIT_ISSUER:-}"
readonly WIT_PUBLIC_KEY_FILE="${RUP_WIT_PUBLIC_KEY_FILE:-}"
readonly WIT_JWKS_FILE="${RUP_WIT_JWKS_FILE:-}"

if [[ -e "${CONFIG_DIR}/rup.json" ]]; then
    printf 'Local RUP configuration already exists: %s\n' "${CONFIG_DIR}/rup.json" >&2
    exit 0
fi

command -v openssl >/dev/null 2>&1 || {
    printf 'ERROR: openssl is required to create local RUP certificates.\n' >&2
    exit 1
}

# json_list prints a JSON array holding $1 when it is non-empty, else [].
json_list() {
    if [[ -z "$1" ]]; then
        printf '[]'
        return
    fi
    if [[ "$1" == *'"'* || "$1" == *'\'* ]]; then
        printf 'ERROR: value must not contain quotes or backslashes: %s\n' "$1" >&2
        exit 1
    fi
    printf '["%s"]' "$1"
}

for f in "${CLIENT_CA_FILE}" "${JWT_PUBLIC_KEY_FILE}" "${JWT_JWKS_FILE}" "${WIT_PUBLIC_KEY_FILE}" "${WIT_JWKS_FILE}"; do
    if [[ -n "${f}" && ! -r "${f}" ]]; then
        printf 'ERROR: trust anchor file is not readable: %s\n' "${f}" >&2
        exit 1
    fi
done

umask 077
mkdir -p "${CERT_DIR}"

openssl ecparam -name prime256v1 -genkey -noout -out "${CERT_DIR}/rup-ca-key.pem"
openssl req -x509 -new -sha256 -days "${CERT_DAYS}" \
    -key "${CERT_DIR}/rup-ca-key.pem" \
    -subj '/CN=TWI Local RUP Development CA' \
    -out "${CERT_DIR}/rup-ca.pem"

openssl ecparam -name prime256v1 -genkey -noout -out "${CERT_DIR}/server-key-ec.pem"
openssl pkcs8 -topk8 -nocrypt -in "${CERT_DIR}/server-key-ec.pem" -out "${CERT_DIR}/server-key.pem"
openssl req -new -sha256 \
    -key "${CERT_DIR}/server-key.pem" \
    -subj '/CN=localhost' \
    -out "${CERT_DIR}/server.csr"
printf '%s\n' \
    "subjectAltName=${SERVER_SANS}" \
    'extendedKeyUsage=serverAuth' > "${CERT_DIR}/server.ext"
openssl x509 -req -sha256 -days "${CERT_DAYS}" \
    -in "${CERT_DIR}/server.csr" \
    -CA "${CERT_DIR}/rup-ca.pem" \
    -CAkey "${CERT_DIR}/rup-ca-key.pem" \
    -CAcreateserial \
    -extfile "${CERT_DIR}/server.ext" \
    -out "${CERT_DIR}/server-cert.pem"
rm -f "${CERT_DIR}/server.csr" "${CERT_DIR}/server.ext" "${CERT_DIR}/rup-ca.srl" "${CERT_DIR}/server-key-ec.pem"

cat > "${CONFIG_DIR}/rup.json" <<EOF
{
  "audience": "${AUDIENCE}",
  "clock_skew_seconds": ${CLOCK_SKEW_SECONDS},
  "accept": [["x509"], ["wic"], ["wit"], ["jwt"]],
  "tls": {
    "cert_file": "certs/server-cert.pem",
    "key_file": "certs/server-key.pem"
  },
  "x509": {
    "ca_files": $(json_list "${CLIENT_CA_FILE}")
  },
  "wic": {
    "ca_files": $(json_list "${CLIENT_CA_FILE}"),
    "uri_schemes": ["spiffe", "wimse"],
    "trust_domains": $(json_list "${WIC_TRUST_DOMAIN}")
  },
  "jwt": {
    "issuers": $(json_list "${JWT_ISSUER}"),
    "algorithms": ["ES256", "ES384", "EdDSA", "RS256", "PS256"],
    "jwks_files": $(json_list "${JWT_JWKS_FILE}"),
    "public_key_files": $(json_list "${JWT_PUBLIC_KEY_FILE}")
  },
  "wit": {
    "issuers": $(json_list "${WIT_ISSUER}"),
    "algorithms": ["ES256", "ES384", "EdDSA", "RS256", "PS256"],
    "jwks_files": $(json_list "${WIT_JWKS_FILE}"),
    "public_key_files": $(json_list "${WIT_PUBLIC_KEY_FILE}")
  }
}
EOF

chmod 600 "${CERT_DIR}/rup-ca-key.pem" "${CERT_DIR}/server-key.pem" "${CONFIG_DIR}/rup.json"
chmod 644 "${CERT_DIR}/rup-ca.pem" "${CERT_DIR}/server-cert.pem"

printf 'Created local RUP configuration in %s\n' "${CONFIG_DIR}"
printf 'Clients trust the RUP via RUP_CA_FILE=%s\n' "${CERT_DIR}/rup-ca.pem"
if [[ -z "${CLIENT_CA_FILE}${JWT_PUBLIC_KEY_FILE}${JWT_JWKS_FILE}${WIT_PUBLIC_KEY_FILE}${WIT_JWKS_FILE}" ]]; then
    printf 'No client trust anchors supplied: the RUP will reject every request until rup.json names some.\n' >&2
fi
