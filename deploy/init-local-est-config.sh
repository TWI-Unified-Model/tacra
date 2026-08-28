#!/usr/bin/env bash
set -euo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly CONFIG_DIR="${DEPLOY_CONFIG_DIR:-${SCRIPT_DIR}/config/local}/globalsign-est"
readonly CERT_DIR="${CONFIG_DIR}/certs"

if [[ -e "${CONFIG_DIR}/estserver.json" ]]; then
    printf 'Local EST configuration already exists: %s\n' "${CONFIG_DIR}/estserver.json" >&2
    exit 0
fi

command -v openssl >/dev/null 2>&1 || {
    printf 'ERROR: openssl is required to create local EST certificates.\n' >&2
    exit 1
}

umask 077
mkdir -p "${CERT_DIR}"

openssl ecparam -name prime256v1 -genkey -noout -out "${CERT_DIR}/ca-key.pem"
openssl req -x509 -new -sha256 -days 30 \
    -key "${CERT_DIR}/ca-key.pem" \
    -subj '/CN=TWI Local EST Development CA' \
    -out "${CERT_DIR}/ca-certificates.pem"

openssl ecparam -name prime256v1 -genkey -noout -out "${CERT_DIR}/server-key.pem"
openssl req -new -sha256 \
    -key "${CERT_DIR}/server-key.pem" \
    -subj '/CN=localhost' \
    -out "${CERT_DIR}/server.csr"
printf '%s\n' \
    'subjectAltName=DNS:localhost,IP:127.0.0.1' \
    'extendedKeyUsage=serverAuth' > "${CERT_DIR}/server.ext"
openssl x509 -req -sha256 -days 30 \
    -in "${CERT_DIR}/server.csr" \
    -CA "${CERT_DIR}/ca-certificates.pem" \
    -CAkey "${CERT_DIR}/ca-key.pem" \
    -CAcreateserial \
    -extfile "${CERT_DIR}/server.ext" \
    -out "${CERT_DIR}/server-certificates.pem"
rm -f "${CERT_DIR}/server.csr" "${CERT_DIR}/server.ext" "${CERT_DIR}/ca-certificates.srl"

cp "${CERT_DIR}/ca-certificates.pem" "${CERT_DIR}/client-ca.pem"
healthcheck_password="$(openssl rand -hex 24)"

cat > "${CONFIG_DIR}/estserver.json" <<EOF
{
  "mock_ca": {
    "certificates": "/etc/est/certs/ca-certificates.pem",
    "private_key": "/etc/est/certs/ca-key.pem"
  },
  "tls": {
    "listen_address": ":8443",
    "certificates": "/etc/est/certs/server-certificates.pem",
    "private_key": "/etc/est/certs/server-key.pem",
    "client_cas": ["/etc/est/certs/client-ca.pem"]
  },
  "allowed_hosts": ["localhost", "127.0.0.1"],
  "healthcheck_password": "${healthcheck_password}",
  "rate_limit": 150,
  "timeout": 30
}
EOF

chmod 600 "${CERT_DIR}"/*-key.pem "${CONFIG_DIR}/estserver.json"
chmod 644 "${CERT_DIR}"/*-certificates.pem "${CERT_DIR}/client-ca.pem"

printf 'Created local EST configuration in %s\n' "${CONFIG_DIR}"