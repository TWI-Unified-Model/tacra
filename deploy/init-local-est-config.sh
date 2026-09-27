#!/usr/bin/env bash
set -euo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly CONFIG_DIR="${DEPLOY_CONFIG_DIR:-${SCRIPT_DIR}/config/local}/globalsign-est"
readonly CERT_DIR="${CONFIG_DIR}/certs"
readonly PROVIDER_DIR="$(dirname -- "${CONFIG_DIR}")/mock-tee-provider"

est_config_is_complete() {
    [[ -f "${CONFIG_DIR}/estserver.json" ]] &&
        [[ -f "${CERT_DIR}/ca-certificates.pem" ]] &&
        [[ -f "${CERT_DIR}/ca-key.pem" ]] &&
        [[ -f "${CERT_DIR}/client-ca.pem" ]] &&
        [[ -f "${CERT_DIR}/server-certificates.pem" ]] &&
        [[ -f "${CERT_DIR}/server-key.pem" ]] &&
        [[ -f "${CERT_DIR}/mock-tee-provider-public-key.pem" ]]
}

write_mock_tee_provider() {
    mkdir -p "${CERT_DIR}" "${PROVIDER_DIR}"
    if [[ ! -f "${PROVIDER_DIR}/key.pem" ]]; then
        openssl ecparam -name prime256v1 -genkey -noout -out "${PROVIDER_DIR}/key.pem"
    fi
    openssl ec -in "${PROVIDER_DIR}/key.pem" -pubout \
        -out "${CERT_DIR}/mock-tee-provider-public-key.pem"
    chmod 600 "${PROVIDER_DIR}/key.pem"
    chmod 644 "${CERT_DIR}/mock-tee-provider-public-key.pem"
}

if est_config_is_complete; then
    printf 'Local EST configuration already exists: %s\n' "${CONFIG_DIR}/estserver.json" >&2
    exit 0
fi

if [[ -e "${CONFIG_DIR}/estserver.json" ]]; then
    for required in ca-certificates.pem ca-key.pem client-ca.pem server-certificates.pem server-key.pem; do
        if [[ ! -f "${CERT_DIR}/${required}" ]]; then
            printf 'ERROR: local EST configuration is incomplete (%s is missing). Remove %s and rerun to regenerate.\n' \
                "${required}" "${CONFIG_DIR}" >&2
            exit 1
        fi
    done
    command -v openssl >/dev/null 2>&1 || {
        printf 'ERROR: openssl is required to create the mock TEE provider key.\n' >&2
        exit 1
    }
    umask 077
    write_mock_tee_provider
    chmod 755 "${CONFIG_DIR}" "${CERT_DIR}"
    chmod 644 "${CONFIG_DIR}/estserver.json" "${CERT_DIR}"/*.pem
    printf 'Added mock TEE provider key to existing local EST configuration in %s\n' "${CONFIG_DIR}"
    exit 0
fi

command -v openssl >/dev/null 2>&1 || {
    printf 'ERROR: openssl is required to create local EST certificates.\n' >&2
    exit 1
}

umask 077
mkdir -p "${CERT_DIR}" "${PROVIDER_DIR}"

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
write_mock_tee_provider

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
  "attest": {
    "trusted_provider_public_key": "/etc/est/certs/mock-tee-provider-public-key.pem",
    "targets": [
      { "name": "RUP-workload-1", "mechanism": "enroll", "freshness_kind": "present-nonce" },
      { "name": "RUP-workload-2", "mechanism": "retrieve", "freshness_kind": "present-nonce" },
      { "name": "RUP-enroll-absent-timestamp", "mechanism": "enroll", "freshness_kind": "absent-timestamp", "max_age": 300 },
      { "name": "RUP-enroll-absent-none", "mechanism": "enroll", "freshness_kind": "absent-none" },
      { "name": "RUP-enroll-absent-epoch", "mechanism": "enroll", "freshness_kind": "absent-epoch", "epoch_marker": "twi-epoch-2026-09" },
      { "name": "RUP-enroll-present-epoch", "mechanism": "enroll", "freshness_kind": "present-epoch", "epoch_marker": "twi-epoch-2026-09" },
      { "name": "RUP-retrieve-absent-timestamp", "mechanism": "retrieve", "freshness_kind": "absent-timestamp", "max_age": 300 },
      { "name": "RUP-retrieve-absent-none", "mechanism": "retrieve", "freshness_kind": "absent-none" },
      { "name": "RUP-retrieve-absent-epoch", "mechanism": "retrieve", "freshness_kind": "absent-epoch", "epoch_marker": "twi-epoch-2026-09" },
      { "name": "RUP-retrieve-present-epoch", "mechanism": "retrieve", "freshness_kind": "present-epoch", "epoch_marker": "twi-epoch-2026-09" }
    ]
  },
  "healthcheck_password": "${healthcheck_password}",
  "rate_limit": 150,
  "timeout": 30
}
EOF

# Bind-mounted into USER est; umask 077 would make the tree unreadable.
chmod 755 "${CONFIG_DIR}" "${CERT_DIR}"
chmod 644 "${CONFIG_DIR}/estserver.json" "${CERT_DIR}"/*.pem
chmod 600 "${PROVIDER_DIR}/key.pem"

printf 'Created local EST configuration in %s\n' "${CONFIG_DIR}"
