#!/usr/bin/env bash
set -euo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly CONFIG_DIR="${DEPLOY_CONFIG_DIR:-${SCRIPT_DIR}/config/local}/spiffe-spire"
readonly SERVER_CONFIG="${CONFIG_DIR}/server.conf"

if [[ -e "${SERVER_CONFIG}" ]]; then
    printf 'Local SPIRE server configuration already exists: %s\n' "${SERVER_CONFIG}" >&2
    exit 0
fi

if [[ -e "${CONFIG_DIR}" ]] && [[ -n "$(find "${CONFIG_DIR}" -mindepth 1 -print -quit)" ]]; then
    printf 'ERROR: local SPIRE configuration is incomplete: %s\n' "${CONFIG_DIR}" >&2
    exit 1
fi

mkdir -p "${CONFIG_DIR}"
cat > "${SERVER_CONFIG}" <<'EOF'
server {
  trust_domain = "twi.local"
  bind_address = "0.0.0.0"
  bind_port = "8081"
  data_dir = "/var/lib/spire/server"
  log_level = "INFO"
  default_x509_svid_ttl = "1h"
  default_jwt_svid_ttl = "5m"
  ca_ttl = "24h"
}

plugins {
  DataStore "sql" {
    plugin_data {
      database_type = "sqlite3"
      connection_string = "/var/lib/spire/server/datastore.sqlite3"
    }
  }

  KeyManager "disk" {
    plugin_data {
      keys_path = "/var/lib/spire/server/keys.json"
    }
  }

  NodeAttestor "join_token" {
    plugin_data {}
  }
}
EOF
chmod 600 "${SERVER_CONFIG}"

printf 'Created local SPIRE server configuration in %s\n' "${CONFIG_DIR}"
printf 'No agent.conf was generated; configure node attestation before starting a SPIRE agent.\n'
