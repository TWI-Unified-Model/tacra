#!/usr/bin/env bash
set -euo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly CONFIG_DIR="${DEPLOY_CONFIG_DIR:-${SCRIPT_DIR}/config/local}/hashicorp-vault/config"
readonly CONFIG_FILE="${CONFIG_DIR}/vault.hcl"

if [[ -e "${CONFIG_FILE}" ]]; then
    printf 'Local Vault configuration already exists: %s\n' "${CONFIG_FILE}" >&2
    exit 0
fi

if [[ -e "${CONFIG_DIR}" ]] && [[ -n "$(find "${CONFIG_DIR}" -mindepth 1 -print -quit)" ]]; then
    printf 'ERROR: local Vault configuration is incomplete: %s\n' "${CONFIG_DIR}" >&2
    exit 1
fi

umask 077
mkdir -p "${CONFIG_DIR}"
cat > "${CONFIG_FILE}" <<'EOF'
ui = true
disable_mlock = true

storage "file" {
  path = "/vault/file"
}

listener "tcp" {
  address = "0.0.0.0:8200"
  tls_disable = true
}

api_addr = "http://twi-hashicorp-vault:8200"
cluster_addr = "http://twi-hashicorp-vault:8201"
EOF
# Bind-mounted into USER vault; umask 077 would make the tree unreadable.
chmod 755 "$(dirname -- "${CONFIG_DIR}")" "${CONFIG_DIR}"
chmod 644 "${CONFIG_FILE}"

printf 'Created local Vault configuration in %s\n' "${CONFIG_DIR}"
