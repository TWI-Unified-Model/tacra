#!/usr/bin/env bash
set -euo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly CONFIG_DIR="${DEPLOY_CONFIG_DIR:-${SCRIPT_DIR}/config/local}/step-ca"

case "$(uname -m)" in
    arm64|aarch64) platform="linux/arm64" ;;
    x86_64|amd64) platform="linux/amd64" ;;
    *) printf 'ERROR: unsupported host architecture: %s\n' "$(uname -m)" >&2; exit 1 ;;
esac

readonly IMAGE="twi/step-ca:local-${platform//\//-}"

if [[ -e "${CONFIG_DIR}" ]] && [[ -n "$(find "${CONFIG_DIR}" -mindepth 1 -print -quit)" ]]; then
    printf 'Local step-ca configuration already exists or is incomplete: %s\n' "${CONFIG_DIR}" >&2
    exit 0
fi

command -v docker >/dev/null 2>&1 || {
    printf 'ERROR: docker is required to create local step-ca configuration.\n' >&2
    exit 1
}
docker image inspect "${IMAGE}" >/dev/null 2>&1 || {
    printf 'ERROR: required step-ca image is missing: %s; run components.sh build --components step-ca first.\n' "${IMAGE}" >&2
    exit 1
}

mkdir -p "${CONFIG_DIR}"
docker run --rm --platform "${platform}" \
    -v "${CONFIG_DIR}:/home/step" \
    -e DOCKER_STEPCA_INIT_NAME="TWI Local Step CA" \
    -e DOCKER_STEPCA_INIT_DNS_NAMES="localhost,127.0.0.1" \
    -e DOCKER_STEPCA_INIT_ACME=true \
    "${IMAGE}" true >/dev/null

printf 'Created local step-ca configuration in %s\n' "${CONFIG_DIR}"
