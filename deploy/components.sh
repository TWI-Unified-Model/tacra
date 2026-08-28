#!/usr/bin/env bash
set -euo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly WORKSPACE_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
readonly NETWORK_NAME="twi-local"

ACTION=""
COMPONENTS="all"
CONFIG_DIR="${DEPLOY_CONFIG_DIR:-${SCRIPT_DIR}/config/local}"
PLATFORM=""
DOCKER_HOST_VALUE=""
DRY_RUN=false
declare -a SELECTED_COMPONENTS=() PARSED_COMPONENTS=()

usage() {
    cat <<'EOF'
Usage:
  twium/deploy/components.sh <build|deploy|stop|status> [options]

Options:
  --components LIST       Comma-separated components, or all (default: all).
  --config-dir PATH       Runtime configuration directory.
  --platform PLATFORM     Docker platform, such as linux/amd64.
  --docker-host ENDPOINT  Docker daemon endpoint for non-Veraison components.
  --dry-run               Print commands without executing them.
  -h, --help              Show this help.

Components:
  globalsign-est, hashicorp-vault, spiffe-spire, step-ca, veraison-services

Build creates selected component images. Deploy requires those images already
exist in the target Docker daemon; no application image is pulled implicitly.
EOF
}

fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
run() { printf '+ '; printf '%q ' "$@"; printf '\n'; [[ "${DRY_RUN}" == true ]] || "$@"; }

detect_platform() {
    [[ -n "${PLATFORM}" ]] && return
    case "$(uname -m)" in
        arm64|aarch64) PLATFORM="linux/arm64" ;;
        x86_64|amd64) PLATFORM="linux/amd64" ;;
        *) fail "unsupported host architecture: $(uname -m); pass --platform" ;;
    esac
}

require_docker() {
    command -v docker >/dev/null 2>&1 || fail "docker is required"
    [[ "${DRY_RUN}" == true ]] || docker info >/dev/null 2>&1 || fail "cannot access the Docker daemon"
}

split_list() {
    IFS=',' read -r -a PARSED_COMPONENTS <<< "$1"
    local item
    for item in "${PARSED_COMPONENTS[@]}"; do [[ -n "${item}" ]] || fail "component lists cannot contain empty values"; done
}

validate_component() {
    case "$1" in
        globalsign-est|hashicorp-vault|spiffe-spire|step-ca|veraison-services) ;;
        twium|veraison-apiclient) fail "$1 is not deployable: it is a schema or client-library project" ;;
        *) fail "unknown component: $1" ;;
    esac
}

resolve_components() {
    local component
    if [[ "${COMPONENTS}" == all ]]; then
        SELECTED_COMPONENTS=(globalsign-est hashicorp-vault spiffe-spire step-ca veraison-services)
    else
        split_list "${COMPONENTS}"; SELECTED_COMPONENTS=("${PARSED_COMPONENTS[@]}")
    fi
    for component in "${SELECTED_COMPONENTS[@]}"; do validate_component "${component}"; done
}

image_tag() { printf 'twi/%s:local-%s' "$1" "${PLATFORM//\//-}"; }
image_exists() { [[ "${DRY_RUN}" == true ]] || docker image inspect "$1" >/dev/null 2>&1; }
require_file() { [[ -f "$1" ]] || fail "required configuration file is missing: $1"; }
require_directory() { [[ -d "$1" ]] || fail "required configuration directory is missing: $1"; }

est_config_is_complete() {
    local component_dir="$1"
    [[ -f "${component_dir}/estserver.json" ]] &&
        [[ -f "${component_dir}/certs/ca-certificates.pem" ]] &&
        [[ -f "${component_dir}/certs/ca-key.pem" ]] &&
        [[ -f "${component_dir}/certs/client-ca.pem" ]] &&
        [[ -f "${component_dir}/certs/server-certificates.pem" ]] &&
        [[ -f "${component_dir}/certs/server-key.pem" ]]
}

ensure_local_est_config() {
    local component_dir="$1"
    est_config_is_complete "${component_dir}" && return
    [[ "${CONFIG_DIR}" == "${SCRIPT_DIR}/config/local" ]] || return
    [[ ! -e "${component_dir}/estserver.json" ]] || return
    printf 'Generating local EST development configuration in %s\n' "${component_dir}"
    DEPLOY_CONFIG_DIR="${CONFIG_DIR}" run "${SCRIPT_DIR}/init-local-est-config.sh"
}

step_ca_config_is_complete() {
    local component_dir="$1"
    [[ -f "${component_dir}/config/ca.json" ]] &&
        [[ -f "${component_dir}/secrets/password" ]] &&
        [[ -f "${component_dir}/certs/root_ca.crt" ]] &&
        [[ -f "${component_dir}/certs/intermediate_ca.crt" ]] &&
        [[ -d "${component_dir}/db" ]]
}

ensure_local_step_ca_config() {
    local component_dir="$1"
    step_ca_config_is_complete "${component_dir}" && return
    [[ "${CONFIG_DIR}" == "${SCRIPT_DIR}/config/local" ]] || return
    [[ ! -e "${component_dir}" || -z "$(find "${component_dir}" -mindepth 1 -print -quit)" ]] || return
    printf 'Generating local step-ca development configuration in %s\n' "${component_dir}"
    DEPLOY_CONFIG_DIR="${CONFIG_DIR}" run "${SCRIPT_DIR}/init-local-step-ca-config.sh"
}

vault_config_is_complete() {
    [[ -f "$1/config/vault.hcl" ]]
}

ensure_local_vault_config() {
    local component_dir="$1"
    vault_config_is_complete "${component_dir}" && return
    [[ "${CONFIG_DIR}" == "${SCRIPT_DIR}/config/local" ]] || return
    [[ ! -e "${component_dir}" || -z "$(find "${component_dir}" -mindepth 1 -print -quit)" ]] || return
    printf 'Generating local Vault development configuration in %s\n' "${component_dir}"
    DEPLOY_CONFIG_DIR="${CONFIG_DIR}" run "${SCRIPT_DIR}/init-local-hashicorp-vault-config.sh"
}

spire_server_config_is_complete() {
    [[ -f "$1/server.conf" ]]
}

ensure_local_spire_config() {
    local component_dir="$1"
    spire_server_config_is_complete "${component_dir}" && return
    [[ "${CONFIG_DIR}" == "${SCRIPT_DIR}/config/local" ]] || return
    [[ ! -e "${component_dir}" || -z "$(find "${component_dir}" -mindepth 1 -print -quit)" ]] || return
    printf 'Generating local SPIRE server configuration in %s\n' "${component_dir}"
    DEPLOY_CONFIG_DIR="${CONFIG_DIR}" run "${SCRIPT_DIR}/init-local-spiffe-spire-config.sh"
}

ensure_network() {
    [[ "${DRY_RUN}" == false ]] && docker network inspect "${NETWORK_NAME}" >/dev/null 2>&1 && return
    run docker network create "${NETWORK_NAME}"
}

remove_container() {
    [[ "${DRY_RUN}" == false ]] && ! docker container inspect "$1" >/dev/null 2>&1 && return
    run docker rm -f "$1"
}

build_component() {
    local component="$1" go_version
    case "${component}" in
        globalsign-est)
            run docker build --platform "${PLATFORM}" --build-arg GO_VERSION=1.26.5 -t "$(image_tag globalsign-est)" -f "${WORKSPACE_ROOT}/globalsign-est/Dockerfile" "${WORKSPACE_ROOT}/globalsign-est"
            ;;
        hashicorp-vault)
            go_version="$(<"${WORKSPACE_ROOT}/hashicorp-vault/.go-version")"
            run docker build --platform "${PLATFORM}" --build-arg VERSION="${go_version}" -t "$(image_tag hashicorp-vault)" -f "${WORKSPACE_ROOT}/hashicorp-vault/scripts/docker/Dockerfile" "${WORKSPACE_ROOT}/hashicorp-vault"
            ;;
        spiffe-spire)
            go_version="$(<"${WORKSPACE_ROOT}/spiffe-spire/.go-version")"
            run docker build --platform "${PLATFORM}" --build-arg goversion="${go_version}" --target spire-server -t "$(image_tag spiffe-spire-server)" "${WORKSPACE_ROOT}/spiffe-spire"
            run docker build --platform "${PLATFORM}" --build-arg goversion="${go_version}" --target spire-agent -t "$(image_tag spiffe-spire-agent)" "${WORKSPACE_ROOT}/spiffe-spire"
            ;;
        step-ca)
            run docker build --platform "${PLATFORM}" -t "$(image_tag step-ca)" -f "${WORKSPACE_ROOT}/step-ca/docker/Dockerfile" "${WORKSPACE_ROOT}/step-ca"
            ;;
        veraison-services)
            [[ -z "${DOCKER_HOST_VALUE}" ]] || fail "veraison-services source deployment supports only the local Docker daemon"
            run make -C "${WORKSPACE_ROOT}/veraison-services/deployments/docker" all
            ;;
    esac
}

require_component_images() {
    local component="$1" image
    case "${component}" in
        globalsign-est|hashicorp-vault|step-ca)
            image="$(image_tag "${component}")"; image_exists "${image}" || fail "missing image: ${image}"
            ;;
        spiffe-spire)
            image_exists "$(image_tag spiffe-spire-server)" || fail "missing image: $(image_tag spiffe-spire-server)"
            image_exists "$(image_tag spiffe-spire-agent)" || fail "missing image: $(image_tag spiffe-spire-agent)"
            ;;
    esac
}

deploy_component() {
    local component="$1" component_dir config_dir
    case "${component}" in
        globalsign-est)
            component_dir="${CONFIG_DIR}/globalsign-est"; ensure_local_est_config "${component_dir}"
            [[ "${DRY_RUN}" == true ]] || est_config_is_complete "${component_dir}" || fail "required EST configuration is incomplete: ${component_dir}; run ${SCRIPT_DIR}/init-local-est-config.sh for local development"
            ensure_network; remove_container twi-globalsign-est
            run docker run -d --name twi-globalsign-est --restart unless-stopped --label twi.component=globalsign-est --network "${NETWORK_NAME}" -p 9444:8443 -v "${component_dir}:/etc/est:ro" "$(image_tag globalsign-est)"
            ;;
        hashicorp-vault)
            component_dir="${CONFIG_DIR}/hashicorp-vault"; ensure_local_vault_config "${component_dir}"
            [[ "${DRY_RUN}" == true ]] || vault_config_is_complete "${component_dir}" || fail "required Vault configuration is incomplete: ${component_dir}; run ${SCRIPT_DIR}/init-local-hashicorp-vault-config.sh for local development"
            config_dir="${component_dir}/config"
            ensure_network; remove_container twi-hashicorp-vault; run docker volume create twi-vault-file; run docker volume create twi-vault-logs
            run docker run -d --name twi-hashicorp-vault --restart unless-stopped --label twi.component=hashicorp-vault --network "${NETWORK_NAME}" -p 8200:8200 -p 8201:8201 -e SKIP_CHOWN=1 -e SKIP_SETCAP=1 -v "${config_dir}:/vault/config:ro" -v twi-vault-file:/vault/file -v twi-vault-logs:/vault/logs "$(image_tag hashicorp-vault)" server
            ;;
        spiffe-spire)
            component_dir="${CONFIG_DIR}/spiffe-spire"; ensure_local_spire_config "${component_dir}"
            [[ "${DRY_RUN}" == true ]] || spire_server_config_is_complete "${component_dir}" || fail "required SPIRE server configuration is incomplete: ${component_dir}; run ${SCRIPT_DIR}/init-local-spiffe-spire-config.sh for local development"
            ensure_network; remove_container twi-spire-server; run docker volume create twi-spire-server-data
            run docker run -d --name twi-spire-server --restart unless-stopped --label twi.component=spiffe-spire --network "${NETWORK_NAME}" -p 8081:8081 -v "${component_dir}/server.conf:/etc/spire/server/server.conf:ro" -v twi-spire-server-data:/var/lib/spire/server "$(image_tag spiffe-spire-server)" -config /etc/spire/server/server.conf
            if [[ -f "${component_dir}/agent.conf" ]]; then
                remove_container twi-spire-agent; run docker volume create twi-spire-agent-data
                run docker run -d --name twi-spire-agent --restart unless-stopped --label twi.component=spiffe-spire --network "${NETWORK_NAME}" -v "${component_dir}/agent.conf:/etc/spire/agent/agent.conf:ro" -v twi-spire-agent-data:/var/lib/spire/agent "$(image_tag spiffe-spire-agent)" -config /etc/spire/agent/agent.conf
            fi
            ;;
        step-ca)
            component_dir="${CONFIG_DIR}/step-ca"; ensure_local_step_ca_config "${component_dir}"
            [[ "${DRY_RUN}" == true ]] || step_ca_config_is_complete "${component_dir}" || fail "required step-ca configuration is incomplete: ${component_dir}; run ${SCRIPT_DIR}/init-local-step-ca-config.sh for local development"
            ensure_network; remove_container twi-step-ca
            run docker run -d --name twi-step-ca --restart unless-stopped --label twi.component=step-ca --network "${NETWORK_NAME}" -p 9000:9000 -v "${component_dir}:/home/step" "$(image_tag step-ca)"
            ;;
        veraison-services)
            [[ -z "${DOCKER_HOST_VALUE}" ]] || fail "veraison-services deployment supports only the local Docker daemon"
            run "${WORKSPACE_ROOT}/veraison-services/deployments/docker/veraison" start
            ;;
    esac
}

stop_component() {
    case "$1" in
        globalsign-est) remove_container twi-globalsign-est ;;
        hashicorp-vault) remove_container twi-hashicorp-vault ;;
        spiffe-spire) remove_container twi-spire-agent; remove_container twi-spire-server ;;
        step-ca) remove_container twi-step-ca ;;
        veraison-services) [[ -z "${DOCKER_HOST_VALUE}" ]] || fail "veraison-services deployment supports only the local Docker daemon"; run "${WORKSPACE_ROOT}/veraison-services/deployments/docker/veraison" stop ;;
    esac
}

status_component() {
    case "$1" in
        globalsign-est) run docker ps --filter name=^/twi-globalsign-est$ --format 'globalsign-est: {{.Status}}' ;;
        hashicorp-vault) run docker ps --filter name=^/twi-hashicorp-vault$ --format 'hashicorp-vault: {{.Status}}' ;;
        spiffe-spire) run docker ps --filter label=twi.component=spiffe-spire --format 'spiffe-spire: {{.Names}} {{.Status}}' ;;
        step-ca) run docker ps --filter name=^/twi-step-ca$ --format 'step-ca: {{.Status}}' ;;
        veraison-services) [[ -z "${DOCKER_HOST_VALUE}" ]] || fail "veraison-services deployment supports only the local Docker daemon"; run "${WORKSPACE_ROOT}/veraison-services/deployments/docker/veraison" status ;;
    esac
}

parse_args() {
    [[ $# -gt 0 ]] || { usage; exit 1; }
    case "$1" in
        -h|--help) usage; exit 0 ;;
    esac
    ACTION="$1"; shift
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --components) COMPONENTS="${2:?missing value for --components}"; shift 2 ;;
            --config-dir) CONFIG_DIR="${2:?missing value for --config-dir}"; shift 2 ;;
            --platform) PLATFORM="${2:?missing value for --platform}"; shift 2 ;;
            --docker-host) DOCKER_HOST_VALUE="${2:?missing value for --docker-host}"; shift 2 ;;
            --dry-run) DRY_RUN=true; shift ;;
            -h|--help) usage; exit 0 ;;
            *) fail "unknown option: $1" ;;
        esac
    done
    case "${ACTION}" in build|deploy|stop|status) ;; *) fail "unknown action: ${ACTION}" ;; esac
}

main() {
    parse_args "$@"; detect_platform; resolve_components
    [[ -z "${DOCKER_HOST_VALUE}" ]] || export DOCKER_HOST="${DOCKER_HOST_VALUE}"
    require_docker
    local component
    case "${ACTION}" in
        build) for component in "${SELECTED_COMPONENTS[@]}"; do build_component "${component}"; done ;;
        deploy) for component in "${SELECTED_COMPONENTS[@]}"; do require_component_images "${component}"; deploy_component "${component}"; done ;;
        stop) for component in "${SELECTED_COMPONENTS[@]}"; do stop_component "${component}"; done ;;
        status) for component in "${SELECTED_COMPONENTS[@]}"; do status_component "${component}"; done ;;
    esac
}

main "$@"