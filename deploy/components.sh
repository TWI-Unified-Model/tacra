#!/usr/bin/env bash
set -euo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly WORKSPACE_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
readonly NETWORK_NAME="twi-local"

ACTION=""
COMPONENTS="all"
CONFIG_DIR="${DEPLOY_CONFIG_DIR:-${SCRIPT_DIR}/config}"
PLATFORM=""
DOCKER_HOST_VALUE=""
NO_BUILD_COMPONENTS=""
DRY_RUN=false
declare -a SELECTED_COMPONENTS=() SKIP_BUILD_COMPONENTS=() PARSED_COMPONENTS=()

usage() {
    cat <<'EOF'
Usage:
  twium/deploy/components.sh <build|deploy|stop|status> [options]

Options:
  --components LIST       Comma-separated components, or all (default: all).
  --no-build LIST         Reuse existing images for listed components during deploy.
  --config-dir PATH       Runtime configuration directory.
  --platform PLATFORM     Docker platform, such as linux/amd64.
  --docker-host ENDPOINT  Docker daemon endpoint for non-Veraison components.
  --dry-run               Print commands without executing them.
  -h, --help              Show this help.

Components:
  globalsign-est, hashicorp-vault, spiffe-spire, step-ca, veraison-services

Deploy builds selected components unless listed in --no-build. --no-build
requires the image already exist in the target Docker daemon; no application
image is pulled implicitly.
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
    [[ -z "${NO_BUILD_COMPONENTS}" ]] && {
        SKIP_BUILD_COMPONENTS=()
        return
    }
    if [[ "${NO_BUILD_COMPONENTS}" == all ]]; then
        SKIP_BUILD_COMPONENTS=("${SELECTED_COMPONENTS[@]}")
    else
        split_list "${NO_BUILD_COMPONENTS}"; SKIP_BUILD_COMPONENTS=("${PARSED_COMPONENTS[@]}")
    fi
    for component in "${SKIP_BUILD_COMPONENTS[@]}"; do validate_component "${component}"; done
}

contains() { local sought="$1" item; shift; for item in "$@"; do [[ "${item}" == "${sought}" ]] && return 0; done; return 1; }
image_tag() { printf 'twi/%s:local-%s' "$1" "${PLATFORM//\//-}"; }
image_exists() { [[ "${DRY_RUN}" == true ]] || docker image inspect "$1" >/dev/null 2>&1; }
require_file() { [[ -f "$1" ]] || fail "required configuration file is missing: $1"; }
require_directory() { [[ -d "$1" ]] || fail "required configuration directory is missing: $1"; }

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
            run make -C "${WORKSPACE_ROOT}/veraison-services" docker-deploy
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
            component_dir="${CONFIG_DIR}/globalsign-est"; require_file "${component_dir}/estserver.json"; require_directory "${component_dir}/certs"
            ensure_network; remove_container twi-globalsign-est
            run docker run -d --name twi-globalsign-est --restart unless-stopped --label twi.component=globalsign-est --network "${NETWORK_NAME}" -p 8443:8443 -v "${component_dir}:/etc/est:ro" "$(image_tag globalsign-est)"
            ;;
        hashicorp-vault)
            config_dir="${CONFIG_DIR}/hashicorp-vault/config"; require_directory "${config_dir}"
            ensure_network; remove_container twi-hashicorp-vault; run docker volume create twi-vault-file; run docker volume create twi-vault-logs
            run docker run -d --name twi-hashicorp-vault --restart unless-stopped --label twi.component=hashicorp-vault --network "${NETWORK_NAME}" --cap-add IPC_LOCK -p 8200:8200 -p 8201:8201 -e SKIP_CHOWN=1 -v "${config_dir}:/vault/config:ro" -v twi-vault-file:/vault/file -v twi-vault-logs:/vault/logs "$(image_tag hashicorp-vault)" server
            ;;
        spiffe-spire)
            component_dir="${CONFIG_DIR}/spiffe-spire"; require_file "${component_dir}/server.conf"
            ensure_network; remove_container twi-spire-server; run docker volume create twi-spire-server-data
            run docker run -d --name twi-spire-server --restart unless-stopped --label twi.component=spiffe-spire --network "${NETWORK_NAME}" -p 8081:8081 -v "${component_dir}/server.conf:/etc/spire/server/server.conf:ro" -v twi-spire-server-data:/var/lib/spire/server "$(image_tag spiffe-spire-server)" -config /etc/spire/server/server.conf
            if [[ -f "${component_dir}/agent.conf" ]]; then
                remove_container twi-spire-agent; run docker volume create twi-spire-agent-data
                run docker run -d --name twi-spire-agent --restart unless-stopped --label twi.component=spiffe-spire --network "${NETWORK_NAME}" -v "${component_dir}/agent.conf:/etc/spire/agent/agent.conf:ro" -v twi-spire-agent-data:/var/lib/spire/agent "$(image_tag spiffe-spire-agent)" -config /etc/spire/agent/agent.conf
            fi
            ;;
        step-ca)
            component_dir="${CONFIG_DIR}/step-ca"; require_file "${component_dir}/config/ca.json"; require_file "${component_dir}/secrets/password"
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
    [[ $# -gt 0 ]] || { usage; exit 1; }; ACTION="$1"; shift
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --components) COMPONENTS="${2:?missing value for --components}"; shift 2 ;;
            --no-build) NO_BUILD_COMPONENTS="${2:?missing value for --no-build}"; shift 2 ;;
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
        deploy) for component in "${SELECTED_COMPONENTS[@]}"; do
            if ((${#SKIP_BUILD_COMPONENTS[@]} > 0)) && contains "${component}" "${SKIP_BUILD_COMPONENTS[@]}"; then
                require_component_images "${component}"
            else
                build_component "${component}"
            fi
            deploy_component "${component}"
        done ;;
        stop) for component in "${SELECTED_COMPONENTS[@]}"; do stop_component "${component}"; done ;;
        status) for component in "${SELECTED_COMPONENTS[@]}"; do status_component "${component}"; done ;;
    esac
}

main "$@"