#!/usr/bin/env bash
# The TACRA demonstration in simulation: both steps on one computer, in Docker,
# without confidential hardware.
#
#   Step 1  The Client acquires an X.509 certificate and a JWT through SPIRE
#           and authenticates with both to the Server.
#   Step 2  The same Client acquires an X.509 certificate and a JWT through EST
#           and authenticates with both to the Server.
#
# Client, CAI sidecar and Server are the programs of this repository. step-ca,
# HashiCorp Vault, SPIRE, the EST Server and Veraison are the images that
# components.sh builds from the workspace. Only the platform of the Client is
# simulated: its Evidence is a PSA attestation token signed with a software
# key, and Veraison appraises that token as it appraises any other PSA token.
#
# The demonstration runs everything itself, Veraison included, on a network of
# its own, and publishes no port on the host. Nothing here is a production
# default: every key, certificate and token is created for one run, kept in a
# directory that Git ignores, and removed by "down", which leaves nothing.
set -euo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly TACRA_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
readonly WORKSPACE_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"

readonly NETWORK="twi-demo"
# The name under which the configuration and the certificate of Veraison know
# its verification service; the service answers to it on the network above.
readonly VERAISON_VERIFIER="verification-service"
readonly LABEL="twi.demo=simulation"
readonly MARKER=".twi-demo"

readonly C_KEYCLOAK="twi-demo-veraison-keycloak"
readonly C_VTS="twi-demo-veraison-vts"
readonly C_PROVISIONING="twi-demo-veraison-provisioning"
readonly C_VERIFICATION="twi-demo-veraison-verification"
readonly C_STEP_CA="twi-demo-step-ca"
readonly C_VAULT="twi-demo-vault"
readonly C_EST_SERVER="twi-demo-est-server"
readonly C_EST_CLIENT="twi-demo-est-client"
readonly C_SPIRE_SERVER="twi-demo-spire-server"
readonly C_SPIRE_AGENT="twi-demo-spire-agent"
readonly C_SERVER="twi-demo-server"
readonly C_CAI_SPIRE="twi-demo-cai-spire"
readonly C_CAI_EST="twi-demo-cai-est"
readonly C_CLIENT="twi-demo-client"
readonly SERVICES="${C_KEYCLOAK} ${C_VTS} ${C_PROVISIONING} ${C_VERIFICATION} ${C_STEP_CA} ${C_VAULT} ${C_EST_SERVER} ${C_EST_CLIENT} ${C_SPIRE_SERVER} ${C_SPIRE_AGENT} ${C_SERVER} ${C_CAI_SPIRE} ${C_CAI_EST}"
# The images that the demonstration runs. The four services of Veraison and its
# manager, which carries cocli, are the images of the Veraison deployment.
readonly IMAGE_NAMES="veraison-keycloak veraison-vts veraison-provisioning veraison-verification veraison-manager step-ca hashicorp-vault globalsign-est spiffe-spire-server spiffe-spire-agent tacra-cai tacra-client tacra-server"

# The Server is reached under this name on the network of the demonstration.
# The name is the Target of both steps and the audience of the JWT.
readonly SERVER_NAME="tacra-server"
readonly TARGET="https://${SERVER_NAME}:8443"
readonly TRUST_DOMAIN="twi.local"
readonly WORKLOAD_ID="spiffe://${TRUST_DOMAIN}/workload"
readonly AGENT_ID="spiffe://${TRUST_DOMAIN}/agent"
readonly CERTIFICATE_NAME="tacra-demo-client.${TRUST_DOMAIN}"
readonly JWT_ISSUER="https://issuer.${TRUST_DOMAIN}"
readonly JWT_SUBJECT="tacra-demo-client"
readonly SECRET_PATH="tacra/server-token"
readonly EVIDENCE_MEDIA_TYPE="application/psa-attestation-token"
readonly ENDORSEMENT_MEDIA_TYPE='application/rim+cbor; profile="tag:arm.com,2025:psa#1.0.0"'
readonly AGENT_SOCKET="/tmp/spire-agent/public/api.sock"

ACTION=""
CONFIG_DIR="${DEMO_CONFIG_DIR:-${SCRIPT_DIR}/config/demo}"
PLATFORM=""
LOG_COMPONENT=""
RAW=false
IMAGES=""
IMAGE_TAG="${DEMO_IMAGE_TAG:-demo}"
UP_STARTED=false
UP_DONE=false
MEASUREMENT=""
NOT_REFUSED=0

usage() {
    cat <<'EOF'
Usage:
  tacra/deploy/demo.sh <workspace|build|up|step1|step2|refusals|all|status|logs|down|push> [options]

Commands:
  workspace  Clone the other repositories of the workspace beside tacra. A
           repository that is already there is left as it is.
  build    Build the images of the workspace (components.sh build) and the
           images of the Client, the CAI sidecar and the Server.
  up       Create the configuration and start everything. A demonstration
           that is already up is removed first.
  step1    Step 1: the Client acquires an X.509 certificate and a JWT through
           SPIRE and authenticates with both to the Server.
  step2    Step 2: the same through EST.
  refusals Show what is refused: a CAI sidecar with another measurement, a
           platform that the Verifier does not know, and the JWT alone.
  all      build, up, step1, step2 and refusals, one after the other.
           With --images there is nothing to build.
  status   Show the state of every container.
  logs     Print the log of one component, for example: logs spire-server
  down     Remove the containers, volumes, network and configuration.
  push     Tag the images that this workspace built under the prefix of
           --images and push them there, for others to run with --images.

Options:
  --config-dir PATH    Directory of the generated configuration
                       (default: tacra/deploy/config/demo, ignored by Git).
  --platform PLATFORM  Docker platform, such as linux/arm64 (default: this host).
  --images PREFIX      Run images that were built elsewhere and pushed under
                       PREFIX (see push) instead of images built here: up
                       pulls them, and no workspace and no build are needed.
  --tag TAG            The tag of those images (default: demo).
  --raw                In step1, step2 and refusals, print the lines of the
                       logs as they are instead of one line for each record.
  -h, --help           Show this help.
EOF
}

fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
say() { printf '\n== %s\n' "$*"; }
note() { printf '   %s\n' "$*"; }

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
    docker info >/dev/null 2>&1 || fail "cannot access the Docker daemon"
}

image_tag() { printf 'twi/%s:local-%s' "$1" "${PLATFORM//\//-}"; }

# image NAME prints the reference of an image of the demonstration: the image
# that this workspace built or, with --images, the image of that name and of
# this platform under the prefix.
image() {
    if [[ -n "${IMAGES}" ]]; then
        printf '%s/%s:%s-%s' "${IMAGES}" "$1" "${IMAGE_TAG}" "${PLATFORM//\//-}"
        return
    fi
    case "$1" in
        veraison-*) printf 'veraison/%s' "${1#veraison-}" ;;
        *) image_tag "$1" ;;
    esac
}
image_exists() { docker image inspect "$1" >/dev/null 2>&1; }
is_running() { [[ "$(docker inspect -f '{{.State.Running}}' "$1" 2>/dev/null || true)" == true ]]; }

# quiet runs a command and shows what it printed only when it fails.
quiet() {
    local output
    if output="$("$@" 2>&1)"; then
        return 0
    fi
    printf '%s\n' "${output}" >&2
    return 1
}

# wait_for SECONDS COMMAND... runs COMMAND once a second until it succeeds.
wait_for() {
    local seconds="$1" i
    shift
    for ((i = 0; i < seconds; i++)); do
        if "$@" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    return 1
}

# give_up prints the last lines of the log of a container and fails.
give_up() {
    local container="$1"
    shift
    printf '\n--- last lines of the log of %s ---\n' "${container}" >&2
    docker logs --tail 25 "${container}" >&2 2>&1 || true
    fail "$*"
}

# share makes a generated directory readable by the user of the container that
# mounts it. The directory above it is closed to other users of this host.
share() { chmod -R a+rX "${CONFIG_DIR}/$1"; }

# tool runs the bash script on its standard input in a container of the step-ca
# image, which carries the step command, curl and jq, as the user of this
# shell and with the configuration directory at /demo. Arguments are options
# of docker run. The script travels as an argument: a command of the script
# that reads its standard input finds it empty.
tool() {
    local script
    script="$(cat)"
    docker run --rm "$@" --user "$(id -u):$(id -g)" -e HOME=/tmp -e STEPPATH=/tmp/step \
        -v "${CONFIG_DIR}:/demo" -w /demo --entrypoint /bin/bash "$(image step-ca)" -euo pipefail -c "${script}"
}

# json_field FILE FILTER prints one field of a JSON file of the configuration
# directory, with the jq of the step-ca image.
json_field() {
    docker run --rm --user "$(id -u):$(id -g)" -v "${CONFIG_DIR}:/demo:ro" -w /demo \
        --entrypoint jq "$(image step-ca)" -r "$2" "$1"
}

# log_lines prints how many lines the log of a container has, so that a later
# call can print only what the container wrote after this point.
log_lines() { docker logs "$1" 2>&1 | wc -l | tr -d ' '; }

# field KEY LINE prints the value of KEY in a log line of key=value pairs, the
# format in which the CAS Servers write their logs.
field() {
    printf '%s\n' "$2" |
        sed -n -E 's/.*[[:space:]]'"$1"'=("(([^"\\]|\\.)*)"|([^[:space:]"]*)).*/\2\4/p' |
        sed 's/\\"/"/g'
}

# told ACTOR TEXT [MORE] prints one line of the account of a step: who, and what.
told() {
    printf '   %-14s %s\n' "$1" "$2"
    if [[ -n "${3:-}" ]]; then
        printf '   %-14s %s\n' "" "$3"
    fi
}

# manager runs a command of the Veraison manager image, the image behind the
# cocli command of the Veraison deployment, with the Endorsements at /endorsements.
manager() {
    docker run --rm --network "${NETWORK}" \
        -v "${CONFIG_DIR}/veraison/endorsements:/endorsements" "$(image veraison-manager)" "$@"
}

vault_cli() { docker exec -e VAULT_ADDR=http://127.0.0.1:8200 -e VAULT_TOKEN "${C_VAULT}" vault "$@"; }
vault_cli_stdin() { docker exec -i -e VAULT_ADDR=http://127.0.0.1:8200 -e VAULT_TOKEN "${C_VAULT}" vault "$@"; }
spire_server() { docker exec "${C_SPIRE_SERVER}" /opt/spire/bin/spire-server "$@"; }
spire_agent() { docker exec "${C_SPIRE_AGENT}" /opt/spire/bin/spire-agent "$@"; }
listens() { docker exec "$1" nc -z 127.0.0.1 "$2"; }

# vault_answers succeeds once Vault answers: status 0 is unsealed, 2 is sealed.
vault_answers() {
    local rc=0
    vault_cli status >/dev/null 2>&1 || rc=$?
    [[ ${rc} -eq 0 || ${rc} -eq 2 ]]
}

require_images() {
    local name
    if [[ -n "${IMAGES}" ]]; then
        say "Images from ${IMAGES}"
    fi
    for name in ${IMAGE_NAMES}; do
        if [[ -n "${IMAGES}" ]]; then
            quiet docker pull "$(image "${name}")" || fail "cannot pull $(image "${name}")"
            note "$(image "${name}")"
        else
            image_exists "$(image "${name}")" || fail "missing image: $(image "${name}"); run: ${0} build"
        fi
    done
    docker run --rm --entrypoint /bin/sh "$(image globalsign-est)" -c 'test -x /usr/local/bin/estcasclient' ||
        fail "the image $(image globalsign-est) holds no EST Client: check out the branch of the demonstration in globalsign-est, then run: ${0} build"
}

require_running() {
    local container
    for container in ${SERVICES}; do
        is_running "${container}" || fail "${container} is not running; run: ${0} up"
    done
    [[ -f "${CONFIG_DIR}/client/server-ca.pem" ]] || fail "no configuration in ${CONFIG_DIR}; run: ${0} up"
}

# print_sources names the commit that each image is built from.
print_sources() {
    command -v git >/dev/null 2>&1 || return 0
    local repository revision
    for repository in tacra globalsign-est spiffe-spire step-ca hashicorp-vault veraison-services; do
        revision="$(git -C "${WORKSPACE_ROOT}/${repository}" log -1 --format='%h %cd' --date=short 2>/dev/null || true)"
        note "$(printf '%-18s %s (%s)' "${repository}" "${revision:-unknown}" "$(git -C "${WORKSPACE_ROOT}/${repository}" rev-parse --abbrev-ref HEAD 2>/dev/null || true)")"
    done
}

# cmd_workspace clones the repositories that the demonstration builds from,
# beside tacra and from the place that tacra itself was cloned from. Where a
# repository has a branch of the same name as the branch of tacra, that branch
# is cloned: a demonstration that is not merged yet spans several repositories.
cmd_workspace() {
    command -v git >/dev/null 2>&1 || fail "git is required"
    local origin branch repository directory
    origin="$(git -C "${TACRA_ROOT}" remote get-url origin 2>/dev/null || true)"
    origin="${origin%.git}"
    origin="${origin%/tacra}"
    [[ -n "${origin}" ]] || origin="https://github.com/TWI-Unified-Model"
    branch="$(git -C "${TACRA_ROOT}" rev-parse --abbrev-ref HEAD 2>/dev/null || true)"
    say "The repositories of the workspace, in ${WORKSPACE_ROOT}"
    for repository in globalsign-est hashicorp-vault spiffe-spire step-ca veraison-services; do
        directory="${WORKSPACE_ROOT}/${repository}"
        if [[ -e "${directory}" ]]; then
            note "$(printf '%-18s is there, left as it is' "${repository}")"
            continue
        fi
        if [[ -n "${branch}" && "${branch}" != HEAD ]] &&
            git ls-remote --exit-code --heads "${origin}/${repository}.git" "${branch}" >/dev/null 2>&1; then
            git clone --quiet --depth 1 --branch "${branch}" "${origin}/${repository}.git" "${directory}" ||
                fail "cloning ${repository} failed"
        else
            git clone --quiet --depth 1 "${origin}/${repository}.git" "${directory}" || fail "cloning ${repository} failed"
        fi
        note "$(printf '%-18s cloned, %s' "${repository}" "$(git -C "${directory}" rev-parse --abbrev-ref HEAD)")"
    done
    printf '\nNext: %s build\n' "${0}"
}

cmd_build() {
    say "Sources"
    print_sources
    say "Images of the workspace (components.sh build)"
    "${SCRIPT_DIR}/components.sh" build --platform "${PLATFORM}" \
        --components globalsign-est,hashicorp-vault,spiffe-spire,step-ca,veraison-services
    say "Images of the CAI sidecar, the Client and the Server"
    docker build --platform "${PLATFORM}" -t "$(image_tag tacra-cai)" -f "${TACRA_ROOT}/cai/Dockerfile" "${TACRA_ROOT}"
    docker build --platform "${PLATFORM}" -t "$(image_tag tacra-client)" -f "${TACRA_ROOT}/client/Dockerfile" "${TACRA_ROOT}"
    docker build --platform "${PLATFORM}" -t "$(image_tag tacra-server)" -f "${TACRA_ROOT}/server/Dockerfile" "${TACRA_ROOT}"
    printf '\nBuilt. Next: %s up\n' "${0}"
}

new_config_dir() {
    [[ ! -e "${CONFIG_DIR}" ]] || fail "${CONFIG_DIR} exists and is not a configuration of this demonstration; remove it or pass --config-dir"
    umask 022
    mkdir -p "${CONFIG_DIR}"
    chmod 700 "${CONFIG_DIR}"
    : > "${CONFIG_DIR}/${MARKER}"
    local directory
    for directory in veraison/endorsements step-ca issuer hashicorp-vault/config platform tls est-server est-client \
        spire-server spire-agent rup/certs rup/trust client trace; do
        mkdir -p "${CONFIG_DIR}/${directory}"
    done
}

# veraison_key asks the Verifier for the key that verifies its Attestation
# Results; the Verifier publishes that key once it is ready.
veraison_key() {
    tool --network "${NETWORK}" -e VERIFIER="${VERAISON_VERIFIER}" <<'EOS'
curl -fsS --cacert veraison/ca.pem "https://${VERIFIER}:8443/.well-known/veraison/verification" > veraison/discovery.json
jq -e -c 'select(."service-state" == "READY") | ."ear-verification-key"' veraison/discovery.json > veraison/ear-verification-key.jwk
EOS
}

# veraison_service SERVICE CONTAINER [OPTION...] starts one service of Veraison
# as the deployment of Veraison creates it (deployments/docker/Makefile):
# under the host name that its configuration and its certificate carry, here
# on the network of the demonstration.
veraison_service() {
    local service="$1" container="$2"
    shift 2
    docker run -d --tty --name "${container}" --label "${LABEL}" --hostname "${service}-service" \
        --network "${NETWORK}" --network-alias "${service}-service" \
        -v twi-demo-veraison-logs:/opt/veraison/logs "$@" "$(image "veraison-${service}")" >/dev/null
}

# start_veraison runs a Veraison of its own for the demonstration, from the
# images of the Veraison deployment and with stores of its own: a deployment
# of Veraison that runs beside it is not touched.
start_veraison() {
    say "Veraison, the Verifier"
    docker volume create --label "${LABEL}" twi-demo-veraison-stores >/dev/null
    docker volume create --label "${LABEL}" twi-demo-veraison-logs >/dev/null
    # The services write their logs as the user veraison, and a new volume belongs to root.
    docker run --rm --user 0 -v twi-demo-veraison-logs:/opt/veraison/logs --entrypoint /bin/chown \
        "$(image veraison-vts)" veraison:veraison /opt/veraison/logs || fail "cannot prepare the log volume of Veraison"
    veraison_service keycloak "${C_KEYCLOAK}" -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin
    veraison_service vts "${C_VTS}" -v twi-demo-veraison-stores:/opt/veraison/stores
    sleep 1 # as the veraison command does: the other services look for vts when they start
    veraison_service provisioning "${C_PROVISIONING}"
    veraison_service verification "${C_VERIFICATION}"
    # The CA of the certificates of these services, as the manager image carries it.
    docker run --rm --entrypoint /bin/cat "$(image veraison-manager)" /usr/local/share/ca-certificates/veraison-ca.crt \
        > "${CONFIG_DIR}/veraison/ca.pem" || fail "the manager image of Veraison holds no CA certificate"
    wait_for 180 veraison_key || give_up "${C_VERIFICATION}" "the Verifier did not become ready"
    note "ready; the key of its Attestation Results is in veraison/ear-verification-key.jwk"
}

start_step_ca() {
    say "step-ca, the Credential Authority behind the EST Server"
    local image
    image="$(image step-ca)"
    docker volume create --label "${LABEL}" twi-demo-step-ca >/dev/null
    # As init-local-step-ca-config.sh does: the image creates its CA at the first start.
    quiet docker run --rm -v twi-demo-step-ca:/home/step \
        -e DOCKER_STEPCA_INIT_NAME="TWI Demo Step CA" \
        -e DOCKER_STEPCA_INIT_DNS_NAMES="${C_STEP_CA},localhost" \
        "${image}" true || fail "step-ca did not create its CA"
    # The provisioner of the CAS Server Plug-in. step-ca holds its public key;
    # the EST Server holds its private key and signs one request with it for
    # each certificate.
    local provisioner='cd /tmp
step crypto jwk create provisioner.pub.json provisioner.key.json --kty EC --crv P-256 --no-password --insecure 1>&2
step ca provisioner add tacra --type JWK --public-key provisioner.pub.json --ca-config /home/step/config/ca.json 1>&2
cat provisioner.key.json'
    if ! docker run --rm -v twi-demo-step-ca:/home/step --entrypoint /bin/bash "${image}" -euo pipefail -c "${provisioner}" \
        > "${CONFIG_DIR}/est-server/provisioner-key.json" 2> "${CONFIG_DIR}/step-ca/provisioner.log"; then
        cat "${CONFIG_DIR}/step-ca/provisioner.log" >&2
        fail "step-ca did not create the provisioner of the CAS Server Plug-in"
    fi
    [[ -s "${CONFIG_DIR}/est-server/provisioner-key.json" ]] || fail "step-ca did not create the provisioner of the CAS Server Plug-in"
    docker run --rm -v twi-demo-step-ca:/home/step --entrypoint /bin/cat "${image}" \
        /home/step/certs/root_ca.crt > "${CONFIG_DIR}/step-ca/root.pem"
    docker run --rm -v twi-demo-step-ca:/home/step --entrypoint /bin/cat "${image}" \
        /home/step/certs/intermediate_ca.crt > "${CONFIG_DIR}/step-ca/intermediate.pem"
    docker run -d --name "${C_STEP_CA}" --label "${LABEL}" --network "${NETWORK}" \
        -v twi-demo-step-ca:/home/step "${image}" >/dev/null
    wait_for 60 docker exec "${C_STEP_CA}" step ca health || give_up "${C_STEP_CA}" "step-ca did not start"
    note "running; provisioner \"tacra\" for the CAS Server Plug-in"
}

# make_credentials creates what no component of the demonstration issues by
# itself: the TLS certificates of the EST Server and of the Server, and the JWT
# that the Server accepts, signed by an issuer made for this run.
make_credentials() {
    say "TLS certificates of the EST Server and the Server; the JWT that the Server accepts"
    quiet tool -e EST_SERVER="${C_EST_SERVER}" -e SERVER_NAME="${SERVER_NAME}" -e TARGET="${TARGET}" \
        -e JWT_ISSUER="${JWT_ISSUER}" -e JWT_SUBJECT="${JWT_SUBJECT}" <<'EOS' || fail "creating the certificates and the JWT failed"
key='--kty EC --curve P-256 --no-password --insecure'
step certificate create "TWI Demo EST Server CA" tls/est-server-ca.pem tls/est-server-ca-key.pem --profile root-ca ${key}
step certificate create "${EST_SERVER}" est-server/tls-cert.pem est-server/tls-key.pem --profile leaf \
    --ca tls/est-server-ca.pem --ca-key tls/est-server-ca-key.pem --san "${EST_SERVER}" --not-after 720h ${key}
cp tls/est-server-ca.pem est-client/est-server-ca.pem

step certificate create "TWI Demo Server CA" tls/server-ca.pem tls/server-ca-key.pem --profile root-ca ${key}
step certificate create "${SERVER_NAME}" rup/certs/server-cert.pem rup/certs/server-key.pem --profile leaf \
    --ca tls/server-ca.pem --ca-key tls/server-ca-key.pem --san "${SERVER_NAME}" --not-after 720h ${key}
cp tls/server-ca.pem client/server-ca.pem

step crypto jwk create issuer/issuer.pub.json issuer/issuer.key.json --kty EC --crv P-256 --no-password --insecure
step crypto jwt sign --key issuer/issuer.key.json --iss "${JWT_ISSUER}" --aud "${TARGET}" --sub "${JWT_SUBJECT}" \
    --exp "$(($(date +%s) + 30 * 24 * 3600))" > issuer/token.jwt
jq -c '{keys: [.]}' issuer/issuer.pub.json > rup/trust/jwt-issuer.jwks.json
# The record that HashiCorp Vault keeps for the Target: the Credential Type and the credential.
jq -n --rawfile token issuer/token.jwt '{type: "jwt", value: ($token | rtrimstr("\n"))}' > issuer/record.json
EOS
    note "issuer ${JWT_ISSUER}, audience ${TARGET}, subject ${JWT_SUBJECT}"
}

start_vault() {
    say "HashiCorp Vault, the Secret Vault"
    # As init-local-hashicorp-vault-config.sh does: file storage, not the development mode.
    cat > "${CONFIG_DIR}/hashicorp-vault/config/vault.hcl" <<EOF
ui = false
disable_mlock = true

storage "file" {
  path = "/vault/file"
}

listener "tcp" {
  address = "0.0.0.0:8200"
  tls_disable = true
}

api_addr = "http://${C_VAULT}:8200"
cluster_addr = "http://${C_VAULT}:8201"
EOF
    share hashicorp-vault/config
    docker volume create --label "${LABEL}" twi-demo-vault-file >/dev/null
    docker volume create --label "${LABEL}" twi-demo-vault-logs >/dev/null
    docker run -d --name "${C_VAULT}" --label "${LABEL}" --network "${NETWORK}" -e SKIP_CHOWN=1 -e SKIP_SETCAP=1 \
        -v "${CONFIG_DIR}/hashicorp-vault/config:/vault/config:ro" \
        -v twi-demo-vault-file:/vault/file -v twi-demo-vault-logs:/vault/logs \
        "$(image hashicorp-vault)" server >/dev/null
    wait_for 60 vault_answers || give_up "${C_VAULT}" "HashiCorp Vault did not start"

    # One unseal key and the root token; both stay in the configuration directory.
    vault_cli operator init -key-shares=1 -key-threshold=1 -format=json > "${CONFIG_DIR}/hashicorp-vault/init.json" ||
        give_up "${C_VAULT}" "HashiCorp Vault did not initialize"
    # The unseal key goes from the file to the API of Vault, never through a command line.
    quiet tool --network "${NETWORK}" -e VAULT="http://${C_VAULT}:8200" <<'EOS' || give_up "${C_VAULT}" "HashiCorp Vault did not unseal"
jq '{key: .unseal_keys_b64[0]}' hashicorp-vault/init.json | curl -fsS -X PUT --data @- "${VAULT}/v1/sys/unseal" | jq -e '.sealed == false'
EOS
    local root_token
    root_token="$(json_field hashicorp-vault/init.json '.root_token')"
    [[ -n "${root_token}" ]] || fail "HashiCorp Vault did not initialize"

    export VAULT_TOKEN="${root_token}"
    quiet vault_cli secrets enable -path=secret -version=2 kv || fail "HashiCorp Vault did not enable the secrets engine"
    quiet vault_cli_stdin kv put -mount=secret "${SECRET_PATH}" - < "${CONFIG_DIR}/issuer/record.json" ||
        fail "HashiCorp Vault did not store the JWT"
    # Each CAS Server reads the secrets of TACRA with its own token and can do nothing else.
    printf 'path "secret/data/tacra/*" {\n  capabilities = ["read"]\n}\n' |
        quiet vault_cli_stdin policy write tacra-cas-server - || fail "HashiCorp Vault did not store the policy"
    vault_cli token create -policy=tacra-cas-server -ttl=720h -display-name=est-server -field=token \
        > "${CONFIG_DIR}/est-server/vault-token" || fail "HashiCorp Vault did not create the token of the EST Server"
    vault_cli token create -policy=tacra-cas-server -ttl=720h -display-name=spire-server -field=token \
        > "${CONFIG_DIR}/spire-server/vault-token" || fail "HashiCorp Vault did not create the token of the SPIRE Server"
    unset VAULT_TOKEN
    [[ -s "${CONFIG_DIR}/est-server/vault-token" && -s "${CONFIG_DIR}/spire-server/vault-token" ]] ||
        fail "HashiCorp Vault did not create the tokens of the CAS Servers"
    note "initialized and unsealed; the JWT is the secret ${SECRET_PATH}, of Credential Type jwt"
}

endorse_platform() {
    say "The simulated platform of the Client and its Endorsements"
    local cai output
    cai="$(image tacra-cai)"
    quiet docker run --rm --user "$(id -u):$(id -g)" -v "${CONFIG_DIR}/platform:/platform" \
        --entrypoint /usr/local/bin/tacra-sim-platform "${cai}" keygen -key /platform/attestation-key.pem ||
        fail "the simulated platform did not create its Attestation Key"
    # The public half, for whoever verifies the Evidence: here, the report of the calls of CAAPI.
    quiet docker run --rm --user "$(id -u):$(id -g)" -v "${CONFIG_DIR}/platform:/platform:ro" -v "${CONFIG_DIR}/trace:/trace" \
        --entrypoint /usr/local/bin/tacra-sim-platform "${cai}" public -key /platform/attestation-key.pem \
        -out /trace/attestation-public-key.pem || fail "the simulated platform did not write its public Attestation Key"
    # The measurement of the simulated platform is the SHA-256 of the program
    # that asks for Evidence: the CAI sidecar of this image.
    MEASUREMENT="$(docker run --rm "${cai}" -measurement)"
    [[ "${MEASUREMENT}" =~ ^[0-9a-f]{64}$ ]] || fail "unexpected measurement of the CAI sidecar: ${MEASUREMENT}"
    printf '%s\n' "${MEASUREMENT}" > "${CONFIG_DIR}/platform/measurement"
    quiet docker run --rm --user "$(id -u):$(id -g)" -v "${CONFIG_DIR}/platform:/platform:ro" \
        -v "${CONFIG_DIR}/veraison/endorsements:/endorsements" \
        --entrypoint /usr/local/bin/tacra-sim-platform "${cai}" \
        endorsements -key /platform/attestation-key.pem -measurement "${MEASUREMENT}" -out /endorsements ||
        fail "the simulated platform did not write its Endorsements"
    # Veraison accepts Endorsements as a CoRIM. Its own cocli builds the CoRIM
    # from the templates and submits it: the trust anchor is the Attestation
    # Key, the Reference Value is the measurement.
    chmod 777 "${CONFIG_DIR}/veraison/endorsements"
    share veraison/endorsements
    quiet manager cocli comid create --template /endorsements/comid-trust-anchor.json \
        --template /endorsements/comid-reference-values.json --output-dir /endorsements ||
        fail "cocli did not create the CoMIDs"
    quiet manager cocli corim create --template /endorsements/corim.json \
        --comid /endorsements/comid-reference-values.cbor --comid /endorsements/comid-trust-anchor.cbor \
        --output /endorsements/corim.cbor || fail "cocli did not create the CoRIM"
    [[ -s "${CONFIG_DIR}/veraison/endorsements/corim.cbor" ]] || fail "cocli did not create the CoRIM"
    if ! wait_for 180 manager cocli corim submit --corim-file /endorsements/corim.cbor --media-type "${ENDORSEMENT_MEDIA_TYPE}"; then
        manager cocli corim submit --corim-file /endorsements/corim.cbor --media-type "${ENDORSEMENT_MEDIA_TYPE}" >&2 || true
        fail "Veraison did not accept the Endorsements"
    fi
    note "measurement ${MEASUREMENT}"
    note "Veraison holds the trust anchor and the Reference Value"
}

start_est() {
    say "EST Server (a CAS Server with the CAS Server Plug-in) and EST Client (its CAS Client)"
    local directory="${CONFIG_DIR}/est-server" healthcheck_password
    healthcheck_password="$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    cat "${CONFIG_DIR}/step-ca/root.pem" "${CONFIG_DIR}/step-ca/intermediate.pem" > "${directory}/workload-ca.pem"
    cp "${CONFIG_DIR}/step-ca/root.pem" "${directory}/step-ca-root.pem"
    cp "${CONFIG_DIR}/veraison/ca.pem" "${directory}/veraison-ca.pem"
    cp "${CONFIG_DIR}/veraison/ear-verification-key.jwk" "${directory}/veraison-ear.jwk"
    cat > "${directory}/estserver.json" <<EOF
{
  "tls": {
    "listen_address": ":8443",
    "certificates": "/etc/est/tls-cert.pem",
    "private_key": "/etc/est/tls-key.pem"
  },
  "allowed_hosts": ["${C_EST_SERVER}"],
  "credential_acquisition": {
    "ca_certs": "/etc/est/workload-ca.pem",
    "acceptable_evidence": ["${EVIDENCE_MEDIA_TYPE}"],
    "verifier": {
      "veraison": {
        "url": "https://${VERAISON_VERIFIER}:8443",
        "ca_path": "/etc/est/veraison-ca.pem",
        "ear_key_path": "/etc/est/veraison-ear.jwk",
        "evidence_media_types": ["${EVIDENCE_MEDIA_TYPE}"],
        "submods": ["PSA_IOT"]
      }
    },
    "target": {
      "${TARGET}": {
        "mode": "enroll",
        "verifiers": ["veraison"],
        "measurements": ["${MEASUREMENT}"],
        "certificate_name": "${CERTIFICATE_NAME}",
        "retrieve_credential_types": ["jwt"],
        "secret_path": "${SECRET_PATH}"
      }
    },
    "secret_vault": {
      "kind": "hashicorp",
      "url": "http://${C_VAULT}:8200",
      "token_path": "/etc/est/vault-token"
    },
    "credential_authority": {
      "kind": "step-ca",
      "url": "https://${C_STEP_CA}:9000",
      "ca_path": "/etc/est/step-ca-root.pem",
      "provisioner": "tacra",
      "provisioner_key_path": "/etc/est/provisioner-key.json"
    }
  },
  "healthcheck_password": "${healthcheck_password}",
  "rate_limit": 150,
  "timeout": 30
}
EOF
    share est-server
    share est-client
    docker run -d --name "${C_EST_SERVER}" --label "${LABEL}" --network "${NETWORK}" \
        -v "${directory}:/etc/est:ro" "$(image globalsign-est)" >/dev/null
    wait_for 30 listens "${C_EST_SERVER}" 8443 || give_up "${C_EST_SERVER}" "the EST Server did not start"
    docker run -d --name "${C_EST_CLIENT}" --label "${LABEL}" --network "${NETWORK}" \
        -e EST_CLIENT_LISTEN=:9090 -e EST_SERVER="${C_EST_SERVER}:8443" \
        -e EST_SERVER_CA=/etc/est-client/est-server-ca.pem \
        -v "${CONFIG_DIR}/est-client:/etc/est-client:ro" \
        --entrypoint /usr/local/bin/estcasclient "$(image globalsign-est)" >/dev/null
    wait_for 30 listens "${C_EST_CLIENT}" 9090 || give_up "${C_EST_CLIENT}" "the EST Client did not start"
    note "the EST Server appraises through Veraison, has step-ca issue the certificate and releases the JWT from HashiCorp Vault"
}

start_spire() {
    say "SPIRE Server (a CAS Server with the CAS Server Plug-in) and SPIRE Agent (its CAS Client)"
    local directory="${CONFIG_DIR}/spire-server" token
    cp "${CONFIG_DIR}/veraison/ca.pem" "${directory}/veraison-ca.pem"
    cp "${CONFIG_DIR}/veraison/ear-verification-key.jwk" "${directory}/veraison-ear.jwk"
    # The CA and the Agent SVID outlive any demonstration: the Server keeps the
    # bundle that it reads at "up", and a computer that sleeps must find its
    # Agent valid when it wakes. DEBUG shows the record of each enrollment.
    cat > "${directory}/server.conf" <<EOF
server {
    bind_address = "0.0.0.0"
    bind_port = "8081"
    trust_domain = "${TRUST_DOMAIN}"
    data_dir = "/var/lib/spire/server"
    log_level = "DEBUG"
    ca_ttl = "8760h"
    agent_ttl = "720h"
    default_x509_svid_ttl = "1h"

    experimental {
        credential_acquisition {
            acceptable_evidence = ["${EVIDENCE_MEDIA_TYPE}"]

            verifier "veraison" {
                url = "https://${VERAISON_VERIFIER}:8443"
                ca_path = "/etc/spire/server/veraison-ca.pem"
                ear_key_path = "/etc/spire/server/veraison-ear.jwk"
                evidence_media_types = ["${EVIDENCE_MEDIA_TYPE}"]
                submods = ["PSA_IOT"]
            }

            target "${TARGET}" {
                mode = "enroll"
                credential_types = ["x509"]
                verifiers = ["veraison"]
                measurements = ["${MEASUREMENT}"]
                retrieve_credential_types = ["jwt"]
                secret_path = "${SECRET_PATH}"
            }

            secret_vault {
                kind = "hashicorp"
                url = "http://${C_VAULT}:8200"
                token_path = "/etc/spire/server/vault-token"
            }
        }
    }
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
    share spire-server
    docker volume create --label "${LABEL}" twi-demo-spire-server-data >/dev/null
    docker run -d --name "${C_SPIRE_SERVER}" --label "${LABEL}" --network "${NETWORK}" \
        -v "${directory}:/etc/spire/server:ro" -v twi-demo-spire-server-data:/var/lib/spire/server \
        "$(image spiffe-spire-server)" -config /etc/spire/server/server.conf >/dev/null
    wait_for 60 spire_server healthcheck || give_up "${C_SPIRE_SERVER}" "the SPIRE Server did not start"

    # The Agent starts from the bundle of the Server and a join token. The same
    # bundle is what the Server of the demonstration trusts for an X509-SVID.
    spire_server bundle show > "${CONFIG_DIR}/spire-agent/bootstrap-bundle.pem" ||
        give_up "${C_SPIRE_SERVER}" "the SPIRE Server did not show its bundle"
    cp "${CONFIG_DIR}/spire-agent/bootstrap-bundle.pem" "${CONFIG_DIR}/rup/trust/spire-bundle.pem"
    token="$(spire_server token generate -spiffeID "${AGENT_ID}" | sed -n 's/^Token: //p')" ||
        give_up "${C_SPIRE_SERVER}" "the SPIRE Server issued no join token"
    [[ -n "${token}" ]] || fail "the SPIRE Server issued no join token"
    cat > "${CONFIG_DIR}/spire-agent/agent.conf" <<EOF
agent {
    data_dir = "/var/lib/spire/agent"
    log_level = "INFO"
    server_address = "${C_SPIRE_SERVER}"
    server_port = "8081"
    socket_path = "${AGENT_SOCKET}"
    trust_bundle_path = "/etc/spire/agent/bootstrap-bundle.pem"
    trust_domain = "${TRUST_DOMAIN}"
}

plugins {
    NodeAttestor "join_token" {
        plugin_data {}
    }

    KeyManager "disk" {
        plugin_data {
            directory = "/var/lib/spire/agent"
        }
    }

    WorkloadAttestor "unix" {
        plugin_data {}
    }
}
EOF
    share spire-agent
    docker volume create --label "${LABEL}" twi-demo-spire-agent-data >/dev/null
    docker volume create --label "${LABEL}" twi-demo-spire-agent-socket >/dev/null
    docker run -d --name "${C_SPIRE_AGENT}" --label "${LABEL}" --network "${NETWORK}" \
        -v "${CONFIG_DIR}/spire-agent:/etc/spire/agent:ro" -v twi-demo-spire-agent-data:/var/lib/spire/agent \
        -v twi-demo-spire-agent-socket:/tmp/spire-agent/public \
        "$(image spiffe-spire-agent)" -config /etc/spire/agent/agent.conf -joinToken "${token}" >/dev/null
    wait_for 60 spire_agent healthcheck -socketPath "${AGENT_SOCKET}" || give_up "${C_SPIRE_AGENT}" "the SPIRE Agent did not start"

    # The Workload of the registration entry is the CAI sidecar: a process of
    # user 0 in the process namespace of the Agent.
    quiet spire_server entry create -parentID "${AGENT_ID}" -spiffeID "${WORKLOAD_ID}" -selector unix:uid:0 ||
        fail "the SPIRE Server did not create the registration entry"
    note "the SPIRE Server appraises through Veraison, signs the X509-SVID with its own CA and releases the JWT from HashiCorp Vault"
    note "registration entry ${WORKLOAD_ID}"
}

start_server() {
    say "The Server, a RATS-unaware Relying Party"
    cp "${CONFIG_DIR}/est-server/workload-ca.pem" "${CONFIG_DIR}/rup/trust/step-ca.pem"
    # A request is authenticated by a certificate AND the JWT: a certificate
    # of step-ca (step 2) or an X509-SVID of the trust domain (step 1).
    cat > "${CONFIG_DIR}/rup/rup.json" <<EOF
{
  "audience": "${TARGET}",
  "clock_skew_seconds": 30,
  "accept": [["x509", "jwt"], ["wic", "jwt"]],
  "tls": {
    "cert_file": "certs/server-cert.pem",
    "key_file": "certs/server-key.pem"
  },
  "x509": {
    "ca_files": ["trust/step-ca.pem"]
  },
  "wic": {
    "ca_files": ["trust/spire-bundle.pem"],
    "uri_schemes": ["spiffe", "wimse"],
    "trust_domains": ["${TRUST_DOMAIN}"]
  },
  "jwt": {
    "issuers": ["${JWT_ISSUER}"],
    "algorithms": ["ES256", "ES384", "EdDSA", "RS256", "PS256"],
    "jwks_files": ["trust/jwt-issuer.jwks.json"],
    "public_key_files": []
  },
  "wit": {
    "issuers": [],
    "algorithms": ["ES256", "ES384", "EdDSA", "RS256", "PS256"],
    "jwks_files": [],
    "public_key_files": []
  }
}
EOF
    share rup
    share client
    docker run -d --name "${C_SERVER}" --label "${LABEL}" --network "${NETWORK}" --network-alias "${SERVER_NAME}" \
        -e RUP_CONFIG=/etc/rup/rup.json -e HTTPS_ADDR=:8443 \
        -v "${CONFIG_DIR}/rup:/etc/rup:ro" "$(image tacra-server)" >/dev/null
    wait_for 30 listens "${C_SERVER}" 8443 || give_up "${C_SERVER}" "the Server did not start"
    note "${TARGET}: accepts a certificate together with the JWT"
}

# start_sidecar NAME CAS_CLIENT PLATFORM [altered] starts a CAI sidecar toward
# the SPIRE Agent (spire) or the EST Client (est), on the simulated platform
# whose Attestation Key is in the directory PLATFORM. With "altered" the
# program of the sidecar gets one more octet at its end: it runs the same and
# its measurement is another.
start_sidecar() {
    local name="$1" cas_client="$2" platform="$3" altered="${4:-}"
    local -a run
    # The sidecar records every call of CAAPI that it makes: nothing secret crosses CAAPI.
    rm -rf "${CONFIG_DIR}/trace/${name}"
    mkdir -p "${CONFIG_DIR}/trace/${name}"
    run=(docker run -d --name "${name}" --label "${LABEL}" --network "${NETWORK}"
        -e CAI_LISTEN=:50051 -e CAI_PLATFORM=simulated -e CAI_SIM_ATTESTATION_KEY=/etc/platform/attestation-key.pem
        -e CAI_TRACE_DIR=/trace -v "${CONFIG_DIR}/trace/${name}:/trace"
        -v "${CONFIG_DIR}/${platform}:/etc/platform:ro")
    case "${cas_client}" in
        # The SPIRE Agent attests its Workload by the process that calls it:
        # the sidecar shares the process namespace and the socket of the Agent.
        spire) run+=(--pid "container:${C_SPIRE_AGENT}" -e CAAPI_ADDR="unix://${AGENT_SOCKET}"
            -v twi-demo-spire-agent-socket:/tmp/spire-agent/public:ro) ;;
        est) run+=(-e CAAPI_ADDR="${C_EST_CLIENT}:9090") ;;
        *) fail "unknown CAS Client: ${cas_client}" ;;
    esac
    if [[ "${altered}" == altered ]]; then
        run+=(--entrypoint /bin/sh "$(image tacra-cai)" -c 'cp /root/cai /tmp/cai && printf x >> /tmp/cai && exec /tmp/cai')
    else
        run+=("$(image tacra-cai)")
    fi
    "${run[@]}" >/dev/null
    wait_for 30 listens "${name}" 50051 || give_up "${name}" "the CAI sidecar ${name} did not start"
}

# start_sidecars starts one CAI sidecar for each CAS Client. Both run the same
# program on the same simulated platform, so both have the same measurement.
start_sidecars() {
    say "CAI sidecars of the Client: one toward the SPIRE Agent, one toward the EST Client"
    share platform
    start_sidecar "${C_CAI_SPIRE}" spire platform
    start_sidecar "${C_CAI_EST}" est platform
    # The Agent learns of the registration entry when it next synchronizes with the Server.
    wait_for 60 spire_agent api fetch x509 -socketPath "${AGENT_SOCKET}" ||
        give_up "${C_SPIRE_AGENT}" "the SPIRE Agent did not receive the registration entry"
    note "simulated platform, measurement ${MEASUREMENT}"
}

on_exit() {
    if [[ "${UP_STARTED}" == true && "${UP_DONE}" != true ]]; then
        printf '\nThe demonstration did not come up. What was started stays for inspection (%s status, %s logs NAME); %s down removes it.\n' \
            "${0}" "${0}" "${0}" >&2
    fi
}

cmd_up() {
    require_images
    if [[ -e "${CONFIG_DIR}/${MARKER}" ]] || [[ -n "$(docker ps -aq --filter "label=${LABEL}")" ]]; then
        say "Removing the demonstration that is already here"
        cmd_down
    fi
    UP_STARTED=true
    new_config_dir
    # The steps that follow run the images that this "up" ran.
    if [[ -n "${IMAGES}" ]]; then
        printf '%s\n%s\n' "${IMAGES}" "${IMAGE_TAG}" > "${CONFIG_DIR}/images"
    fi
    docker network create --label "${LABEL}" "${NETWORK}" >/dev/null
    start_veraison
    start_step_ca
    make_credentials
    start_vault
    endorse_platform
    start_est
    start_spire
    start_server
    start_sidecars
    UP_DONE=true
    cat <<EOF

The demonstration is up.

  Step 1   Client -> CAI sidecar -> SPIRE Agent -> SPIRE Server -> Veraison, CA of SPIRE, HashiCorp Vault
  Step 2   Client -> CAI sidecar -> EST Client  -> EST Server   -> Veraison, step-ca,     HashiCorp Vault
  Both     Client -> Server at ${TARGET}, with the certificate and the JWT

  Configuration: ${CONFIG_DIR}

Next:
  ${0} step1
  ${0} step2
  ${0} refusals
  ${0} down
EOF
}

# run_client runs the Client once against a CAI sidecar and prints what it
# prints; its status is the status of the Client.
run_client() {
    local sidecar="$1"
    docker rm -f "${C_CLIENT}" >/dev/null 2>&1 || true
    docker run --rm --name "${C_CLIENT}" --label "${LABEL}" --network "${NETWORK}" \
        -e CAI_ADDR="${sidecar}:50051" -e RUP_CA_FILE=/etc/client/server-ca.pem \
        -v "${CONFIG_DIR}/client:/etc/client:ro" "$(image tacra-client)" "${TARGET}" 2>&1 |
        while IFS= read -r line; do
            if [[ -n "${line}" ]]; then
                told Client "${line}"
            fi
        done
}

# calls SIDECAR prints how many calls of CAAPI a sidecar has recorded.
calls() {
    local n=0 file
    for file in "${CONFIG_DIR}/trace/$1"/*.json; do
        if [[ -e "${file}" ]]; then
            n=$((n + 1))
        fi
    done
    printf '%s' "${n}"
}

# wire SIDECAR AFTER prints what crossed CAAPI in the calls that a sidecar made
# after its first AFTER calls, and checks it from the outside: the signature
# of the Evidence under the Attestation Key of the platform, and the nonce of
# the Evidence against the binding value computed from the request. Its status
# says whether the checks held.
wire() {
    told CAAPI "the calls of the CAI sidecar to its CAS Client, as the sidecar recorded them"
    docker run --rm -v "${CONFIG_DIR}/trace:/trace:ro" --entrypoint /usr/local/bin/caapi-trace "$(image tacra-cai)" \
        -after "$2" -attestation-key /trace/attestation-public-key.pem \
        -reference-measurement "$(cat "${CONFIG_DIR}/platform/measurement")" \
        -indent "                  " "/trace/$1"
}

# record NAME CONTAINER LINES prints what a CAS Server wrote to its log after
# the first LINES lines about acquisitions: what it issued, released or
# refused, one line for each record. With --raw the lines are printed as the
# CAS Server wrote them.
record() {
    local name="$1" container="$2" lines="$3" line measurement shown=""
    docker logs "${container}" 2>&1 | tail -n "+$((lines + 1))" |
        grep -E 'Enrolled an attested X509-SVID|Certificate issued by the Credential Authority|Credential released from the Secret Vault|Attestation Results refused|remote attestation failed' |
        while IFS= read -r line; do
            if [[ "${RAW}" == true ]]; then
                printf '%s\n' "${line}"
                continue
            fi
            # The measurement of the Evidence, once for each step.
            measurement="$(field measurement "${line}")"
            if [[ -n "${measurement}" && "${measurement}" != "${shown}" ]]; then
                shown="${measurement}"
                measurement="measurement ${measurement}"
            else
                measurement=""
            fi
            case "${line}" in
                *'Enrolled an attested X509-SVID'*)
                    told "${name}" "Evidence affirmed by $(field verifier "${line}"); X509-SVID issued, valid until $(field expiration "${line}")" "${measurement}" ;;
                *'Certificate issued by the Credential Authority'*)
                    told "${name}" "Evidence affirmed by $(field verifier "${line}"); certificate issued by the Credential Authority for $(field name "${line}")" "${measurement}" ;;
                *'Credential released from the Secret Vault'*)
                    told "${name}" "Evidence affirmed by $(field verifier "${line}"); $(field type "${line}") released from the Secret Vault" "${measurement}" ;;
                *'Attestation Results refused'*)
                    told "${name}" "refused: $(field error "${line}")" ;;
                *'remote attestation failed'*)
                    : ;; # the same refusal as the API of the SPIRE Server logs it
                *)
                    printf '%s\n' "${line}" ;;
            esac
        done || true
}

# server_record LINES prints what the Server wrote to its log after the first LINES lines.
server_record() {
    local line
    docker logs "${C_SERVER}" 2>&1 | tail -n "+$(($1 + 1))" |
        while IFS= read -r line; do
            if [[ "${RAW}" == true ]]; then
                printf '%s\n' "${line}"
            else
                told Server "$(printf '%s\n' "${line}" |
                    sed -E 's/^Received authenticated request\. Formats: (\[[^]]*\]), subject: "([^"]*)".*/accepted the request: formats \1, subject \2/')"
            fi
        done || true
}

# run_step runs the Client once and prints what the CAS Server and the Server
# recorded for that run, from their own logs.
run_step() {
    local number="$1" title="$2" sidecar="$3" cas_server="$4" cas_server_name="$5"
    require_running
    say "Step ${number}: ${title}"
    local rc=0 checked=0 cas_server_lines server_lines before
    cas_server_lines="$(log_lines "${cas_server}")"
    server_lines="$(log_lines "${C_SERVER}")"
    before="$(calls "${sidecar}")"
    printf '\n'
    run_client "${sidecar}" || rc=$?
    wire "${sidecar}" "${before}" || checked=$?
    record "${cas_server_name}" "${cas_server}" "${cas_server_lines}"
    server_record "${server_lines}"
    [[ ${rc} -eq 0 ]] || fail "step ${number} did not pass: the Client ended with status ${rc}"
    [[ ${checked} -eq 0 ]] || fail "step ${number} did not pass: a check of the recorded calls did not hold"
    printf '\nStep %s passed.\n' "${number}"
}

# refused runs the Client against a CAI sidecar that must get nothing, through
# one CAS Server, and counts a Client that got its credentials as a failure.
refused() {
    local sidecar="$1" cas_server="$2" cas_server_name="$3"
    local rc=0 cas_server_lines before
    cas_server_lines="$(log_lines "${cas_server}")"
    before="$(calls "${sidecar}")"
    printf '\n'
    run_client "${sidecar}" || rc=$?
    # The report says what in the Evidence is not as the Verifier holds it; here that is the point.
    wire "${sidecar}" "${before}" 2>/dev/null || true
    record "${cas_server_name}" "${cas_server}" "${cas_server_lines}"
    if [[ ${rc} -eq 0 ]]; then
        NOT_REFUSED=$((NOT_REFUSED + 1))
        printf 'NOT REFUSED: the Client got its credentials.\n'
    fi
}

# jwt_alone prints the HTTP status of the Server for a request that carries
# the JWT and no certificate.
jwt_alone() {
    tool --network "${NETWORK}" -e TARGET="${TARGET}" <<'EOS'
curl -sS -o /dev/null -w '%{http_code}' --cacert client/server-ca.pem \
    -H "Authorization: Bearer $(cat issuer/token.jwt)" "${TARGET}/?message=the-JWT-alone"
EOS
}

cmd_refusals() {
    require_running
    NOT_REFUSED=0
    local status
    docker rm -f twi-demo-refusal-spire twi-demo-refusal-est >/dev/null 2>&1 || true

    say "Refusal 1: another program. One octet more in the CAI sidecar: its measurement is not the Reference Value"
    start_sidecar twi-demo-refusal-spire spire platform altered
    start_sidecar twi-demo-refusal-est est platform altered
    refused twi-demo-refusal-spire "${C_SPIRE_SERVER}" "SPIRE Server"
    refused twi-demo-refusal-est "${C_EST_SERVER}" "EST Server"
    docker rm -f twi-demo-refusal-spire twi-demo-refusal-est >/dev/null

    say "Refusal 2: another platform. An Attestation Key for which the Verifier holds no trust anchor"
    rm -rf "${CONFIG_DIR}/platform-unknown"
    mkdir -p "${CONFIG_DIR}/platform-unknown"
    quiet docker run --rm --user "$(id -u):$(id -g)" -v "${CONFIG_DIR}/platform-unknown:/platform" \
        --entrypoint /usr/local/bin/tacra-sim-platform "$(image tacra-cai)" keygen -key /platform/attestation-key.pem ||
        fail "the simulated platform did not create an Attestation Key"
    share platform-unknown
    start_sidecar twi-demo-refusal-spire spire platform-unknown
    start_sidecar twi-demo-refusal-est est platform-unknown
    refused twi-demo-refusal-spire "${C_SPIRE_SERVER}" "SPIRE Server"
    refused twi-demo-refusal-est "${C_EST_SERVER}" "EST Server"
    docker rm -f twi-demo-refusal-spire twi-demo-refusal-est >/dev/null
    rm -rf "${CONFIG_DIR}/platform-unknown"

    say "Refusal 3: the JWT alone. A request to the Server with the JWT and no certificate"
    status="$(jwt_alone)" || status="no answer"
    printf '\n'
    told Server "answered HTTP ${status}"
    if [[ "${status}" == 200 ]]; then
        NOT_REFUSED=$((NOT_REFUSED + 1))
        printf 'NOT REFUSED: the Server accepted the JWT alone.\n'
    fi

    [[ ${NOT_REFUSED} -eq 0 ]] || fail "${NOT_REFUSED} of 5 requests were not refused"
    printf '\nAll 5 requests were refused.\n'
}

# cmd_push tags the images that this workspace built under the prefix of
# --images, for this platform, and pushes them: whoever runs "up --images" with
# the same prefix gets the demonstration with no workspace and no build.
cmd_push() {
    [[ -n "${IMAGES}" ]] || fail "push needs --images PREFIX: where the images go"
    local name source prefix="${IMAGES}"
    say "Images to ${prefix}"
    for name in ${IMAGE_NAMES}; do
        IMAGES=""
        source="$(image "${name}")"
        IMAGES="${prefix}"
        image_exists "${source}" || fail "missing image: ${source}; run: ${0} build"
        docker tag "${source}" "$(image "${name}")"
        quiet docker push "$(image "${name}")" || fail "cannot push $(image "${name}")"
        note "$(image "${name}")"
    done
}

cmd_status() {
    local container state
    for container in ${SERVICES}; do
        state="$(docker inspect -f '{{.State.Status}}' "${container}" 2>/dev/null || true)"
        printf '%-24s %s\n' "${container}" "${state:-not created}"
    done
}

cmd_logs() {
    [[ -n "${LOG_COMPONENT}" ]] || fail "name a component, one of: ${SERVICES//twi-demo-/}"
    docker logs "twi-demo-${LOG_COMPONENT#twi-demo-}"
}

cmd_down() {
    local ids
    ids="$(docker ps -aq --filter "label=${LABEL}")"
    if [[ -n "${ids}" ]]; then
        # shellcheck disable=SC2086 # one identifier for each word
        docker rm -f ${ids} >/dev/null
    fi
    ids="$(docker volume ls -q --filter "label=${LABEL}")"
    if [[ -n "${ids}" ]]; then
        # shellcheck disable=SC2086
        docker volume rm ${ids} >/dev/null
    fi
    if docker network inspect "${NETWORK}" >/dev/null 2>&1; then
        docker network rm "${NETWORK}" >/dev/null
    fi
    if [[ -f "${CONFIG_DIR}/${MARKER}" ]]; then
        rm -rf "${CONFIG_DIR}"
    fi
    printf 'The demonstration is removed.\n'
}

step1() {
    run_step 1 "the Client acquires an X.509 certificate and a JWT through SPIRE" "${C_CAI_SPIRE}" "${C_SPIRE_SERVER}" "SPIRE Server"
}

step2() {
    run_step 2 "the Client acquires an X.509 certificate and a JWT through EST" "${C_CAI_EST}" "${C_EST_SERVER}" "EST Server"
}

parse_args() {
    [[ $# -gt 0 ]] || { usage; exit 1; }
    case "$1" in
        -h|--help) usage; exit 0 ;;
    esac
    ACTION="$1"
    shift
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --config-dir) CONFIG_DIR="${2:?missing value for --config-dir}"; shift 2 ;;
            --platform) PLATFORM="${2:?missing value for --platform}"; shift 2 ;;
            --raw) RAW=true; shift ;;
            --images) IMAGES="${2:?missing value for --images}"; IMAGES="${IMAGES%/}"; shift 2 ;;
            --tag) IMAGE_TAG="${2:?missing value for --tag}"; shift 2 ;;
            -h|--help) usage; exit 0 ;;
            -*) fail "unknown option: $1" ;;
            *)
                [[ "${ACTION}" == logs && -z "${LOG_COMPONENT}" ]] || fail "unexpected argument: $1"
                LOG_COMPONENT="$1"; shift ;;
        esac
    done
    case "${ACTION}" in workspace|build|up|step1|step2|refusals|all|status|logs|down|push) ;; *) fail "unknown command: ${ACTION}" ;; esac
    [[ "${CONFIG_DIR}" == /* ]] || fail "the configuration directory must be an absolute path: ${CONFIG_DIR}"
}

main() {
    parse_args "$@"
    detect_platform
    if [[ "${ACTION}" == workspace ]]; then
        cmd_workspace
        return
    fi
    require_docker
    trap on_exit EXIT
    case "${ACTION}" in
        step1|step2|refusals)
            if [[ -z "${IMAGES}" && -f "${CONFIG_DIR}/images" ]]; then
                IMAGES="$(sed -n 1p "${CONFIG_DIR}/images")"
                IMAGE_TAG="$(sed -n 2p "${CONFIG_DIR}/images")"
            fi
            ;;
    esac
    case "${ACTION}" in
        build) cmd_build ;;
        up) cmd_up ;;
        step1) step1 ;;
        step2) step2 ;;
        refusals) cmd_refusals ;;
        all)
            if [[ -z "${IMAGES}" ]]; then
                cmd_build
            fi
            cmd_up
            step1
            step2
            cmd_refusals
            ;;
        push) cmd_push ;;
        status) cmd_status ;;
        logs) cmd_logs ;;
        down) cmd_down ;;
    esac
}

main "$@"
