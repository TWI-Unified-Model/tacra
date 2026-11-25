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
# Nothing here is a production default. Every key, certificate and token is
# created for one run, kept in a directory that Git ignores, and removed by
# "down". No port is published on the host.
set -euo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly TACRA_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
readonly WORKSPACE_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
readonly VERAISON_DIR="${WORKSPACE_ROOT}/veraison-services/deployments/docker"

readonly NETWORK="twi-demo"
readonly VERAISON_NETWORK="veraison-net"
readonly VERAISON_VERIFIER="verification-service"
readonly LABEL="twi.demo=simulation"
readonly MARKER=".twi-demo"

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
readonly SERVICES="${C_STEP_CA} ${C_VAULT} ${C_EST_SERVER} ${C_EST_CLIENT} ${C_SPIRE_SERVER} ${C_SPIRE_AGENT} ${C_SERVER} ${C_CAI_SPIRE} ${C_CAI_EST}"

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
UP_STARTED=false
UP_DONE=false
MEASUREMENT=""
NOT_REFUSED=0

usage() {
    cat <<'EOF'
Usage:
  tacra/deploy/demo.sh <build|up|step1|step2|refusals|status|logs|down> [options]

Commands:
  build    Build the images of the workspace (components.sh build) and the
           images of the Client, the CAI sidecar and the Server.
  up       Create the configuration and start everything. A demonstration
           that is already up is removed first.
  step1    Step 1: the Client acquires an X.509 certificate and a JWT through
           SPIRE and authenticates with both to the Server.
  step2    Step 2: the same through EST.
  refusals Show what is refused: a CAI sidecar with another measurement, a
           platform that the Verifier does not know, and the JWT alone.
  status   Show the state of every container.
  logs     Print the log of one component, for example: logs spire-server
  down     Remove the containers, volumes, network and configuration.

Options:
  --config-dir PATH    Directory of the generated configuration
                       (default: tacra/deploy/config/demo, ignored by Git).
  --platform PLATFORM  Docker platform, such as linux/arm64 (default: this host).
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
        -v "${CONFIG_DIR}:/demo" -w /demo --entrypoint /bin/bash "$(image_tag step-ca)" -euo pipefail -c "${script}"
}

# json_field FILE FILTER prints one field of a JSON file of the configuration
# directory, with the jq of the step-ca image.
json_field() {
    docker run --rm --user "$(id -u):$(id -g)" -v "${CONFIG_DIR}:/demo:ro" -w /demo \
        --entrypoint jq "$(image_tag step-ca)" -r "$2" "$1"
}

# log_lines prints how many lines the log of a container has, so that a later
# call can print only what the container wrote after this point.
log_lines() { docker logs "$1" 2>&1 | wc -l | tr -d ' '; }

# manager runs a command of the Veraison manager image, the image behind the
# cocli command of the Veraison deployment, with the Endorsements at /endorsements.
manager() {
    docker run --rm --network "${VERAISON_NETWORK}" \
        -v "${CONFIG_DIR}/veraison/endorsements:/endorsements" veraison/manager "$@"
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
    local image
    for image in step-ca hashicorp-vault globalsign-est spiffe-spire-server spiffe-spire-agent tacra-cai tacra-client tacra-server; do
        image_exists "$(image_tag "${image}")" || fail "missing image: $(image_tag "${image}"); run: ${0} build"
    done
    image_exists veraison/manager || fail "missing image: veraison/manager; run: ${0} build"
    docker container inspect "${VERAISON_VERIFIER}" >/dev/null 2>&1 || fail "Veraison is not deployed; run: ${0} build"
    docker run --rm --entrypoint /bin/sh "$(image_tag globalsign-est)" -c 'test -x /usr/local/bin/estcasclient' ||
        fail "the image $(image_tag globalsign-est) holds no EST Client: check out the branch of the demonstration in globalsign-est, then run: ${0} build"
}

require_running() {
    local container
    for container in ${SERVICES} "${VERAISON_VERIFIER}"; do
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
        spire-server spire-agent rup/certs rup/trust client; do
        mkdir -p "${CONFIG_DIR}/${directory}"
    done
}

# veraison_key asks the Verifier for the key that verifies its Attestation
# Results; the Verifier publishes that key once it is ready.
veraison_key() {
    tool --network "${VERAISON_NETWORK}" -e VERIFIER="${VERAISON_VERIFIER}" <<'EOS'
curl -fsS --cacert veraison/ca.pem "https://${VERIFIER}:8443/.well-known/veraison/verification" > veraison/discovery.json
jq -e -c 'select(."service-state" == "READY") | ."ear-verification-key"' veraison/discovery.json > veraison/ear-verification-key.jwk
EOS
}

start_veraison() {
    say "Veraison, the Verifier"
    docker network inspect "${VERAISON_NETWORK}" >/dev/null 2>&1 || fail "the network ${VERAISON_NETWORK} of Veraison is missing; run: ${0} build"
    if ! is_running "${VERAISON_VERIFIER}"; then
        : > "${CONFIG_DIR}/veraison/started-by-this-demonstration"
    fi
    quiet "${VERAISON_DIR}/veraison" start || fail "Veraison did not start"
    cp "${VERAISON_DIR}/src/certs/rootCA.crt" "${CONFIG_DIR}/veraison/ca.pem"
    wait_for 120 veraison_key || give_up "${VERAISON_VERIFIER}" "the Verifier did not become ready"
    note "ready; the key of its Attestation Results is in veraison/ear-verification-key.jwk"
}

start_step_ca() {
    say "step-ca, the Credential Authority behind the EST Server"
    local image
    image="$(image_tag step-ca)"
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
        "$(image_tag hashicorp-vault)" server >/dev/null
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
    cai="$(image_tag tacra-cai)"
    quiet docker run --rm --user "$(id -u):$(id -g)" -v "${CONFIG_DIR}/platform:/platform" \
        --entrypoint /usr/local/bin/tacra-sim-platform "${cai}" keygen -key /platform/attestation-key.pem ||
        fail "the simulated platform did not create its Attestation Key"
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
    # Veraison takes Endorsements as a CoRIM. Its own cocli builds the CoRIM
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
    if ! wait_for 60 manager cocli corim submit --corim-file /endorsements/corim.cbor --media-type "${ENDORSEMENT_MEDIA_TYPE}"; then
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
    docker create --name "${C_EST_SERVER}" --label "${LABEL}" --network "${NETWORK}" \
        -v "${directory}:/etc/est:ro" "$(image_tag globalsign-est)" >/dev/null
    docker network connect "${VERAISON_NETWORK}" "${C_EST_SERVER}"
    docker start "${C_EST_SERVER}" >/dev/null
    wait_for 30 listens "${C_EST_SERVER}" 8443 || give_up "${C_EST_SERVER}" "the EST Server did not start"
    docker run -d --name "${C_EST_CLIENT}" --label "${LABEL}" --network "${NETWORK}" \
        -e EST_CLIENT_LISTEN=:9090 -e EST_SERVER="${C_EST_SERVER}:8443" \
        -e EST_SERVER_CA=/etc/est-client/est-server-ca.pem \
        -v "${CONFIG_DIR}/est-client:/etc/est-client:ro" \
        --entrypoint /usr/local/bin/estcasclient "$(image_tag globalsign-est)" >/dev/null
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
    docker create --name "${C_SPIRE_SERVER}" --label "${LABEL}" --network "${NETWORK}" \
        -v "${directory}:/etc/spire/server:ro" -v twi-demo-spire-server-data:/var/lib/spire/server \
        "$(image_tag spiffe-spire-server)" -config /etc/spire/server/server.conf >/dev/null
    docker network connect "${VERAISON_NETWORK}" "${C_SPIRE_SERVER}"
    docker start "${C_SPIRE_SERVER}" >/dev/null
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
        "$(image_tag spiffe-spire-agent)" -config /etc/spire/agent/agent.conf -joinToken "${token}" >/dev/null
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
        -v "${CONFIG_DIR}/rup:/etc/rup:ro" "$(image_tag tacra-server)" >/dev/null
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
    run=(docker run -d --name "${name}" --label "${LABEL}" --network "${NETWORK}"
        -e CAI_LISTEN=:50051 -e CAI_PLATFORM=simulated -e CAI_SIM_ATTESTATION_KEY=/etc/platform/attestation-key.pem
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
        run+=(--entrypoint /bin/sh "$(image_tag tacra-cai)" -c 'cp /root/cai /tmp/cai && printf x >> /tmp/cai && exec /tmp/cai')
    else
        run+=("$(image_tag tacra-cai)")
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

# run_client runs the Client once against a CAI sidecar; its status is the status of the Client.
run_client() {
    local sidecar="$1"
    docker rm -f "${C_CLIENT}" >/dev/null 2>&1 || true
    docker run --rm --name "${C_CLIENT}" --label "${LABEL}" --network "${NETWORK}" \
        -e CAI_ADDR="${sidecar}:50051" -e RUP_CA_FILE=/etc/client/server-ca.pem \
        -v "${CONFIG_DIR}/client:/etc/client:ro" "$(image_tag tacra-client)" "${TARGET}"
}

# record CONTAINER LINES prints what a CAS Server wrote to its log after the
# first LINES lines about acquisitions: what it issued, released or refused.
record() {
    docker logs "$1" 2>&1 | tail -n "+$(($2 + 1))" |
        grep -E 'Enrolled an attested X509-SVID|Certificate issued by the Credential Authority|Credential released from the Secret Vault|Attestation Results refused|remote attestation failed' || true
}

# run_step runs the Client once and prints what the CAS Server and the Server
# recorded for that run, from their own logs.
run_step() {
    local number="$1" title="$2" sidecar="$3" cas_server="$4" cas_server_name="$5"
    require_running
    say "Step ${number}: ${title}"
    local rc=0 cas_server_lines server_lines
    cas_server_lines="$(log_lines "${cas_server}")"
    server_lines="$(log_lines "${C_SERVER}")"
    printf -- '-- the Client (%s %s)\n' "$(image_tag tacra-client)" "${TARGET}"
    run_client "${sidecar}" || rc=$?
    printf -- '-- the record of the %s\n' "${cas_server_name}"
    record "${cas_server}" "${cas_server_lines}"
    printf -- '-- the record of the Server\n'
    docker logs "${C_SERVER}" 2>&1 | tail -n "+$((server_lines + 1))"
    [[ ${rc} -eq 0 ]] || fail "step ${number} did not pass: the Client ended with status ${rc}"
    printf '\nStep %s passed.\n' "${number}"
}

# refused runs the Client against a CAI sidecar that must get nothing, through
# one CAS Server, and counts a Client that got its credentials as a failure.
refused() {
    local sidecar="$1" cas_server="$2" cas_server_name="$3"
    local rc=0 cas_server_lines
    cas_server_lines="$(log_lines "${cas_server}")"
    printf -- '-- the Client, through the %s\n' "${cas_server_name}"
    run_client "${sidecar}" || rc=$?
    printf -- '-- the record of the %s\n' "${cas_server_name}"
    record "${cas_server}" "${cas_server_lines}"
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
        --entrypoint /usr/local/bin/tacra-sim-platform "$(image_tag tacra-cai)" keygen -key /platform/attestation-key.pem ||
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
    printf -- '-- the Server answered: HTTP %s\n' "${status}"
    if [[ "${status}" == 200 ]]; then
        NOT_REFUSED=$((NOT_REFUSED + 1))
        printf 'NOT REFUSED: the Server accepted the JWT alone.\n'
    fi

    [[ ${NOT_REFUSED} -eq 0 ]] || fail "${NOT_REFUSED} of 5 requests were not refused"
    printf '\nAll 5 requests were refused.\n'
}

cmd_status() {
    local container state
    for container in ${SERVICES} vts-service provisioning-service "${VERAISON_VERIFIER}"; do
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
    # Veraison is stopped only if this demonstration started it. Its stores keep
    # the Endorsements of the simulated platform.
    if [[ -f "${CONFIG_DIR}/veraison/started-by-this-demonstration" ]]; then
        quiet "${VERAISON_DIR}/veraison" stop || true
    fi
    if [[ -f "${CONFIG_DIR}/${MARKER}" ]]; then
        rm -rf "${CONFIG_DIR}"
    fi
    printf 'The demonstration is removed.\n'
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
            -h|--help) usage; exit 0 ;;
            -*) fail "unknown option: $1" ;;
            *)
                [[ "${ACTION}" == logs && -z "${LOG_COMPONENT}" ]] || fail "unexpected argument: $1"
                LOG_COMPONENT="$1"; shift ;;
        esac
    done
    case "${ACTION}" in build|up|step1|step2|refusals|status|logs|down) ;; *) fail "unknown command: ${ACTION}" ;; esac
    [[ "${CONFIG_DIR}" == /* ]] || fail "the configuration directory must be an absolute path: ${CONFIG_DIR}"
}

main() {
    parse_args "$@"
    detect_platform
    require_docker
    trap on_exit EXIT
    case "${ACTION}" in
        build) cmd_build ;;
        up) cmd_up ;;
        step1) run_step 1 "the Client acquires an X.509 certificate and a JWT through SPIRE" "${C_CAI_SPIRE}" "${C_SPIRE_SERVER}" "SPIRE Server" ;;
        step2) run_step 2 "the Client acquires an X.509 certificate and a JWT through EST" "${C_CAI_EST}" "${C_EST_SERVER}" "EST Server" ;;
        refusals) cmd_refusals ;;
        status) cmd_status ;;
        logs) cmd_logs ;;
        down) cmd_down ;;
    esac
}

main "$@"
