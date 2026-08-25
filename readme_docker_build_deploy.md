# Docker Build and Deployment

This document explains how to build Docker images for all TWI stack components and deploy them locally or to remote hosts.

## Overview

Twium provides a unified deployment dispatcher (`components.sh`) that builds and deploys all trusted-workload-identity (TWI) stack components from source. The script manages:

- **globalsign-est**: RFC 7030 EST server for certificate enrollment
- **hashicorp-vault**: Secrets and identity management platform
- **spiffe-spire**: Workload identity and SVID issuance (server + agent)
- **step-ca**: Online CA for TLS/SSH/ACME certificates
- **veraison-services**: Attestation verification services

**Note:** `twium` itself is a schema/protobuf project and `veraison-apiclient` is a client library—neither is deployed as a service.

## Prerequisites

### Docker Installation

**macOS:**
1. Install Docker Desktop from [docker.com](https://www.docker.com/products/docker-desktop)
2. Start Docker Desktop from Applications
3. Verify Docker is running: `docker info`

**Ubuntu/Linux:**
```bash
# Install Docker Engine
sudo apt-get update
sudo apt-get install -y docker.io docker-compose-plugin

# Add your user to the docker group (requires logout/login)
sudo usermod -aG docker $USER
newgrp docker  # Or logout and login again

# Verify Docker access
docker info
```

### File Sharing (macOS Only)

For Docker Desktop on macOS, ensure the workspace directory is shared:
1. Open Docker Desktop → Settings → Resources → File sharing
2. Add `/Users/sudsadmin/Downloads/vscode_worspaces/twi-unified-model`
3. Add the parent directory of your `DEPLOY_CONFIG_DIR` if using an external config location

## The components.sh Deployment Script

### Location

```
./twium/deploy/components.sh
```

Run from workspace root: `/Users/sudsadmin/Downloads/vscode_worspaces/twi-unified-model`

### Usage

```bash
./twium/deploy/components.sh <build|deploy|stop|status> [options]
```

### Commands

| Command | Description |
|---------|-------------|
| `build` | Build Docker images from source for selected components |
| `deploy` | Build (unless `--no-build`) and start containers |
| `stop` | Stop running containers |
| `status` | Show container status |

### Options

| Option | Description | Example |
|--------|-------------|---------|
| `--components LIST` | Comma-separated component list or `all` (default: `all`) | `--components globalsign-est,step-ca` |
| `--no-build LIST` | Reuse existing images for listed components during deploy | `--no-build hashicorp-vault` |
| `--config-dir PATH` | Runtime configuration directory | `--config-dir "$HOME/twi-config"` |
| `--platform PLATFORM` | Docker platform (auto-detected by default) | `--platform linux/amd64` |
| `--docker-host ENDPOINT` | Remote Docker daemon endpoint | `--docker-host ssh://user@vm.example` |
| `--dry-run` | Print commands without executing | `--dry-run` |
| `-h, --help` | Show help message | `-h` |

### Component List

Valid components:
- `globalsign-est`
- `hashicorp-vault`
- `spiffe-spire`
- `step-ca`
- `veraison-services`

Or use `all` to select all components.

## Source Builds and Docker Images

All images are built from the checked-out workspace source code. The dispatcher never silently pulls published application images.

### Image Tags and Build Definitions

| Component | Dockerfile Location | Local Image Tag | Container Name | Ports |
|-----------|---------------------|-----------------|----------------|-------|
| globalsign-est | `globalsign-est/Dockerfile` | `twi/globalsign-est:local-<platform>` | `twi-globalsign-est` | 8443 |
| hashicorp-vault | `hashicorp-vault/scripts/docker/Dockerfile` | `twi/hashicorp-vault:local-<platform>` | `twi-hashicorp-vault` | 8200, 8201 |
| spiffe-spire | `spiffe-spire/Dockerfile` (multi-stage) | `twi/spiffe-spire-server:local-<platform>`, `twi/spiffe-spire-agent:local-<platform>` | `twi-spire-server`, `twi-spire-agent` | 8081 |
| step-ca | `step-ca/docker/Dockerfile` | `twi/step-ca:local-<platform>` | `twi-step-ca` | 9000 |
| veraison-services | Uses existing `make docker-deploy` | Project-owned `veraison/*` images | Multiple containers | Various |

### Platform Auto-Detection

The script automatically detects your platform:
- Apple Silicon (M1/M2/M3): `linux/arm64`
- Intel/AMD x86_64: `linux/amd64`

Override with `--platform` when building for remote deployment (e.g., building ARM images on an Intel Mac for transfer to an ARM VM).

## Configuration Management

Runtime configuration, certificates, keys, and passwords are **intentionally external** to the repository.

### Configuration Directory Structure

Set via `--config-dir` or environment variable `DEPLOY_CONFIG_DIR`:

```bash
export DEPLOY_CONFIG_DIR="/path/to/config"
```

**Default:** `twium/deploy/config` (not recommended for actual secrets)

**Recommended for local dev:** `twium/deploy/config/local` (gitignored)

### Expected Directory Layout

```
<config-dir>/
├── globalsign-est/
│   ├── estserver.json
│   └── certs/
│       ├── ca-certificates.pem
│       ├── ca-key.pem
│       ├── server-certificates.pem
│       ├── server-key.pem
│       └── client-ca.pem
├── hashicorp-vault/
│   └── config/
│       └── vault.hcl
├── spiffe-spire/
│   ├── server.conf
│   └── agent.conf              # Optional; starts local agent if present
└── step-ca/
    ├── config/
    │   └── ca.json
    └── secrets/
        └── password
```

See `deploy/config/README.md` for full configuration details.

## Local EST Configuration: init-local-est-config.sh

### Purpose

The `init-local-est-config.sh` script generates a **complete local development configuration** for the GlobalSign EST server, including:

- Mock CA certificate and private key (30-day validity)
- EST server TLS certificate and private key
- Client CA certificate for mTLS
- `estserver.json` configuration file with random health-check password

### Usage

```bash
export DEPLOY_CONFIG_DIR="$PWD/twium/deploy/config/local"
./twium/deploy/init-local-est-config.sh
```

### What It Creates

```
twium/deploy/config/local/globalsign-est/
├── estserver.json                    # EST server configuration
└── certs/
    ├── ca-certificates.pem           # Mock CA certificate
    ├── ca-key.pem                    # Mock CA private key
    ├── server-certificates.pem       # EST server TLS certificate
    ├── server-key.pem                # EST server TLS private key
    └── client-ca.pem                 # Client CA for mTLS
```

### Safety Features

- **Idempotent:** Refuses to overwrite existing configuration
- **Local-only:** All artifacts are generated with 30-day validity
- **Password Generation:** Creates a random health-check password
- **Gitignored:** `config/local/` is excluded via `.gitignore`

### Security Warnings

⚠️ **For local development only**. The GlobalSign `estserver` uses `internal/mockca` and is explicitly labeled non-production by upstream.

- Never use these certificates in production
- Never commit generated secrets to Git
- Rotate local configuration periodically

## Component-Specific Dockerfiles

### globalsign-est Dockerfile

**Location:** `globalsign-est/Dockerfile`

```dockerfile
ARG GO_VERSION=1.26.5

FROM golang:${GO_VERSION}-alpine AS builder
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/estserver ./cmd/estserver

FROM alpine:3.22
RUN addgroup -S est && adduser -S -G est est
COPY --from=builder /out/estserver /usr/local/bin/estserver
USER est
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/estserver"]
CMD ["-config", "/etc/est/estserver.json"]
```

**Key Features:**
- Multi-stage build to minimize image size (final: ~16 MB)
- CGO disabled for static binary
- Non-root `est` user for security
- Configuration mounted at `/etc/est/`

### hashicorp-vault Dockerfile

**Location:** `hashicorp-vault/scripts/docker/Dockerfile`

**Special Consideration:** Vault's build process requires Git metadata for version embedding and tool installation. The `.dockerignore` originally excluded `.git`, causing build failures. **This has been fixed** by removing `.git` from `.dockerignore`.

The Dockerfile runs `make bootstrap` which:
1. Installs internal/external Go tools
2. Uses `git rev-parse` to find the repository root
3. Embeds Git commit hash into the binary

### spiffe-spire Dockerfile

**Location:** `spiffe-spire/Dockerfile` (root of spiffe-spire repo)

Multi-stage build producing two images:
- `twi/spiffe-spire-server:local-<platform>` - SPIRE server
- `twi/spiffe-spire-agent:local-<platform>` - SPIRE agent

### step-ca Dockerfile

**Location:** `step-ca/docker/Dockerfile`

Builds the `step-ca` binary and sets up the CA environment. The mounted configuration directory is read-write because step-ca maintains state in `/home/step`.

### veraison-services

Uses the existing Veraison project's own `make docker-deploy` workflow. The dispatcher invokes this for veraison-services instead of building a custom image.

## Deployment Workflows

### 1. Local Development Deployment

Build and deploy all components with local configuration:

```bash
# Set up local EST configuration (one-time)
export DEPLOY_CONFIG_DIR="$PWD/twium/deploy/config/local"
./twium/deploy/init-local-est-config.sh

# Build and deploy all components
./twium/deploy/components.sh deploy --components all
```

### 2. Build Specific Components

```bash
./twium/deploy/components.sh build --components globalsign-est,step-ca
```

### 3. Deploy Without Rebuilding

If images already exist:

```bash
./twium/deploy/components.sh deploy --components all \
    --no-build globalsign-est,step-ca
```

### 4. Cross-Platform Build (for VM deployment)

Build AMD64 images on Apple Silicon for an x86_64 VM:

```bash
./twium/deploy/components.sh build --components all \
    --platform linux/amd64
```

### 5. Remote Deployment

Deploy to a remote Docker daemon via SSH:

```bash
# Option 1: Build locally and transfer
docker save twi/globalsign-est:local-linux-amd64 | \
    ssh user@vm.example 'docker load'

# Option 2: Use remote Docker host directly
./twium/deploy/components.sh deploy --components globalsign-est \
    --docker-host ssh://user@vm.example \
    --config-dir /opt/twi-config
```

**Note:** `veraison-services` remains local-only through this dispatcher.

### 6. Check Status

```bash
./twium/deploy/components.sh status --components all
```

Or manually:

```bash
docker ps --filter "name=twi-"
```

### 7. Stop Components

```bash
./twium/deploy/components.sh stop --components all
```

## Container Management

### Persistent Data

Certain components use Docker volumes for persistent state:

- **Vault:** Named volume `twi-vault-data` stores unsealed Vault data
- **SPIRE Server:** Named volume `twi-spire-server-data` stores registration entries
- **step-ca:** Bind mount to config directory (read-write) for CA state

### Networking

All containers join the `twi-local` Docker bridge network for inter-component communication.

### Logs

View logs for any container:

```bash
docker logs twi-globalsign-est
docker logs -f twi-hashicorp-vault  # Follow logs
```

## Troubleshooting

### "cannot access the Docker daemon"

- **macOS:** Start Docker Desktop from Applications
- **Linux:** Start Docker service: `sudo systemctl start docker`
- **Permissions:** Ensure your user is in the `docker` group

### Bind Mount Fails (macOS)

Add workspace and config directories to Docker Desktop file sharing:
1. Docker Desktop → Settings → Resources → File sharing
2. Add paths, click Apply & Restart

### "missing image" with --no-build

Build the image first or remove the `--no-build` flag for that component.

### "required configuration ... missing"

Create the configuration directory structure documented in `deploy/config/README.md`. For local development, run `init-local-est-config.sh` for EST.

### Port Already Allocated

Stop conflicting services or change published ports in the dispatcher script.

Default ports:
- EST: 8443
- Vault: 8200, 8201
- SPIRE Server: 8081
- step-ca: 9000

### Container Exits Immediately

Check logs:

```bash
docker logs <container-name>
```

Common issues:
- Missing configuration files
- Invalid configuration syntax
- Missing certificates/keys
- Permission issues on mounted volumes

### Vault Build Fails with "fatal: not a git repository"

**Fixed:** Ensured `.git` is no longer in `hashicorp-vault/.dockerignore`. If you encounter this, verify:

```bash
grep -v "^#" hashicorp-vault/.dockerignore
# Should NOT contain ".git"
```

## Build Times

Approximate build times on Apple Silicon (M1/M2/M3):

| Component | Build Time | Image Size |
|-----------|------------|------------|
| globalsign-est | ~30 seconds | 16 MB |
| hashicorp-vault | ~5-10 minutes | 150 MB |
| spiffe-spire | ~3-5 minutes | 150 MB (server), 62 MB (agent) |
| step-ca | ~3-5 minutes | 147 MB |
| veraison-services | ~2-3 minutes | Varies |

Cross-platform builds (e.g., `--platform linux/amd64` on ARM) may take 2-3× longer due to emulation.

## Next Steps

After deploying components:

1. **Initialize Vault** (if deployed):
   ```bash
   docker exec -it twi-hashicorp-vault vault operator init
   # Save the unseal keys and root token
   docker exec -it twi-hashicorp-vault vault operator unseal
   ```

2. **Verify EST Server**:
   ```bash
   curl -k https://localhost:8443/.well-known/est/cacerts
   ```

3. **Check SPIRE Server**:
   ```bash
   docker exec -it twi-spire-server spire-server healthcheck
   ```

4. **Test step-ca**:
   ```bash
   curl https://localhost:9000/health
   ```

## See Also

- [Installation Prerequisites](readme_install_prereq.md) - Install Go and protoc
- [deploy/config/README.md](deploy/config/README.md) - Configuration directory structure
- [README.md](README.md) - Main project overview
