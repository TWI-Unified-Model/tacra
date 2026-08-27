# TWI Unified Model - Proof of Concept

TWI Unified Model Proof-of-Concept

## Quick Start

Get the TWI stack running in 3 steps:

```bash
# 1. Install prerequisites (Go 1.23+, protoc 25.3+)
#    See: readme_install_prereq.md

# 2. Build twium proto schemas
make install-tools
make proto

# 3. Build images, then deploy all components with Docker
export DEPLOY_CONFIG_DIR="$PWD/deploy/config/local"
./deploy/components.sh build --components all
./deploy/components.sh deploy --components all
```

## Documentation

| Topic | Description | Link |
|-------|-------------|------|
| **Installation Prerequisites** | Install Go compiler, Protobuf compiler (protoc), and build tools required to compile twium schemas from source. **Start here** if setting up a new development environment. | [readme_install_prereq.md](readme_install_prereq.md) |
| **Docker Build & Deployment** | Build Docker images from source for all TWI stack components (globalsign-est, hashicorp-vault, spiffe-spire, step-ca, veraison-services) and deploy them locally or to remote hosts. Covers `components.sh` usage, configuration management, component-specific Dockerfiles, and the `init-local-est-config.sh` script for local development setup. | [readme_docker_build_deploy.md](readme_docker_build_deploy.md) |
| **Configuration Structure** | Runtime configuration directory layout, certificate/key requirements, and component-specific config examples. | [deploy/config/README.md](deploy/config/README.md) |
| **CA API Schema** | Protobuf message definitions and gRPC service contracts for the CA API. | [proto/caapi/v1/caapi.proto](proto/caapi/v1/caapi.proto) |
| **Sequence Diagrams** | Visual flow diagrams showing mint, retrieve, and initiate operations across the stack. | [proto/caapi/v1/*.mmd](proto/caapi/v1/) |

## Repository Structure

```
twium/
├── proto/                      # Protobuf schema definitions
│   └── caapi/v1/
│       ├── caapi.proto         # CA API service and messages
│       ├── mint.mmd            # Mint operation flow diagram
│       ├── retrieve.mmd        # Retrieve operation flow diagram
│       └── initiate.mmd        # Initiate operation flow diagram
├── gen/                        # Generated Go code (do not edit manually)
│   └── go/
│       └── caapi/v1/
│           ├── caapi.pb.go     # Protobuf Go bindings
│           └── caapi_grpc.pb.go # gRPC Go bindings
├── deploy/                     # Deployment orchestration
│   ├── components.sh           # Main deployment dispatcher script
│   ├── init-local-est-config.sh # Local EST config generator
│   └── config/
│       ├── README.md           # Configuration documentation
│       └── local/              # Gitignored local dev configs
├── Makefile                    # Build automation
├── README.md                   # This file
├── readme_install_prereq.md    # Installation prerequisites
└── readme_docker_build_deploy.md # Docker deployment guide
```

## Component Integration

Twium integrates with these upstream projects (vendored in the workspace):

| Component | Role | Repository |
|-----------|------|------------|
| **globalsign-est** | RFC 7030 EST server for certificate enrollment | [globalsign/est](https://github.com/globalsign/est) |
| **hashicorp-vault** | Secrets and identity management | [hashicorp/vault](https://github.com/hashicorp/vault) |
| **spiffe-spire** | Workload identity and SVID issuance | [spiffe/spire](https://github.com/spiffe/spire) |
| **step-ca** | Online CA for TLS/SSH/ACME | [smallstep/certificates](https://github.com/smallstep/certificates) |
| **veraison-services** | Attestation verification services | [veraison/services](https://github.com/veraison/services) |
| **veraison-apiclient** | Go client for Veraison API | [veraison/apiclient](https://github.com/veraison/apiclient) |

