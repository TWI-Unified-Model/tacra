# TACRA - Proof of Concept

Trustworthy Acquisition of Credentials using Remote Attestation Proof-of-Concept

## Quick Start

Get the TACRA stack running in 3 steps:

```bash
# 1. Install prerequisites (Go 1.23+, protoc 25.3+)
#    See: readme_install_prereq.md

# 2. Build TACRA proto schemas
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
| **Understand TACRA** | This PoC implements the Trustworthy Credential Acquisition using Remote Attestion (TACRA) architecture | [TACRA Informational Draft](https://github.com/TheBankster/rats-tacra/) |
| **Installation Prerequisites** | Install Go compiler, Protobuf compiler (protoc), and build tools required to compile TACRA schemas from source. **Start here** if setting up a new development environment. | [readme_install_prereq.md](readme_install_prereq.md) |
| **Docker Build & Deployment** | Build Docker images from source for all TWI stack components (globalsign-est, hashicorp-vault, spiffe-spire, step-ca, veraison-services) and deploy them locally or to remote hosts. Covers `components.sh` usage, configuration management, component-specific Dockerfiles, and the `init-local-est-config.sh` script for local development setup. | [readme_docker_build_deploy.md](readme_docker_build_deploy.md) |
| **Configuration Structure** | Runtime configuration directory layout, certificate/key requirements, and component-specific config examples. | [deploy/config/README.md](deploy/config/README.md) |
| **Sequence Diagrams** | Visual flow diagrams showing acquire, initiate, retrieve, and enroll operations across the stack. | [proto/*.mmd](proto/*.mmd) |
| **CAI Schema** | Protobuf message definitions and gRPC service contracts for CAI. | [proto/cai/v1/cai.proto](proto/cai/v1/cai.proto) |
| **CAAPI Schema** | Protobuf message definitions and gRPC service contracts for CAAPI. | [proto/caapi/v1/caapi.proto](proto/caapi/v1/caapi.proto) |

## Repository Structure

```
.
├── cai                         # Credential Acquisition Interface (CAI) implementation
│   └── cmd/sidecar/            # CAI Sidecar implementation
├── client/                     # PoC Client
├── deploy/
│   ├── components.sh           # Main deployment dispatcher script
│   ├── init-local-est-config.sh             # Local EST config generator
│   ├── init-local-hashicorp-vault-config.sh # Local HashiCorp Vault config generator
│   ├── init-local-rup-config.sh             # Local demo RUP TLS identity + rup.json generator
│   ├── init-local-spiffe-spire-config.sh    # Local SPIFFE/SPIRE config generator
│   ├── init-local-step-ca-config.sh         # Local step-ca config generator
│   └── config/
│       └── README.md           # Configuration documentation
├── est/                        # EST integration tests
├── gen/go/
│   ├── caapi/v1/
│   │   ├── caapi.pb.go         # CAAPI Protobuf Go bindings
│   │   └── caapi_grpc.pb.go    # CAAPI gRPC Go bindings
│   └── cai/v1/
│       ├── cai.pb.go           # CAI Protobuf Go bindings
│       └── cai_grpc.pb.go      # CAI gRPC Go bindings
├── platform/                   # Platform plug-in
├── proto/
│   │                           # Protobuf services and message definitions
│   ├── caapi/v1/caapi.proto    # Credential Acquisition API v1 (CAAPI)
│   ├── cai/v1/cai.proto        # Credential Acquisition Interface v1 (CAI)
│   │                           # Mermaid sequence diagrams
│   ├── acquire.mmd             # CAI: AcquireCredential flow
│   ├── enroll.mmd              # CAAPI: EnrollCredential flow
│   ├── initiate.mmd            # CAAPI: InitiateAcquisition flow
│   └── retrieve.mmd            # CAAPI: RetrieveCredential flow
├── Makefile                    # Build automation
├── README.md                   # This file
├── readme_docker_build_deploy.md # Docker deployment guide
├── readme_install_prereq.md    # Installation prerequisites
└── server/                     # Demo RATS-unaware Relying Party (RUP); see server/README.md
```

## Component Integration

TACRA integrates with these upstream projects (vendored in the workspace):

| Component | Role | Repository |
|-----------|------|------------|
| **globalsign-est** | RFC 7030 EST server for certificate enrollment | [globalsign/est](https://github.com/globalsign/est) |
| **hashicorp-vault** | Secrets and identity management | [hashicorp/vault](https://github.com/hashicorp/vault) |
| **spiffe-spire** | Workload identity and SVID issuance | [spiffe/spire](https://github.com/spiffe/spire) |
| **step-ca** | Online CA for TLS/SSH/ACME | [smallstep/certificates](https://github.com/smallstep/certificates) |
| **veraison-services** | Attestation verification services | [veraison/services](https://github.com/veraison/services) |
| **veraison-apiclient** | Go client for Veraison API | [veraison/apiclient](https://github.com/veraison/apiclient) |

