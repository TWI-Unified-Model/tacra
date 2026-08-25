# TWI Unified Model - Proof of Concept

**Twium** defines the Protobuf/gRPC schema contracts that integrate the trusted-workload-identity (TWI) stack components. This repository serves as the central schema definition and deployment orchestration point for the entire TWI ecosystem.

## What is TWI?

The Trusted Workload Identity model enables workloads to:
1. Obtain SPIFFE identities via **SPIRE**
2. Present attestation evidence verified by **Veraison**
3. Acquire certificates/secrets through **step-ca**, **EST**, and **Vault**

**Twium** provides the glue: shared proto definitions (CA API, mint/retrieve/initiate flows) that these services consume to communicate.

## Quick Start

Get the TWI stack running in 3 steps:

```bash
# 1. Install prerequisites (Go 1.23+, protoc 25.3+)
#    See: readme_install_prereq.md

# 2. Build twium proto schemas
make install-tools
make proto

# 3. Deploy all components with Docker
export DEPLOY_CONFIG_DIR="$PWD/deploy/config/local"
./deploy/init-local-est-config.sh
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

## Key Concepts

### Schema-First Design

Twium defines service contracts in `.proto` files. Components import the generated Go bindings to ensure type-safe, version-compatible communication across the stack.

### Deployment Orchestration

The `deploy/components.sh` script provides a unified interface to build and deploy all TWI components from source, handling:
- Multi-stage Docker builds
- Platform-specific compilation (ARM64/AMD64)
- Configuration mounting and secret management
- Container lifecycle and networking

### Local Development Setup

For rapid iteration, the `init-local-est-config.sh` script generates a complete mock CA environment with self-signed certificates, enabling immediate local testing without external infrastructure dependencies.

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

## Build Commands

| Command | Description |
|---------|-------------|
| `make` | Compile all `.proto` files to Go (default target) |
| `make proto` | Explicitly compile protobuf schemas |
| `make install-tools` | Install `protoc-gen-go` and `protoc-gen-go-grpc` plugins |
| `make clean` | Remove all generated Go files from `gen/` |

Generated code is placed in `gen/go/` and should never be edited manually—regenerate by running `make proto` after modifying `.proto` files.

## Development Workflow

1. **Modify schemas:** Edit `.proto` files in `proto/caapi/v1/`
2. **Regenerate code:** Run `make proto`
3. **Test locally:** Deploy with `./deploy/components.sh deploy --components all`
4. **Iterate:** Update component implementations to consume new schema versions

## Design Decisions

### Why Protobuf/gRPC?

- **Type safety:** Compile-time checking across all language bindings
- **Versioning:** Backward-compatible schema evolution
- **Performance:** Efficient binary serialization
- **Multi-language:** Official support for Go, Java, Python, C++, etc.

### Why Source Builds in Docker?

The dispatcher builds from checked-out source rather than pulling published images to ensure:
- **Reproducibility:** Exact versions match the workspace state
- **Transparency:** No hidden dependencies or backdoored binaries
- **Customization:** Local patches and experimental branches deploy immediately

### Why Separate Configuration?

Runtime configuration (certificates, keys, passwords) is external to the repository to:
- **Prevent accidental commits:** Secrets never touch Git
- **Environment isolation:** Dev/staging/prod configs remain separate
- **Simplified rotation:** Replace certs without redeploying code

### hashicorp-vault .dockerignore Fix

Vault's build process requires Git metadata (via `git rev-parse` and `git status`) for version embedding and tool installation. The original `.dockerignore` excluded `.git`, causing build failures. This has been corrected by removing `.git` from the ignore list, allowing Vault to build successfully within Docker.

## Troubleshooting

### "protoc: command not found"

See [Installation Prerequisites](readme_install_prereq.md) for protoc installation steps.

### "cannot access the Docker daemon"

Ensure Docker Desktop (macOS) or Docker Engine (Linux) is running: `docker info`

### Build Failures

- **Vault:** Verify `.git` is NOT in `hashicorp-vault/.dockerignore`
- **Long build times:** Source compilation of large Go projects (Vault, SPIRE) can take 5-10 minutes on ARM64
- **Platform mismatch:** Use `--platform linux/amd64` when building for x86_64 VMs

### Deployment Issues

See the comprehensive troubleshooting section in [Docker Build & Deployment](readme_docker_build_deploy.md).

## Contributing

When adding new proto messages or services:

1. Define schemas in `proto/caapi/v1/*.proto`
2. Run `make proto` to regenerate Go bindings
3. Update sequence diagrams (`.mmd` files) to reflect new flows
4. Document breaking changes in commit messages
5. Ensure component integration tests pass

## License

See workspace root for license information.

## Support

For questions or issues:
- Check documentation links in the table above
- Review sequence diagrams in `proto/caapi/v1/*.mmd`
- Examine component-specific Dockerfiles for build details
- Consult `deploy/config/README.md` for configuration requirements