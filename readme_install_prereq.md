# Installation Prerequisites

This document covers the required software and tools to build **twium** from source.

## Go Compiler

Current minimum requirement is version 1.23 of Go.

### Installation on Ubuntu/Debian

```bash
sudo add-apt-repository ppa:longsleep/golang-backports -y
sudo apt update
sudo apt install -y golang-go

go version
```

### Installation on macOS

```bash
brew install go
# or download from https://go.dev/dl/
```

### Verify Installation

```bash
go version
# Expected: go version go1.23.x or later
```

## Protobuf Compiler

**Important:** Installing `protobuf-compiler` via apt on Ubuntu often installs an outdated version (e.g., v3.12) that fails on proto3 optional fields. Installing the pre-compiled binary from GitHub is strongly recommended.

### Installation Steps

#### 1. Remove Outdated System Package (if installed)

```bash
sudo apt remove -y protobuf-compiler
```

#### 2. Download and Install Latest protoc Binary (v25.3+)

**Linux (x86_64):**
```bash
curl -LO https://github.com/protocolbuffers/protobuf/releases/download/v25.3/protoc-25.3-linux-x86_64.zip
sudo unzip -o protoc-25.3-linux-x86_64.zip -d /usr/local
rm protoc-25.3-linux-x86_64.zip
```

**Linux (ARM64):**
```bash
curl -LO https://github.com/protocolbuffers/protobuf/releases/download/v25.3/protoc-25.3-linux-aarch_64.zip
sudo unzip -o protoc-25.3-linux-aarch_64.zip -d /usr/local
rm protoc-25.3-linux-aarch_64.zip
```

**macOS:**
```bash
brew install protobuf
```

#### 3. Clear Bash Command Path Cache

This prevents "No such file or directory" errors:

```bash
hash -r
```

#### 4. Set Up Go Path for Future Sessions

```bash
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
source ~/.bashrc

# For zsh users (macOS default):
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.zshrc
source ~/.zshrc
```

#### 5. Verify protoc Installation

```bash
protoc --version
# Expected: libprotoc 25.3 or later
```

## Build Instructions

Once prerequisites are installed, follow these steps to build twium:

### 1. Install Go Protoc Plugins (One-time Setup)

This installs `protoc-gen-go` and `protoc-gen-go-grpc`:

```bash
make install-tools
```

### 2. Compile Protobuf Files

Generate Go code from `.proto` files:

```bash
make proto
# or simply
make
```

Generated files are placed in `gen/go/`.

### 3. Clean Generated Files

Remove all generated code:

```bash
make clean
```

## Next Steps

After completing prerequisites and building twium, see:
- [Docker Build and Deployment](readme_docker_build_deploy.md) - Deploy the full TWI stack
- [README.md](README.md) - Main project overview
