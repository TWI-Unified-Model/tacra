# TWI Unified Model - Proof of Concept
TWI Unified Model Proof-of-Concept

# Install Prerequisites

## Go Compiler
Current minimum requirement is version 1.2 of Go.
```code
sudo add-apt-repository ppa:longsleep/golang-backports -y
sudo apt update
sudo apt install -y golang-go

go version
```

## Protobuf Compiler
Note: Installing protobuf-compiler via apt on Ubuntu often installs an outdated version (e.g., v3.12) that fails on proto3 optional fields. Installing the pre-compiled binary from GitHub is recommended.
```code
# Remove outdated system package if installed
sudo apt remove -y protobuf-compiler

# Download and install the latest protoc binary (v25.3)
curl -LO https://github.com/protocolbuffers/protobuf/releases/download/v25.3/protoc-25.3-linux-x86_64.zip
sudo unzip -o protoc-25.3-linux-x86_64.zip -d /usr/local
rm protoc-25.3-linux-x86_64.zip

# Clear bash command path cache (prevents "No such file or directory" errors)
hash -r

# Set up the path for the future
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
source ~/.bashrc

# Verify protoc installation
protoc --version
```

## Build Instructions
1. Install Go Protoc Plugins (do this once):
```code
make install-tools
```
2. Compile Protobuf Files:
```code
make proto
# or simply
make
```
3. Clean Generated Files:
```code
make clean
```