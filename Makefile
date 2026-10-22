# Directory definitions
PROTO_DIR := proto
OUT_DIR   := gen/go
BIN_DIR   := bin
CLIENT_BIN := $(BIN_DIR)/client
SERVER_BIN := $(BIN_DIR)/server
CAI_BIN    := $(BIN_DIR)/cai

# Find all .proto files inside the PROTO_DIR directory
PROTO_FILES := $(shell find $(PROTO_DIR) -name '*.proto')
PROTO_SRCS  := $(patsubst $(PROTO_DIR)/%,%,$(PROTO_FILES))

.PHONY: all proto install-tools clean help client server platform cai

all: proto platform cai client server

## proto: Compiles all .proto files into Go code
proto:
	@mkdir -p $(OUT_DIR)
	protoc \
		--proto_path=$(PROTO_DIR) \
		--go_out=$(OUT_DIR) \
		--go_opt=paths=source_relative \
		--go-grpc_out=$(OUT_DIR) \
		--go-grpc_opt=paths=source_relative \
		$(PROTO_SRCS)
	@echo "Successfully compiled proto files to $(OUT_DIR)"

## platform: Builds the platform plug-in library
platform:
	cd platform && go build ./...
	@echo "Successfully built platform library"

## cai: Builds the CAI library and sidecar binary
cai: proto
	cd cai && go build ./...
	@mkdir -p $(BIN_DIR)
	go build -o $(CAI_BIN) ./cai/cmd/sidecar
	@echo "Successfully built cai library and sidecar to $(CAI_BIN)"

## client: Compiles the HTTP client (talks to the CAI sidecar)
client: proto
	@mkdir -p $(BIN_DIR)
	go build -o $(CLIENT_BIN) ./client
	@echo "Successfully compiled client to $(CLIENT_BIN)"

## server: Compiles the demo RATS-unaware Relying Party (RUP)
server:
	@mkdir -p $(BIN_DIR)
	go build -o $(SERVER_BIN) ./server
	@echo "Successfully compiled server to $(SERVER_BIN)"

## install-tools: Installs necessary protoc Go plugins
install-tools:
	@echo "Installing protoc-gen-go and protoc-gen-go-grpc..."
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

## clean: Removes generated Go files, binaries, and cai/platform build artifacts
clean:
	rm -rf $(OUT_DIR)/caapi $(OUT_DIR)/cai $(OUT_DIR)/proto $(BIN_DIR)
	cd platform && go clean ./...
	cd cai && go clean ./...
	@echo "Cleaned generated files, binaries, and cai/platform artifacts."

## help: Shows available Makefile targets
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@sed -n 's/^##//p' $(MAKEFILE_LIST)
