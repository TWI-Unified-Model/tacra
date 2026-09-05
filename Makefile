# Directory definitions
PROTO_DIR := proto
OUT_DIR   := gen/go
BIN_DIR   := bin
CLIENT_SRC := client/main.go
SERVER_SRC := server/main.go
CLIENT_BIN := $(BIN_DIR)/client
SERVER_BIN := $(BIN_DIR)/server

# Find all .proto files inside the PROTO_DIR directory
PROTO_FILES := $(shell find $(PROTO_DIR) -name '*.proto')

.PHONY: all proto install-tools clean help client server test platform

all: proto client server

## test: Runs unit tests for library packages
test:
	cd platform && GOWORK=off go test ./...

## platform: Runs the platform plug-in tests
platform:
	cd platform && GOWORK=off go test ./...

## proto: Compiles all .proto files into Go code
proto:
	@mkdir -p $(OUT_DIR)
	protoc \
		--proto_path=. \
		--go_out=$(OUT_DIR) \
		--go_opt=paths=source_relative \
		--go-grpc_out=$(OUT_DIR) \
		--go-grpc_opt=paths=source_relative \
		$(PROTO_FILES)
	@echo "Successfully compiled proto files to $(OUT_DIR)"

## client: Compiles the HTTP client
client:
	@mkdir -p $(BIN_DIR)
	go build -o $(CLIENT_BIN) $(CLIENT_SRC)
	@echo "Successfully compiled client to $(CLIENT_BIN)"

## server: Compiles the HTTP server
server:
	@mkdir -p $(BIN_DIR)
	go build -o $(SERVER_BIN) $(SERVER_SRC)
	@echo "Successfully compiled server to $(SERVER_BIN)"

## install-tools: Installs necessary protoc Go plugins
install-tools:
	@echo "Installing protoc-gen-go and protoc-gen-go-grpc..."
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

## clean: Removes all generated Go files and binaries
clean:
	rm -rf $(OUT_DIR) $(BIN_DIR)
	@echo "Cleaned generated files and binaries."

## help: Shows available Makefile targets
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@sed -n 's/^##//p' $(MAKEFILE_LIST)