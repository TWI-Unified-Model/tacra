# Directory definitions
PROTO_DIR := proto
OUT_DIR   := gen/go

# Find all .proto files inside the PROTO_DIR directory
PROTO_FILES := $(shell find $(PROTO_DIR) -name '*.proto')

.PHONY: all proto install-tools clean help

# Default target
all: proto

## proto: Compiles all .proto files into Go code
proto:
	@mkdir -p $(OUT_DIR)
	protoc \
		--proto_path=$(PROTO_DIR) \
		--go_out=$(OUT_DIR) \
		--go_opt=paths=source_relative \
		--go-grpc_out=$(OUT_DIR) \
		--go-grpc_opt=paths=source_relative \
		$(PROTO_FILES)
	@echo "Successfully compiled proto files to $(OUT_DIR)"

## install-tools: Installs necessary protoc Go plugins
install-tools:
	@echo "Installing protoc-gen-go and protoc-gen-go-grpc..."
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

## clean: Removes all generated Go files
clean:
	rm -rf $(OUT_DIR)
	@echo "Cleaned generated files."

## help: Shows available Makefile targets
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@sed -n 's/^##//p' $(MAKEFILE_LIST)