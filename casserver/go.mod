module github.com/TWI-Unified-Model/tacra/casserver

go 1.26.5

replace github.com/TWI-Unified-Model/tacra/constants => ../constants

require (
	github.com/TWI-Unified-Model/tacra/constants v0.0.0-20261112212256-c40a1def0f3a
	github.com/fxamacker/cbor/v2 v2.9.1
	github.com/go-jose/go-jose/v4 v4.1.6
	github.com/sirupsen/logrus v1.10.2
	github.com/stretchr/testify v1.12.1
	google.golang.org/grpc v1.84.0
)

require (
	github.com/x448/float16 v0.8.4 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/sys v0.47.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260706201446-f0a921348800 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)
