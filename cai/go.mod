module github.com/TWI-Unified-Model/tacra/cai

go 1.26.5

replace github.com/TWI-Unified-Model/tacra/platform => ../platform

replace github.com/TWI-Unified-Model/tacra/gen/go => ../gen/go

require (
	github.com/TWI-Unified-Model/tacra/gen/go v0.0.0-00010101000000-000000000000
	github.com/TWI-Unified-Model/tacra/platform v0.0.0-00010101000000-000000000000
	github.com/fxamacker/cbor/v2 v2.9.3
	github.com/veraison/eat v0.0.0-20251105185612-2c0e43e22ea9
	golang.org/x/crypto v0.56.0
	google.golang.org/grpc v1.83.2
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/stretchr/testify v1.11.1 // indirect
	github.com/veraison/go-cose v1.3.0 // indirect
	github.com/veraison/swid v1.1.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
	google.golang.org/protobuf v1.36.12 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
