package main

import (
	"fmt"
	"net"
	"os"

	"github.com/TWI-Unified-Model/tacra/cai"
	caiv1 "github.com/TWI-Unified-Model/tacra/gen/go/cai/v1"
	"github.com/TWI-Unified-Model/tacra/platform"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	listen := envOr("CAI_LISTEN", ":50051")
	caapiAddr := envOr("CAAPI_ADDR", "127.0.0.1:9090")

	plugin, err := platform.NewSimulated()
	if err != nil {
		fmt.Fprintf(os.Stderr, "platform plug-in: %v\n", err)
		os.Exit(1)
	}

	inner, conn, err := cai.Dial(caapiAddr, plugin, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Fprintf(os.Stderr, "CAAPI dial %s: %v\n", caapiAddr, err)
		os.Exit(1)
	}
	defer conn.Close()

	ln, err := net.Listen("tcp", listen)
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen %s: %v\n", listen, err)
		os.Exit(1)
	}

	s := grpc.NewServer()
	caiv1.RegisterCredentialAcquisitionInterfaceServer(s, cai.NewGRPC(inner))
	fmt.Printf("CAI sidecar on %s (CAAPI %s)\n", listen, caapiAddr)
	if err := s.Serve(ln); err != nil {
		fmt.Fprintf(os.Stderr, "CAI sidecar failed: %v\n", err)
		os.Exit(1)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
