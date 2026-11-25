// Command sidecar is the CAI sidecar: it serves the Credential Acquisition
// Interface to a Workload beside it and holds the Platform Plug-In.
//
// Environment:
//
//	CAI_LISTEN               address of the CAI service (default ":50051")
//	CAAPI_ADDR               gRPC target of the CAS Client (default "127.0.0.1:9090")
//	CAI_PLATFORM             "simulated" (default), "sev-snp" or "tdx"
//	CAI_SIM_ATTESTATION_KEY  file of the Attestation Key of the simulated platform, PEM;
//	                         without it the sidecar generates a key that no Verifier holds
//	CAI_TRACE_DIR            directory in which the sidecar records every call of CAAPI
//	                         that it makes, one file for each; nothing secret crosses
//	                         CAAPI, and the command caapi-trace reports the records
//
// With the argument -measurement the sidecar prints the measurement that the
// simulated platform reports for this program, and exits.
package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/TWI-Unified-Model/tacra/cai"
	"github.com/TWI-Unified-Model/tacra/cai/trace"
	caiv1 "github.com/TWI-Unified-Model/tacra/gen/go/cai/v1"
	"github.com/TWI-Unified-Model/tacra/platform"
	"github.com/TWI-Unified-Model/tacra/platform/sim"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "-measurement" {
		measurement, err := sim.MeasureProgram()
		if err != nil {
			fail("measurement: %v", err)
		}
		fmt.Println(hex.EncodeToString(measurement))
		return
	}

	listen := envOr("CAI_LISTEN", ":50051")
	caapiAddr := envOr("CAAPI_ADDR", "127.0.0.1:9090")

	plugin, err := newPlugin(envOr("CAI_PLATFORM", "simulated"))
	if err != nil {
		fail("platform plug-in: %v", err)
	}

	dialOptions := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		// The sidecar takes no service configuration from DNS. Without this option
		// the first call to a CAS Client named by host waits for a TXT lookup that
		// a resolver may take half a second to refuse.
		grpc.WithDisableServiceConfig(),
	}
	if dir := os.Getenv("CAI_TRACE_DIR"); dir != "" {
		record, err := trace.Interceptor(dir)
		if err != nil {
			fail("CAI_TRACE_DIR: %v", err)
		}
		dialOptions = append(dialOptions, grpc.WithChainUnaryInterceptor(record))
		fmt.Printf("the calls of CAAPI are recorded in %s\n", dir)
	}
	inner, conn, err := cai.Dial(caapiAddr, plugin, dialOptions...)
	if err != nil {
		fail("CAAPI dial %s: %v", caapiAddr, err)
	}
	defer conn.Close()

	ln, err := net.Listen("tcp", listen)
	if err != nil {
		fail("listen %s: %v", listen, err)
	}

	s := grpc.NewServer()
	caiv1.RegisterCredentialAcquisitionInterfaceServer(s, cai.NewGRPC(inner))
	fmt.Printf("CAI sidecar on %s (CAAPI %s, platform %s)\n", listen, caapiAddr, plugin.Name())
	if err := s.Serve(ln); err != nil {
		fail("CAI sidecar failed: %v", err)
	}
}

// newPlugin constructs the Platform Plug-In that CAI_PLATFORM names.
func newPlugin(name string) (platform.Plugin, error) {
	switch name {
	case "simulated":
		return newSimulated()
	case "sev-snp":
		return platform.NewSEVSNP()
	case "tdx":
		return platform.NewTDX()
	default:
		return nil, fmt.Errorf("CAI_PLATFORM is %q; the platforms are simulated, sev-snp and tdx", name)
	}
}

func newSimulated() (platform.Plugin, error) {
	var opts []sim.Option
	if path := os.Getenv("CAI_SIM_ATTESTATION_KEY"); path != "" {
		encoded, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		key, err := sim.ParseAttestationKey(encoded)
		if err != nil {
			return nil, err
		}
		opts = append(opts, sim.WithAttestationKey(key))
	} else {
		fmt.Println("CAI_SIM_ATTESTATION_KEY is not set: the simulated platform signs with a new Attestation Key")
	}
	plugin, err := sim.NewSimulated(opts...)
	if err != nil {
		return nil, err
	}
	fmt.Printf("simulated platform: measurement %s\n", hex.EncodeToString(plugin.Measurement()))
	return plugin, nil
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
