package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"time"
)

const (
	// defaultConfigPath is where deploy/init-local-rup-config.sh writes rup.json,
	// relative to tacra/, where ./bin/server runs.
	defaultConfigPath = "deploy/config/local/rup/rup.json"
	defaultHTTPSHost  = ""
	defaultHTTPSPort  = "8443"
	readHeaderTimeout = 10 * time.Second
	// demoReceivedURI is the demo RUP's success response body.
	demoReceivedURI = "https://example.com/received"
)

func main() {
	httpsAddr := envOr("HTTPS_ADDR", net.JoinHostPort(defaultHTTPSHost, defaultHTTPSPort))
	configPath := envOr("RUP_CONFIG", defaultConfigPath)

	cfg, err := LoadConfig(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "rup: %v\n", err)
		os.Exit(1)
	}
	verifier, err := New(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "rup: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("RATS-unaware Relying Party on %s (config %s)\n", httpsAddr, configPath)
	if err := serveHTTPS(httpsAddr, verifier); err != nil {
		fmt.Fprintf(os.Stderr, "HTTPS server failed: %v\n", err)
		os.Exit(1)
	}
}

func serveHTTPS(addr string, verifier *Verifier) error {
	mux := http.NewServeMux()
	mux.Handle("/", verifier.Middleware(http.HandlerFunc(demoHandler), func(r *http.Request, err error) {
		fmt.Printf("RUP rejected request from %s: %v\n", r.RemoteAddr, err)
	}))

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: readHeaderTimeout,
		TLSConfig:         verifier.TLSConfig(),
	}
	return srv.ListenAndServeTLS("", "")
}

func demoHandler(w http.ResponseWriter, r *http.Request) {
	p, _ := PrincipalFrom(r.Context())
	fmt.Printf("Received authenticated request. Formats: %v, subject: %q, Message: %q, X-Greeting: %q\n",
		p.Formats, p.Subject, r.URL.Query().Get("message"), r.Header.Get("X-Greeting"))

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(demoReceivedURI))
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
