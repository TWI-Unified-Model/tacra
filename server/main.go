package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	caapiv1 "github.com/TWI-Unified-Model/twium/gen/go/caapi/v1"
	"google.golang.org/grpc"
)

func main() {
	httpsAddr := envOr("HTTPS_ADDR", ":8443")
	caapiAddr := envOr("CAAPI_ADDR", ":9090")

	iss, err := newIssuer()
	if err != nil {
		fmt.Fprintf(os.Stderr, "issuer: %v\n", err)
		os.Exit(1)
	}
	cas, err := newCAAPIServer(iss)
	if err != nil {
		fmt.Fprintf(os.Stderr, "caapi: %v\n", err)
		os.Exit(1)
	}

	go func() {
		if err := serveCAAPI(caapiAddr, cas); err != nil {
			fmt.Fprintf(os.Stderr, "CAAPI server failed: %v\n", err)
			os.Exit(1)
		}
	}()

	fmt.Printf("CAAPI gRPC on %s\n", caapiAddr)
	fmt.Printf("HTTPS mTLS on %s\n", httpsAddr)
	if err := serveHTTPS(httpsAddr, iss, cas); err != nil {
		fmt.Fprintf(os.Stderr, "HTTPS server failed: %v\n", err)
		os.Exit(1)
	}
}

func serveCAAPI(addr string, cas *caapiServer) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s := grpc.NewServer()
	caapiv1.RegisterCredentialAcquisitionServiceServer(s, cas)
	return s.Serve(ln)
}

func serveHTTPS(addr string, iss *issuer, cas *caapiServer) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "client certificate required", http.StatusUnauthorized)
			return
		}
		auth := r.Header.Get("Authorization")
		const bearer = "Bearer "
		if !strings.HasPrefix(auth, bearer) {
			http.Error(w, "bearer token required", http.StatusUnauthorized)
			return
		}
		if err := cas.verifyJWT(strings.TrimPrefix(auth, bearer)); err != nil {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}

		message := r.URL.Query().Get("message")
		greeting := r.Header.Get("X-Greeting")
		fmt.Printf("Received mTLS+JWT request. Message: %q, X-Greeting: %q, client CN: %q\n",
			message, greeting, r.TLS.PeerCertificates[0].Subject.CommonName)

		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("https://example.com/received"))
	})

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{iss.serverTLS},
			ClientCAs:    iss.clientCAPool(),
			ClientAuth:   tls.RequireAndVerifyClientCert,
		},
	}
	return srv.ListenAndServeTLS("", "")
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
