package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/TWI-Unified-Model/twium/cai"
	"github.com/TWI-Unified-Model/twium/platform"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <server-name-or-host>\n", os.Args[0])
		os.Exit(1)
	}

	server := os.Args[1]
	if !strings.HasPrefix(server, "http://") && !strings.HasPrefix(server, "https://") {
		server = "https://" + server
	}

	serverURL, err := url.Parse(server)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid server url: %s\n", server)
		os.Exit(1)
	}
	if serverURL.ForceQuery || serverURL.RawQuery != "" {
		fmt.Fprintf(os.Stderr, "No query string allowed on server URL\n")
		os.Exit(1)
	}
	if serverURL.Scheme != "https" {
		fmt.Fprintf(os.Stderr, "Server URL must be https for mTLS\n")
		os.Exit(1)
	}

	caapiAddr := os.Getenv("CAAPI_ADDR")
	if caapiAddr == "" {
		caapiAddr = net.JoinHostPort(serverURL.Hostname(), "9090")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	plugin, err := platform.NewSimulated()
	if err != nil {
		fmt.Fprintf(os.Stderr, "platform plug-in: %v\n", err)
		os.Exit(1)
	}

	caiClient, conn, err := cai.Dial(caapiAddr, plugin, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Fprintf(os.Stderr, "CAI dial %s: %v\n", caapiAddr, err)
		os.Exit(1)
	}
	defer conn.Close()

	fmt.Printf("Acquiring X.509 client certificate for %s via CAI...\n", serverURL.String())
	x509Cred, err := caiClient.AcquireCredential(ctx, serverURL.String(), cai.CredentialTypeX509)
	if err != nil {
		fmt.Fprintf(os.Stderr, "AcquireCredential X509: %v\n", err)
		os.Exit(1)
	}
	tlsCert, roots, err := tlsCertFromCredential(x509Cred)
	if err != nil {
		fmt.Fprintf(os.Stderr, "X.509 credential: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Acquired X.509 certificate.")

	fmt.Printf("Acquiring JWT for %s via CAI...\n", serverURL.String())
	jwtCred, err := caiClient.AcquireCredential(ctx, serverURL.String(), cai.CredentialTypeJWT)
	if err != nil {
		fmt.Fprintf(os.Stderr, "AcquireCredential JWT: %v\n", err)
		os.Exit(1)
	}
	if len(jwtCred.Document) == 0 {
		fmt.Fprintf(os.Stderr, "empty JWT\n")
		os.Exit(1)
	}
	fmt.Println("Acquired JWT.")

	httpClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion:   tls.VersionTLS12,
				Certificates: []tls.Certificate{tlsCert},
				RootCAs:      roots,
				ServerName:   serverURL.Hostname(),
			},
		},
	}

	reqURL := fmt.Sprintf("%s/?message=%s", strings.TrimRight(serverURL.String(), "/"), url.QueryEscape("Hello, world!"))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create request: %v\n", err)
		os.Exit(1)
	}
	req.Header.Set("X-Greeting", "Hello, world!")
	req.Header.Set("Authorization", "Bearer "+string(jwtCred.Document))

	resp, err := httpClient.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "HTTPS GET request failed: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read response body: %v\n", err)
		os.Exit(1)
	}
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "Server returned %s: %s\n", resp.Status, body)
		os.Exit(1)
	}

	receivedURI := strings.TrimSpace(string(body))
	parsedURI, err := url.ParseRequestURI(receivedURI)
	if err != nil || parsedURI.Scheme == "" {
		fmt.Fprintf(os.Stderr, "Response is not a valid URI: %q\n", receivedURI)
		os.Exit(1)
	}
	fmt.Printf("Received valid URI: %s\n", receivedURI)
}

func tlsCertFromCredential(cred *cai.Credential) (tls.Certificate, *x509.CertPool, error) {
	if cred == nil {
		return tls.Certificate{}, nil, fmt.Errorf("nil X.509 credential")
	}
	if cred.PrivateKey == nil {
		return tls.Certificate{}, nil, fmt.Errorf("X.509 enrollment did not return a private key")
	}
	certs, err := parseCerts(cred.Document)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	if len(certs) == 0 {
		return tls.Certificate{}, nil, fmt.Errorf("no certificates in X.509 credential")
	}

	chain := make([][]byte, 0, len(certs))
	roots := x509.NewCertPool()
	for i, c := range certs {
		chain = append(chain, c.Raw)
		if i > 0 {
			roots.AddCert(c)
		}
	}
	if len(certs) < 2 {
		return tls.Certificate{}, nil, fmt.Errorf("X.509 credential has no CA certificate to verify the server")
	}

	return tls.Certificate{
		Certificate: chain,
		PrivateKey:  cred.PrivateKey,
	}, roots, nil
}

func parseCerts(doc []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := doc
	if bytesHasPEM(rest) {
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" {
				continue
			}
			c, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse PEM certificate: %w", err)
			}
			certs = append(certs, c)
		}
		return certs, nil
	}
	c, err := x509.ParseCertificate(doc)
	if err != nil {
		return nil, fmt.Errorf("parse DER certificate: %w", err)
	}
	return []*x509.Certificate{c}, nil
}

func bytesHasPEM(b []byte) bool {
	return strings.Contains(string(b), "-----BEGIN ")
}
