package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <server-name-or-host>\n", os.Args[0])
		os.Exit(1)
	}

	server := os.Args[1]
	if !strings.HasPrefix(server, "http://") && !strings.HasPrefix(server, "https://") {
		server = "http://" + server
	}

	var port int
	if strings.HasPrefix(server, "https://") {
		port = 443
	} else if strings.HasPrefix(server, "http://") {
		port = 8080
	} else {
		panic("Unexepcted server prefix")
	}

	if len(os.Args) > 2 {
		var err error
		if port, err = strconv.Atoi(os.Args[2]); err != nil {
			fmt.Fprintf(os.Stderr, "Invalid port: \"%s\"%v", os.Args[2], err)
			os.Exit(1)
		}
		if port < 0 || port > 65535 {
			fmt.Fprintf(os.Stderr, "Port value cannot be negative or too large")
			os.Exit(1)
		}
	}

	// Construct request endpoint with 'Hello, world!' payload
	reqURL := fmt.Sprintf("%s:%d/?message=%s", server, port, url.QueryEscape("Hello, world!"))

	client := &http.Client{Timeout: 10 * time.Second}

	req, err := http.NewRequest(http.MethodGet, reqURL, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create request: %v\n", err)
		os.Exit(1)
	}

	// Set custom header in case server expects payload there
	req.Header.Set("X-Greeting", "Hello, world!")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "HTTP GET request failed: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read response body: %v\n", err)
		os.Exit(1)
	}

	receivedURI := strings.TrimSpace(string(body))

	// Validate returned string is a valid URI
	parsedURI, err := url.ParseRequestURI(receivedURI)
	if err != nil || parsedURI.Scheme == "" {
		fmt.Fprintf(os.Stderr, "Response is not a valid URI: %q\n", receivedURI)
		os.Exit(1)
	}

	fmt.Printf("Received valid URI: %s\n", receivedURI)
}
