package main

import (
	"fmt"
	"net/http"
	// "net/url"
)

func handler(w http.ResponseWriter, r *http.Request) {
	// Extract 'message' from query parameters
	message := r.URL.Query().Get("message")

	// Also check the custom header 'X-Greeting' as the client sets it
	greeting := r.Header.Get("X-Greeting")

	fmt.Printf("Received request. Message: %q, X-Greeting: %q\n", message, greeting)

	// The client expects a valid URI in the response body.
	// We will return a dummy URI as requested by the client's validation logic.
	responseURI := "https://example.com/received"

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(responseURI))
}

func main() {
	port := "8080"
	http.HandleFunc("/", handler)

	fmt.Printf("Starting server on :%s...\n", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		fmt.Printf("Server failed: %s\n", err)
	}
}
