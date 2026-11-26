package casserver

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/TWI-Unified-Model/tacra/constants"
)

// Refusals of a Secret Vault that this Server reads itself.
var (
	// ErrNoStoredCredential is the Secret Vault holding no credential at the
	// path that the policy for the Target names.
	ErrNoStoredCredential = errors.New("the Secret Vault holds no credential for the Target")
	// ErrStoredCredential is a record in the Secret Vault that is not a
	// credential as this Server reads it.
	ErrStoredCredential = errors.New("the record in the Secret Vault is not a credential")
)

// hashicorpVaultKind is HashiCorp Vault as the Secret Vault: the Server reads
// the credential for a Target from the key-value secrets engine, version 2,
// with the token provisioned for it. The record of a credential has the
// fields type, a Credential Type of TACRA; value, the credential as text; and,
// optionally, format, another encoding of the octets of the credential.
type hashicorpVaultKind struct{}

// defaultHashicorpMount is the mount of the key-value secrets engine when the
// configuration names none.
const defaultHashicorpMount = "secret"

func (hashicorpVaultKind) Name() string { return "hashicorp" }

func (hashicorpVaultKind) Store() bool { return true }

func (hashicorpVaultKind) Validate(c *SecretVaultConfig) error {
	switch {
	case c.URL == "":
		return errors.New("url is required")
	case c.TokenPath == "":
		return errors.New("token_path is required")
	}
	return nil
}

func (hashicorpVaultKind) New(c *SecretVaultConfig, tc *tls.Config) (secretVault, secretStore, error) {
	mount := strings.Trim(c.Mount, "/")
	if mount == "" {
		mount = defaultHashicorpMount
	}
	return nil, &hashicorpVault{
		url:       strings.TrimRight(c.URL, "/"),
		mount:     mount,
		tokenPath: c.TokenPath,
		client:    &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: tc}},
	}, nil
}

// hashicorpVault is a Secret Vault of kind hashicorp.
type hashicorpVault struct {
	url       string
	mount     string
	tokenPath string
	client    *http.Client
}

// Read returns the latest version of the credential at path.
func (v *hashicorpVault) Read(ctx context.Context, path string) (*storedCredential, error) {
	token, err := os.ReadFile(v.tokenPath)
	if err != nil {
		return nil, fmt.Errorf("%w: token_path: %w", ErrVaultUnavailable, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.url+"/v1/"+v.mount+"/data/"+strings.Trim(path, "/"), nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrVaultUnavailable, err)
	}
	req.Header.Set("X-Vault-Token", strings.TrimSpace(string(token)))
	resp, err := v.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrVaultUnavailable, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrVaultUnavailable, err)
	}
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, ErrNoStoredCredential
	default:
		return nil, fmt.Errorf("%w: HTTP %d", ErrVaultUnavailable, resp.StatusCode)
	}
	var record struct {
		Data struct {
			Data     map[string]string `json:"data"`
			Metadata struct {
				Version int `json:"version"`
			} `json:"metadata"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &record); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrStoredCredential, err)
	}
	fields := record.Data.Data
	if fields["type"] == "" || fields["value"] == "" {
		return nil, fmt.Errorf("%w: the fields type and value are required", ErrStoredCredential)
	}
	return &storedCredential{
		Type:    constants.CredentialType(fields["type"]),
		Format:  fields["format"],
		Value:   []byte(fields["value"]),
		Version: strconv.Itoa(record.Data.Metadata.Version),
	}, nil
}
