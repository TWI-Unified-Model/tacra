package casserver

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	"github.com/TWI-Unified-Model/tacra/constants"
	"github.com/TWI-Unified-Model/tacra/container"
)

const (
	storeTarget     = "https://server.example"
	storeSecretPath = "tacra/server-token"
	storeToken      = "the token of the Server"
	storedJWT       = "header.payload.signature"
)

// mockHashicorpVault answers the read of the key-value secrets engine,
// version 2, as HashiCorp Vault does, for one record at storeSecretPath.
type mockHashicorpVault struct {
	server *httptest.Server
	record map[string]string
	status int
}

func newMockHashicorpVault(t *testing.T) *mockHashicorpVault {
	v := &mockHashicorpVault{record: map[string]string{"type": "jwt", "value": storedJWT}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/secret/data/"+storeSecretPath, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Header.Get("X-Vault-Token") != storeToken:
			w.WriteHeader(http.StatusForbidden)
		case v.status != 0:
			w.WriteHeader(v.status)
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"data": v.record, "metadata": map[string]any{"version": 3}}})
		}
	})
	v.server = httptest.NewServer(mux)
	t.Cleanup(v.server.Close)
	return v
}

func (v *mockHashicorpVault) store(t *testing.T) secretStore {
	tokenPath := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(tokenPath, []byte(storeToken+"\n"), 0o600))
	_, store, err := hashicorpVaultKind{}.New(&SecretVaultConfig{URL: v.server.URL, TokenPath: tokenPath}, nil)
	require.NoError(t, err)
	return store
}

type releaseTest struct {
	a     *Acquirer
	vault *mockHashicorpVault
	psa   *mockVerifier
	now   time.Time
}

// newReleaseTest builds an Acquirer that reads a HashiCorp Vault itself, for
// one Target that enrolls x509 and releases jwt, with a Verifier that affirms
// PSA attestation tokens of the admitted measurement.
func newReleaseTest(t *testing.T) *releaseTest {
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	key := newTestKey(t)
	f := newMockVerifier(t)
	f.setAnswer(func(nonce, _ []byte, _ string) (string, string) {
		return "complete", signEAR(t, key, nonce, now, "PSA_IOT", "affirming", psaAnnotated(psaMeasurement))
	})
	window := resultsWindow{maxAge: 2 * time.Minute, skew: 5 * time.Second, now: func() time.Time { return now }}
	verifiers := map[string]verifierClient{"psa": &veraisonVerifier{name: "psa", mediaTypes: []string{psaTokenMediaType}, url: f.server.URL,
		client: f.server.Client(), key: &key.PublicKey, submods: []string{"PSA_IOT"}, window: window}}
	enroll := &Policy{Name: storeTarget, Mode: constants.CredentialAcquisitionModeEnroll, CredentialTypes: []constants.CredentialType{constants.CredentialTypeX509},
		FreshnessKind: constants.FreshnessKindPresentNonce, ExpiresIn: 5 * time.Minute, Verifiers: []string{"psa"}, AcceptableCSK: []string{"ecdsa-p256-sha256"},
		Measurements: [][]byte{psaMeasurement}}
	enroll.Retrieve = &Policy{Name: storeTarget, Mode: constants.CredentialAcquisitionModeRetrieve, CredentialTypes: []constants.CredentialType{constants.CredentialTypeJWT},
		FreshnessKind: constants.FreshnessKindPresentNonce, ExpiresIn: 5 * time.Minute, Verifiers: []string{"psa"}, Measurements: [][]byte{psaMeasurement},
		SecretPath: storeSecretPath, AcceptableCEK: []string{container.AcceptableMLKEM768P256, container.AcceptableDHKEMP256}}
	log, _ := test.NewNullLogger()
	vault := newMockHashicorpVault(t)
	a := newAcquirer(log, map[string]*Policy{storeTarget: enroll}, []string{psaTokenMediaType}, verifiers, nil, func() time.Time { return now })
	a.store = vault.store(t)
	return &releaseTest{a: a, vault: vault, psa: f, now: now}
}

// retrieval initiates for the jwt of the Target and returns the Retrieval that
// follows, with a new P-256 CEK.
func (x *releaseTest) retrieval(t *testing.T) (Retrieval, container.Expect) {
	init, err := x.a.Initiate(context.Background(), Initiation{EntryID: testEntryID, AgentID: testAgentID, Target: storeTarget, CredentialType: constants.CredentialTypeJWT})
	require.NoError(t, err)
	require.Equal(t, constants.CredentialAcquisitionModeRetrieve, init.Mode)
	require.Equal(t, constants.FreshnessKindPresentNonce, init.FreshnessKind)
	cek, cekPub, err := container.GenerateCEKP256()
	require.NoError(t, err)
	recipient, err := container.DHKEMPrivateKey(cek)
	require.NoError(t, err)
	return Retrieval{EntryID: testEntryID, AgentID: testAgentID, Target: storeTarget, CredentialType: constants.CredentialTypeJWT,
			FreshnessKind: constants.FreshnessKindPresentNonce, FreshnessElement: init.Handle, CEKPub: cekPub, Evidence: []byte{0xd2, 0x84},
			EvidenceProfile: psaTokenMediaType, BindingMethod: constants.BindingMethod, BindingHash: constants.BindingHash},
		container.Expect{Target: storeTarget, Handle: init.Handle, CEK: recipient, CEKPub: cekPub}
}

func TestInitiateForATargetOfTwoModes(t *testing.T) {
	x := newReleaseTest(t)
	init, err := x.a.Initiate(context.Background(), Initiation{EntryID: testEntryID, AgentID: testAgentID, Target: storeTarget, CredentialType: constants.CredentialTypeX509})
	require.NoError(t, err)
	require.Equal(t, constants.CredentialAcquisitionModeEnroll, init.Mode)
	require.NotEmpty(t, init.AcceptableCSK)

	init, err = x.a.Initiate(context.Background(), Initiation{EntryID: testEntryID, AgentID: testAgentID, Target: storeTarget, CredentialType: constants.CredentialTypeJWT})
	require.NoError(t, err)
	require.Equal(t, constants.CredentialAcquisitionModeRetrieve, init.Mode)
	require.Len(t, init.Handle, 32)
	require.Equal(t, []string{container.AcceptableMLKEM768P256, container.AcceptableDHKEMP256}, init.AcceptableCEK)

	_, err = x.a.Initiate(context.Background(), Initiation{EntryID: testEntryID, AgentID: testAgentID, Target: storeTarget, CredentialType: constants.CredentialTypeAPIKey})
	requireStatus(t, err, codes.Unimplemented, "is not supported for Target")
}

func TestRelease(t *testing.T) {
	t.Run("the credential of the Target, sealed to CEKpub", func(t *testing.T) {
		x := newReleaseTest(t)
		in, expect := x.retrieval(t)
		raw, err := x.a.Retrieve(context.Background(), in)
		require.NoError(t, err)

		// The Verifier was asked with the binding value over the Handle, the Target and CEKpub.
		require.Equal(t, [][]byte{BindingValue(in.FreshnessElement, storeTarget, in.CEKPub)}, x.psa.nonces)

		var sealed container.Bundle
		require.NoError(t, json.Unmarshal(raw, &sealed))
		require.Nil(t, sealed.Origin)
		content, err := container.Open(&sealed, expect)
		require.NoError(t, err)
		require.NoError(t, container.CheckItems(content, false, 3600))
		require.Len(t, content.CredentialItems, 1)
		item := content.CredentialItems[0]
		require.Equal(t, "jwt", item.Type)
		octets, err := container.ItemOctets(item)
		require.NoError(t, err)
		require.Equal(t, storedJWT, string(octets))
		require.Equal(t, groupID(psaMeasurement, familyPSA, storeTarget, ""), sealed.AAD.GroupID)
		require.Equal(t, sealed.AAD.GroupID[:16], item.Kid)
		require.Equal(t, "3", content.Metadata["secret_version"])
	})
	t.Run("a Handle is accepted once", func(t *testing.T) {
		x := newReleaseTest(t)
		in, _ := x.retrieval(t)
		_, err := x.a.Retrieve(context.Background(), in)
		require.NoError(t, err)
		_, err = x.a.Retrieve(context.Background(), in)
		requireStatus(t, err, codes.InvalidArgument, "freshness")
	})
	t.Run("a launch measurement that the policy does not admit", func(t *testing.T) {
		x := newReleaseTest(t)
		x.a.policies[storeTarget].Retrieve.Measurements = [][]byte{bytes.Repeat([]byte{0x77}, 32)}
		in, _ := x.retrieval(t)
		_, err := x.a.Retrieve(context.Background(), in)
		requireStatus(t, err, codes.PermissionDenied, "the launch measurement is not admitted")
	})
	t.Run("Attestation Results that are not affirming", func(t *testing.T) {
		x := newReleaseTest(t)
		key := newTestKey(t)
		x.psa.setAnswer(func(nonce, _ []byte, _ string) (string, string) {
			return "complete", signEAR(t, key, nonce, x.now, "PSA_IOT", "warning", psaAnnotated(psaMeasurement))
		})
		in, _ := x.retrieval(t)
		_, err := x.a.Retrieve(context.Background(), in)
		requireStatus(t, err, codes.PermissionDenied, "remote attestation failed")
	})
	t.Run("CEKpub that is no key of a suite of the container", func(t *testing.T) {
		x := newReleaseTest(t)
		in, _ := x.retrieval(t)
		in.CEKPub = []byte("not a key")
		_, err := x.a.Retrieve(context.Background(), in)
		requireStatus(t, err, codes.InvalidArgument, "CEKpub is neither")
	})
	t.Run("CEKpub of a suite that the Target does not accept", func(t *testing.T) {
		x := newReleaseTest(t)
		x.a.policies[storeTarget].Retrieve.AcceptableCEK = []string{container.AcceptableMLKEM768P256}
		in, _ := x.retrieval(t)
		_, err := x.a.Retrieve(context.Background(), in)
		requireStatus(t, err, codes.InvalidArgument, "is not acceptable for Target")
	})
	t.Run("the Secret Vault holds a credential of another type", func(t *testing.T) {
		x := newReleaseTest(t)
		x.vault.record["type"] = "api-key"
		in, _ := x.retrieval(t)
		_, err := x.a.Retrieve(context.Background(), in)
		requireStatus(t, err, codes.Unimplemented, `holds a credential of type "api-key"`)
	})
	t.Run("the Secret Vault holds no credential at the path", func(t *testing.T) {
		x := newReleaseTest(t)
		x.vault.status = http.StatusNotFound
		in, _ := x.retrieval(t)
		_, err := x.a.Retrieve(context.Background(), in)
		requireStatus(t, err, codes.NotFound, "holds no credential for the Target")
	})
	t.Run("the Secret Vault does not answer the read", func(t *testing.T) {
		x := newReleaseTest(t)
		x.vault.status = http.StatusServiceUnavailable
		in, _ := x.retrieval(t)
		_, err := x.a.Retrieve(context.Background(), in)
		requireStatus(t, err, codes.Unavailable, "the Secret Vault is unavailable")
	})
	t.Run("a record without the fields of a credential", func(t *testing.T) {
		x := newReleaseTest(t)
		delete(x.vault.record, "value")
		in, _ := x.retrieval(t)
		_, err := x.a.Retrieve(context.Background(), in)
		requireStatus(t, err, codes.Unavailable, "the Secret Vault is unavailable")
	})
}

func TestHashicorpVaultKind(t *testing.T) {
	kind, ok := secretVaultKindNamed("hashicorp")
	require.True(t, ok)
	require.True(t, kind.Store())
	require.ErrorContains(t, kind.Validate(&SecretVaultConfig{}), "url is required")
	require.ErrorContains(t, kind.Validate(&SecretVaultConfig{URL: "http://vault.example"}), "token_path is required")
	require.NoError(t, kind.Validate(&SecretVaultConfig{URL: "http://vault.example", TokenPath: "/run/token"}))

	_, store, err := kind.New(&SecretVaultConfig{URL: "http://127.0.0.1:1", TokenPath: filepath.Join(t.TempDir(), "absent")}, nil)
	require.NoError(t, err)
	_, err = store.Read(context.Background(), storeSecretPath)
	require.ErrorIs(t, err, ErrVaultUnavailable)
}

func TestConfigForATargetOfTwoModes(t *testing.T) {
	config := func() *Config {
		return &Config{
			Target: map[string]*TargetConfig{storeTarget: {
				Mode:                    constants.CredentialAcquisitionModeEnroll,
				Verifiers:               []string{"psa"},
				Measurements:            []string{hex.EncodeToString(psaMeasurement)},
				RetrieveCredentialTypes: []constants.CredentialType{constants.CredentialTypeJWT},
				SecretPath:              storeSecretPath,
			}},
			Verifier:           map[string]*VerifierConfig{"psa": {URL: "https://veraison.example", EARKeyPath: "/keys/veraison.jwk", EvidenceMediaTypes: []string{psaTokenMediaType}, Submods: []string{"PSA_IOT"}}},
			AcceptableEvidence: []string{psaTokenMediaType},
			SecretVault:        &SecretVaultConfig{SecretVaultKind: "hashicorp", URL: "http://vault.example:8200", TokenPath: "/run/token"},
		}
	}
	t.Run("one Target, x509 by Enrollment and jwt by Retrieval", func(t *testing.T) {
		policies, err := config().Validate()
		require.NoError(t, err)
		p := policies[storeTarget]
		require.Equal(t, constants.CredentialAcquisitionModeEnroll, p.Mode)
		require.NotNil(t, p.Retrieve)
		require.Equal(t, constants.CredentialAcquisitionModeRetrieve, p.Retrieve.Mode)
		require.Equal(t, []constants.CredentialType{constants.CredentialTypeJWT}, p.Retrieve.CredentialTypes)
		require.Equal(t, storeSecretPath, p.Retrieve.SecretPath)
		require.Equal(t, [][]byte{psaMeasurement}, p.Retrieve.Measurements)
		require.Equal(t, []string{"psa"}, p.Retrieve.Verifiers)
		require.Equal(t, p.ExpiresIn, p.Retrieve.ExpiresIn)
		require.Equal(t, []string{container.AcceptableMLKEM768P256, container.AcceptableDHKEMP256}, p.Retrieve.AcceptableCEK)
	})
	for _, tt := range []struct {
		name   string
		mutate func(*Config)
		err    string
	}{
		{name: "without a path of the credential", mutate: func(c *Config) { c.Target[storeTarget].SecretPath = "" }, err: "secret_path is required"},
		{name: "a Credential Type that is enrolled as well", mutate: func(c *Config) {
			c.Target[storeTarget].RetrieveCredentialTypes = []constants.CredentialType{constants.CredentialTypeX509}
		}, err: "is enrolled for the Target and cannot be retrieved as well"},
		{name: "a Credential Type that TACRA does not define", mutate: func(c *Config) {
			c.Target[storeTarget].RetrieveCredentialTypes = []constants.CredentialType{"token"}
		}, err: "is not defined by TACRA"},
		{name: "a suite that is not of the container", mutate: func(c *Config) { c.Target[storeTarget].AcceptableCEK = []string{"RSA"} }, err: "is not a suite of the hpke-base container"},
		{name: "a Secret Vault that the Server does not read itself", mutate: func(c *Config) {
			c.SecretVault = &SecretVaultConfig{URL: "https://vault.example"}
		}, err: "needs a secret_vault that this Server reads itself"},
		{name: "no Secret Vault", mutate: func(c *Config) { c.SecretVault = nil }, err: "needs a secret_vault that this Server reads itself"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := config()
			tt.mutate(c)
			_, err := c.Validate()
			require.ErrorContains(t, err, tt.err)
		})
	}
	t.Run("a Target in retrieve mode names the Verifiers and the measurements", func(t *testing.T) {
		c := config()
		c.Target[storeTarget] = &TargetConfig{Mode: constants.CredentialAcquisitionModeRetrieve, CredentialTypes: []constants.CredentialType{constants.CredentialTypeJWT},
			Verifiers: []string{"psa"}, Measurements: []string{hex.EncodeToString(psaMeasurement)}, SecretPath: storeSecretPath}
		policies, err := c.Validate()
		require.NoError(t, err)
		require.Equal(t, storeSecretPath, policies[storeTarget].SecretPath)
		require.Equal(t, [][]byte{psaMeasurement}, policies[storeTarget].Measurements)

		c.Target[storeTarget].Verifiers = nil
		_, err = c.Validate()
		require.ErrorContains(t, err, "at least one Verifier must be configured")

		c.Target[storeTarget].Verifiers = []string{"psa"}
		c.Target[storeTarget].RATSModel = constants.RATSModelPassport
		_, err = c.Validate()
		require.ErrorContains(t, err, "rats_model does not apply")
	})
}
