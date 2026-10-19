package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	testAudience  = "tacra-server"
	testJWTIssuer = "tacra-cas"
	testWITIssuer = "https://wit.example.org"
	testJWTKid    = "jwt-1"
	testWITKid    = "wit-1"
	testDomain    = "example.org"
)

type testEnv struct {
	t         *testing.T
	dir       string
	ca        *x509.Certificate
	caKey     *ecdsa.PrivateKey
	jwtKey    *ecdsa.PrivateKey // published in a JWKS with testJWTKid
	jwtPEMKey *ecdsa.PrivateKey // published as a PEM public key, no kid
	witKey    *ecdsa.PrivateKey
	clientKey *ecdsa.PrivateKey
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	e := &testEnv{t: t, dir: t.TempDir()}
	e.ca, e.caKey = newCA(t, "rup-test-ca")
	e.jwtKey = mustECKey(t)
	e.jwtPEMKey = mustECKey(t)
	e.witKey = mustECKey(t)
	e.clientKey = mustECKey(t)
	return e
}

func (e *testEnv) config() Config {
	t := e.t
	serverCA, serverCAKey := newCA(t, "rup-test-server-ca")
	serverKey := mustECKey(t)
	serverCert := issue(t, serverCA, serverCAKey, serverKey.Public(), "localhost", nil, x509.ExtKeyUsageServerAuth)
	keyDER, err := x509.MarshalPKCS8PrivateKey(serverKey)
	if err != nil {
		t.Fatal(err)
	}
	return Config{
		Audience:         testAudience,
		ClockSkewSeconds: 5,
		Accept:           [][]string{{FormatX509}, {FormatWIC}, {FormatWIT}, {FormatJWT}},
		TLS: TLSConfig{
			CertFile: e.write("server-cert.pem", pemCert(serverCert)),
			KeyFile:  e.write("server-key.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})),
		},
		X509: X509Config{CAFiles: []string{e.write("ca.pem", pemCert(e.ca))}},
		WIC: WICConfig{
			CAFiles:      []string{filepath.Join(e.dir, "ca.pem")},
			URISchemes:   []string{"spiffe", "wimse"},
			TrustDomains: []string{testDomain},
		},
		JWT: JWTConfig{
			Issuers:        []string{testJWTIssuer},
			Algorithms:     []string{"ES256"},
			JWKSFiles:      []string{e.writeJWKS("jwt-jwks.json", testJWTKid, e.jwtKey.Public())},
			PublicKeyFiles: []string{e.write("jwt-pub.pem", pemPublicKey(t, e.jwtPEMKey.Public()))},
		},
		WIT: WITConfig{
			Issuers:    []string{testWITIssuer},
			Algorithms: []string{"ES256"},
			JWKSFiles:  []string{e.writeJWKS("wit-jwks.json", testWITKid, e.witKey.Public())},
		},
	}
}

func (e *testEnv) verifier(mutate func(*Config)) *Verifier {
	e.t.Helper()
	cfg := e.config()
	if mutate != nil {
		mutate(&cfg)
	}
	v, err := New(cfg)
	if err != nil {
		e.t.Fatalf("New: %v", err)
	}
	return v
}

func (e *testEnv) write(name string, data []byte) string {
	e.t.Helper()
	path := filepath.Join(e.dir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		e.t.Fatal(err)
	}
	return path
}

func (e *testEnv) writeJWKS(name, kid string, pub crypto.PublicKey) string {
	e.t.Helper()
	k := jwkFor(e.t, pub)
	k["kid"] = kid
	b, err := json.Marshal(map[string]any{"keys": []any{k}})
	if err != nil {
		e.t.Fatal(err)
	}
	return e.write(name, b)
}

// clientCert issues a client certificate for e.clientKey from the test CA.
func (e *testEnv) clientCert(uris ...string) *x509.Certificate {
	return issue(e.t, e.ca, e.caKey, e.clientKey.Public(), "workload-a", uris, x509.ExtKeyUsageClientAuth)
}

func (e *testEnv) jwtClaims() jwt.MapClaims {
	return jwt.MapClaims{
		"iss": testJWTIssuer,
		"aud": testAudience,
		"sub": "jwt-subject",
		"exp": time.Now().Add(time.Hour).Unix(),
	}
}

func (e *testEnv) witClaims(bound crypto.PublicKey) jwt.MapClaims {
	return jwt.MapClaims{
		"iss": testWITIssuer,
		"sub": "wimse://" + testDomain + "/workload-a",
		"exp": time.Now().Add(time.Hour).Unix(),
		"cnf": map[string]any{"jwk": jwkFor(e.t, bound)},
	}
}

func signJWT(t *testing.T, method jwt.SigningMethod, key any, kid, typ string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(method, claims)
	if kid != "" {
		tok.Header["kid"] = kid
	}
	if typ != "" {
		tok.Header["typ"] = typ
	}
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func signES(t *testing.T, key *ecdsa.PrivateKey, kid, typ string, claims jwt.MapClaims) string {
	t.Helper()
	return signJWT(t, jwt.SigningMethodES256, key, kid, typ, claims)
}

// bearerJWT is a valid bearer token signed by the JWKS-published issuer key.
func (e *testEnv) bearerJWT() string {
	return signES(e.t, e.jwtKey, testJWTKid, "", e.jwtClaims())
}

func request(certs []*x509.Certificate, headers map[string]string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "https://rup.example/", nil)
	if len(certs) > 0 {
		r.TLS = &tls.ConnectionState{PeerCertificates: certs}
	} else {
		r.TLS = &tls.ConnectionState{}
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func expectFormats(t *testing.T, p *Principal, err error, want ...string) {
	t.Helper()
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if !slices.Equal(p.Formats, want) {
		t.Fatalf("formats = %v, want %v", p.Formats, want)
	}
}

func expectReject(t *testing.T, p *Principal, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected rejection, got principal %+v", p)
	}
}

func TestX509(t *testing.T) {
	e := newTestEnv(t)
	v := e.verifier(nil)
	p, err := v.Authenticate(request([]*x509.Certificate{e.clientCert()}, nil))
	expectFormats(t, p, err, FormatX509)
	if p.Subject != "workload-a" {
		t.Errorf("subject = %q", p.Subject)
	}
}

func TestX509PlusJWT(t *testing.T) {
	e := newTestEnv(t)
	v := e.verifier(nil)
	p, err := v.Authenticate(request([]*x509.Certificate{e.clientCert()}, map[string]string{"Authorization": "Bearer " + e.bearerJWT()}))
	expectFormats(t, p, err, FormatX509, FormatJWT)
	if p.Subject != "workload-a" || p.Issuer != testJWTIssuer {
		t.Errorf("principal = %+v", p)
	}
}

func TestJWTBearer(t *testing.T) {
	e := newTestEnv(t)
	v := e.verifier(nil)
	for name, tok := range map[string]string{
		"ES256 key from JWKS":       e.bearerJWT(),
		"ES256 key from PEM public": signES(t, e.jwtPEMKey, "", "", e.jwtClaims()),
	} {
		t.Run(name, func(t *testing.T) {
			p, err := v.Authenticate(request(nil, map[string]string{"Authorization": "bearer " + tok}))
			expectFormats(t, p, err, FormatJWT)
			if p.Subject != "jwt-subject" {
				t.Errorf("subject = %q", p.Subject)
			}
		})
	}
}

func TestJWTRejected(t *testing.T) {
	e := newTestEnv(t)
	v := e.verifier(nil)
	with := func(k string, val any) jwt.MapClaims {
		c := e.jwtClaims()
		if val == nil {
			delete(c, k)
		} else {
			c[k] = val
		}
		return c
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := pemPublicKey(t, e.jwtPEMKey.Public())
	cases := map[string]string{
		"expired":        signES(t, e.jwtKey, testJWTKid, "", with("exp", time.Now().Add(-time.Hour).Unix())),
		"missing exp":    signES(t, e.jwtKey, testJWTKid, "", with("exp", nil)),
		"wrong audience": signES(t, e.jwtKey, testJWTKid, "", with("aud", "someone-else")),
		"wrong issuer":   signES(t, e.jwtKey, testJWTKid, "", with("iss", "evil")),
		"disallowed alg": signJWT(t, jwt.SigningMethodES384, p384, "", "", e.jwtClaims()),
		"unknown key":    signES(t, mustECKey(t), testJWTKid, "", e.jwtClaims()),
		"HMAC token":     signJWT(t, jwt.SigningMethodHS256, []byte("0123456789abcdef0123456789abcdef"), "", "", e.jwtClaims()),
		// Classic key confusion: HMAC keyed with the RUP's own public key bytes.
		"public key as HMAC secret": signJWT(t, jwt.SigningMethodHS256, pubPEM, "", "", e.jwtClaims()),
		"WIT as bearer":             signES(t, e.witKey, testWITKid, witType, e.witClaims(e.clientKey.Public())),
		"malformed token":           "not-a-jwt",
	}
	for name, tok := range cases {
		t.Run(name, func(t *testing.T) {
			p, err := v.Authenticate(request(nil, map[string]string{"Authorization": "Bearer " + tok}))
			expectReject(t, p, err)
		})
	}
	t.Run("HMAC rejected even when listed", func(t *testing.T) {
		cfg := e.config()
		cfg.JWT.Algorithms = append(cfg.JWT.Algorithms, "HS256")
		if _, err := New(cfg); err == nil {
			t.Error("configuration with an HMAC algorithm accepted")
		}
	})
	t.Run("unsupported scheme", func(t *testing.T) {
		p, err := v.Authenticate(request(nil, map[string]string{"Authorization": "Basic dXNlcjpwYXNz"}))
		expectReject(t, p, err)
	})
}

func TestWIC(t *testing.T) {
	e := newTestEnv(t)
	v := e.verifier(nil)
	for _, id := range []string{"spiffe://" + testDomain + "/workload-a", "wimse://" + testDomain + "/workload-a"} {
		t.Run(id, func(t *testing.T) {
			p, err := v.Authenticate(request([]*x509.Certificate{e.clientCert(id)}, nil))
			expectFormats(t, p, err, FormatWIC)
			if p.Subject != id {
				t.Errorf("subject = %q, want %q", p.Subject, id)
			}
		})
	}
	t.Run("non-WIC URI SAN is plain X.509", func(t *testing.T) {
		p, err := v.Authenticate(request([]*x509.Certificate{e.clientCert("https://localhost:8443")}, nil))
		expectFormats(t, p, err, FormatX509)
	})
}

func TestWICRejected(t *testing.T) {
	e := newTestEnv(t)
	v := e.verifier(nil)
	otherCA, otherKey := newCA(t, "other-ca")
	cases := map[string]*x509.Certificate{
		"wrong trust domain": e.clientCert("spiffe://evil.example/workload-a"),
		"two identifiers":    e.clientCert("spiffe://"+testDomain+"/a", "wimse://"+testDomain+"/b"),
		"untrusted CA": issue(t, otherCA, otherKey, e.clientKey.Public(), "workload-a",
			[]string{"spiffe://" + testDomain + "/workload-a"}, x509.ExtKeyUsageClientAuth),
	}
	for name, cert := range cases {
		t.Run(name, func(t *testing.T) {
			p, err := v.Authenticate(request([]*x509.Certificate{cert}, nil))
			expectReject(t, p, err)
		})
	}
	t.Run("no WIC trust anchors", func(t *testing.T) {
		v := e.verifier(func(c *Config) { c.WIC.CAFiles = nil })
		p, err := v.Authenticate(request([]*x509.Certificate{e.clientCert("spiffe://" + testDomain + "/a")}, nil))
		expectReject(t, p, err)
	})
}

func TestWITBoundToTLSKey(t *testing.T) {
	e := newTestEnv(t)
	v := e.verifier(nil)
	wit := signES(t, e.witKey, testWITKid, witType, e.witClaims(e.clientKey.Public()))

	t.Run("untrusted self-signed client cert", func(t *testing.T) {
		self := selfSigned(t, e.clientKey)
		p, err := v.Authenticate(request([]*x509.Certificate{self}, map[string]string{HeaderWIT: wit}))
		expectFormats(t, p, err, FormatWIT)
		if p.Subject != "wimse://"+testDomain+"/workload-a" || p.Issuer != testWITIssuer {
			t.Errorf("principal = %+v", p)
		}
	})
	t.Run("trusted client cert", func(t *testing.T) {
		p, err := v.Authenticate(request([]*x509.Certificate{e.clientCert()}, map[string]string{HeaderWIT: wit}))
		expectFormats(t, p, err, FormatWIT, FormatX509)
	})
}

func TestWITRejected(t *testing.T) {
	e := newTestEnv(t)
	v := e.verifier(nil)
	cert := []*x509.Certificate{selfSigned(t, e.clientKey)}
	claims := func(mutate func(jwt.MapClaims)) jwt.MapClaims {
		c := e.witClaims(e.clientKey.Public())
		mutate(c)
		return c
	}
	cases := map[string]struct {
		certs []*x509.Certificate
		token string
	}{
		"no client certificate": {nil, signES(t, e.witKey, testWITKid, witType, e.witClaims(e.clientKey.Public()))},
		"bound to another key":  {cert, signES(t, e.witKey, testWITKid, witType, e.witClaims(mustECKey(t).Public()))},
		"wrong typ":             {cert, signES(t, e.witKey, testWITKid, "JWT", e.witClaims(e.clientKey.Public()))},
		"unknown signing key":   {cert, signES(t, mustECKey(t), testWITKid, witType, e.witClaims(e.clientKey.Public()))},
		"expired": {cert, signES(t, e.witKey, testWITKid, witType,
			claims(func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Hour).Unix() }))},
		"untrusted issuer": {cert, signES(t, e.witKey, testWITKid, witType,
			claims(func(c jwt.MapClaims) { c["iss"] = "https://evil.example" }))},
		"missing cnf": {cert, signES(t, e.witKey, testWITKid, witType,
			claims(func(c jwt.MapClaims) { delete(c, "cnf") }))},
		"missing sub": {cert, signES(t, e.witKey, testWITKid, witType,
			claims(func(c jwt.MapClaims) { delete(c, "sub") }))},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			p, err := v.Authenticate(request(tc.certs, map[string]string{HeaderWIT: tc.token}))
			expectReject(t, p, err)
		})
	}
}

func TestUntrustedCertificateAloneRejected(t *testing.T) {
	e := newTestEnv(t)
	v := e.verifier(nil)
	p, err := v.Authenticate(request([]*x509.Certificate{selfSigned(t, e.clientKey)}, nil))
	expectReject(t, p, err)
	p, err = v.Authenticate(request(nil, nil))
	expectReject(t, p, err)
}

func TestAcceptCombination(t *testing.T) {
	e := newTestEnv(t)
	v := e.verifier(func(c *Config) { c.Accept = [][]string{{FormatX509, FormatJWT}} })
	cert := []*x509.Certificate{e.clientCert()}
	p, err := v.Authenticate(request(cert, nil))
	expectReject(t, p, err)

	p, err = v.Authenticate(request(cert, map[string]string{"Authorization": "Bearer " + e.bearerJWT()}))
	expectFormats(t, p, err, FormatX509, FormatJWT)
}

func TestMiddleware(t *testing.T) {
	e := newTestEnv(t)
	v := e.verifier(nil)
	var rejected error
	var got *Principal
	h := v.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = PrincipalFrom(r.Context())
	}), func(_ *http.Request, err error) { rejected = err })

	w := httptest.NewRecorder()
	h.ServeHTTP(w, request(nil, nil))
	if w.Code != http.StatusUnauthorized || rejected == nil || w.Header().Get(HeaderCredentialFormat) != "" {
		t.Fatalf("rejection: code=%d err=%v header=%q", w.Code, rejected, w.Header().Get(HeaderCredentialFormat))
	}
	if strings.Contains(w.Body.String(), rejected.Error()) {
		t.Error("401 body leaks the rejection reason")
	}

	w = httptest.NewRecorder()
	h.ServeHTTP(w, request([]*x509.Certificate{e.clientCert()}, map[string]string{"Authorization": "Bearer " + e.bearerJWT()}))
	if w.Code != http.StatusOK || w.Header().Get(HeaderCredentialFormat) != "x509,jwt" || got == nil {
		t.Fatalf("success: code=%d header=%q principal=%+v", w.Code, w.Header().Get(HeaderCredentialFormat), got)
	}
}

func TestLoadConfig(t *testing.T) {
	cfg, err := LoadConfig(filepath.Join("testdata", "rup.json"))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := cfg.TLS.CertFile, filepath.Join("testdata", "server-cert.pem"); got != want {
		t.Errorf("cert_file = %q, want %q (relative to config dir)", got, want)
	}
	if got := cfg.WIT.JWKSFiles[0]; got != "/etc/rup/wit-jwks.json" {
		t.Errorf("absolute path rewritten to %q", got)
	}

	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte(`{"audience":"a","unknown":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(bad); err == nil {
		t.Error("unknown field accepted")
	}
}

func TestValidate(t *testing.T) {
	e := newTestEnv(t)
	cases := map[string]func(*Config){
		"none algorithm":     func(c *Config) { c.JWT.Algorithms = []string{"none"} },
		"HMAC JWT algorithm": func(c *Config) { c.JWT.Algorithms = []string{"HS256"} },
		"HMAC WIT algorithm": func(c *Config) { c.WIT.Algorithms = []string{"HS256"} },
		"unknown format":     func(c *Config) { c.Accept = [][]string{{"saml"}} },
		"empty combination":  func(c *Config) { c.Accept = [][]string{{}} },
		"no accept":          func(c *Config) { c.Accept = nil },
		"no audience":        func(c *Config) { c.Audience = "" },
		"negative skew":      func(c *Config) { c.ClockSkewSeconds = -1 },
		"public key file is a private key": func(c *Config) {
			c.JWT.PublicKeyFiles = []string{c.TLS.KeyFile}
		},
		"missing public key file": func(c *Config) {
			c.WIT.PublicKeyFiles = []string{filepath.Join(e.dir, "absent.pem")}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := e.config()
			mutate(&cfg)
			if _, err := New(cfg); err == nil {
				t.Error("invalid configuration accepted")
			}
		})
	}
}

func TestParseJWK(t *testing.T) {
	ed, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for name, pub := range map[string]crypto.PublicKey{
		"EC P-256": mustECKey(t).Public(),
		"Ed25519":  ed,
		"RSA":      &rsaKey.PublicKey,
	} {
		t.Run(name, func(t *testing.T) {
			got, err := parseJWK(jwkFor(t, pub))
			if err != nil || !samePublicKey(got, pub) {
				t.Fatalf("round trip failed: %v", err)
			}
		})
	}

	zero := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	smallRSA, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	for name, jwk := range map[string]map[string]any{
		"EC point not on curve": {"kty": "EC", "crv": "P-256", "x": zero, "y": zero},
		"unsupported curve":     {"kty": "EC", "crv": "secp256k1", "x": zero, "y": zero},
		"RSA below 2048 bits":   jwkFor(t, &smallRSA.PublicKey),
		"unknown kty":           {"kty": "oct", "k": zero},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseJWK(jwk); err == nil {
				t.Error("invalid JWK accepted")
			}
		})
	}
}

func mustECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func newCA(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key := mustECKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func issue(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, pub crypto.PublicKey, cn string, uris []string, eku x509.ExtKeyUsage) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{eku},
		DNSNames:     []string{cn},
	}
	for _, s := range uris {
		u, err := url.Parse(s)
		if err != nil {
			t.Fatal(err)
		}
		tmpl.URIs = append(tmpl.URIs, u)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, pub, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func selfSigned(t *testing.T, key *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "self-signed-workload"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func pemCert(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

func pemPublicKey(t *testing.T, pub crypto.PublicKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func jwkFor(t *testing.T, pub crypto.PublicKey) map[string]any {
	t.Helper()
	b64 := base64.RawURLEncoding.EncodeToString
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		point, err := k.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		size := (k.Curve.Params().BitSize + 7) / 8
		return map[string]any{"kty": "EC", "crv": k.Curve.Params().Name, "x": b64(point[1 : 1+size]), "y": b64(point[1+size:])}
	case ed25519.PublicKey:
		return map[string]any{"kty": "OKP", "crv": "Ed25519", "x": b64(k)}
	case *rsa.PublicKey:
		return map[string]any{"kty": "RSA", "n": b64(k.N.Bytes()), "e": b64(big.NewInt(int64(k.E)).Bytes())}
	default:
		t.Fatalf("unsupported key %T", pub)
		return nil
	}
}
