// Command server is the demo RATS-unaware Relying Party. It authenticates
// X.509, WIMSE WIC, WIMSE WIT and bearer-JWT credentials from their standard
// wire presentation using only configured trust anchors, independent of how
// TACRA acquired them.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// HeaderCredentialFormat reports the verified formats on successful responses.
const HeaderCredentialFormat = "X-RUP-Credential-Format"

const bearerPrefix = "bearer "

// formatOrder ranks formats from strongest identity binding to weakest; the
// first verified one supplies Principal.Subject.
var formatOrder = []string{FormatWIT, FormatWIC, FormatX509, FormatJWT}

// Principal is an authenticated caller.
type Principal struct {
	Formats []string
	Subject string
	Issuer  string
}

// Verifier authenticates requests against a Config.
type Verifier struct {
	cfg        Config
	skew       time.Duration
	now        func() time.Time
	serverCert tls.Certificate

	x509Roots       *x509.CertPool
	wicRoots        *x509.CertPool
	wicSchemes      map[string]bool
	wicTrustDomains map[string]bool
	jwtKeys         keySet
	witKeys         keySet
}

// New loads every trust anchor named by cfg.
func New(cfg Config) (*Verifier, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	serverCert, err := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("rup: server certificate: %w", err)
	}
	v := &Verifier{
		cfg:             cfg,
		skew:            time.Duration(cfg.ClockSkewSeconds) * time.Second,
		now:             time.Now,
		serverCert:      serverCert,
		wicSchemes:      lowerSet(cfg.WIC.URISchemes),
		wicTrustDomains: lowerSet(cfg.WIC.TrustDomains),
	}
	if v.x509Roots, err = loadCertPool(cfg.X509.CAFiles); err != nil {
		return nil, err
	}
	if v.wicRoots, err = loadCertPool(cfg.WIC.CAFiles); err != nil {
		return nil, err
	}
	if v.jwtKeys, err = loadKeySet(cfg.JWT.JWKSFiles, cfg.JWT.PublicKeyFiles); err != nil {
		return nil, err
	}
	if v.witKeys, err = loadKeySet(cfg.WIT.JWKSFiles, cfg.WIT.PublicKeyFiles); err != nil {
		return nil, err
	}
	return v, nil
}

// TLSConfig requests, but does not require or chain-verify, a client
// certificate: chains are verified per format by Authenticate, and a WIT may
// be bound to an otherwise untrusted key. Go's TLS server still verifies the
// client's CertificateVerify, so a presented certificate proves key possession.
func (v *Verifier) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{v.serverCert},
		ClientAuth:   tls.RequestClientCert,
	}
}

// Authenticate verifies every credential the request presents. Any presented
// credential that fails verification rejects the request; otherwise the
// verified formats must satisfy one of the configured combinations.
func (v *Verifier) Authenticate(r *http.Request) (*Principal, error) {
	subjects := map[string]string{}
	var issuer string
	var leaf *x509.Certificate

	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		leaf = r.TLS.PeerCertificates[0]
		format, subject, err := v.classifyPeer(r.TLS.PeerCertificates, v.now())
		if err != nil {
			return nil, err
		}
		if format != "" {
			subjects[format] = subject
		}
	}
	if raw := r.Header.Get(HeaderWIT); raw != "" {
		subject, iss, err := v.verifyWIT(raw, leaf)
		if err != nil {
			return nil, err
		}
		subjects[FormatWIT] = subject
		issuer = iss
	}
	if auth := r.Header.Get("Authorization"); auth != "" {
		if len(auth) <= len(bearerPrefix) || !strings.EqualFold(auth[:len(bearerPrefix)], bearerPrefix) {
			return nil, errors.New("unsupported Authorization scheme")
		}
		subject, iss, err := v.verifyJWT(strings.TrimSpace(auth[len(bearerPrefix):]))
		if err != nil {
			return nil, err
		}
		subjects[FormatJWT] = subject
		if issuer == "" {
			issuer = iss
		}
	}

	p := &Principal{Issuer: issuer}
	for _, f := range formatOrder {
		if subject, ok := subjects[f]; ok {
			p.Formats = append(p.Formats, f)
			if p.Subject == "" {
				p.Subject = subject
			}
		}
	}
	if !v.accepted(subjects) {
		return nil, fmt.Errorf("credential combination %v is not accepted", p.Formats)
	}
	return p, nil
}

func (v *Verifier) accepted(present map[string]string) bool {
	for _, combo := range v.cfg.Accept {
		ok := true
		for _, f := range combo {
			if _, found := present[f]; !found {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

type principalKey struct{}

// Middleware authenticates each request, answering 401 with a generic body on
// failure. onReject, if set, receives the reason; it never contains tokens.
func (v *Verifier) Middleware(next http.Handler, onReject func(*http.Request, error)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, err := v.Authenticate(r)
		if err != nil {
			if onReject != nil {
				onReject(r, err)
			}
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set(HeaderCredentialFormat, strings.Join(p.Formats, ","))
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey{}, p)))
	})
}

// PrincipalFrom returns the Principal stored by Middleware.
func PrincipalFrom(ctx context.Context) (*Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(*Principal)
	return p, ok
}

func lowerSet(values []string) map[string]bool {
	m := make(map[string]bool, len(values))
	for _, s := range values {
		m[strings.ToLower(s)] = true
	}
	return m
}
