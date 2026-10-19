package main

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// HeaderWIT carries a WIMSE Workload Identity Token bound to the mTLS client key.
const HeaderWIT = "Workload-Identity-Token"

const witType = "wit+jwt"

// keySet holds public verification keys only, so the RUP can verify but never mint tokens.
type keySet []publicKey

func (ks keySet) keyfunc(t *jwt.Token) (any, error) {
	if _, ok := t.Method.(*jwt.SigningMethodHMAC); ok {
		return nil, errors.New("HMAC-signed tokens are not accepted")
	}
	kid, _ := t.Header["kid"].(string)
	var keys []jwt.VerificationKey
	for _, k := range ks {
		if kid == "" || k.kid == "" || k.kid == kid {
			keys = append(keys, k.key)
		}
	}
	if len(keys) == 0 {
		return nil, errors.New("no verification key for token")
	}
	return jwt.VerificationKeySet{Keys: keys}, nil
}

func loadKeySet(jwksFiles, pemFiles []string) (keySet, error) {
	keys, err := loadJWKS(jwksFiles)
	if err != nil {
		return nil, err
	}
	for _, file := range pemFiles {
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("rup: public key: %w", err)
		}
		block, _ := pem.Decode(b)
		if block == nil || block.Type != "PUBLIC KEY" {
			return nil, fmt.Errorf("rup: public key %s must be PEM PUBLIC KEY", file)
		}
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("rup: public key %s: %w", file, err)
		}
		keys = append(keys, publicKey{key: pub})
	}
	return keys, nil
}

func isWITType(t *jwt.Token) bool {
	typ, _ := t.Header["typ"].(string)
	return strings.EqualFold(typ, witType)
}

func (v *Verifier) parser(algorithms []string, opts ...jwt.ParserOption) *jwt.Parser {
	return jwt.NewParser(append([]jwt.ParserOption{
		jwt.WithValidMethods(algorithms),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(v.skew),
		jwt.WithTimeFunc(v.now),
	}, opts...)...)
}

func (v *Verifier) verifyJWT(raw string) (subject, issuer string, err error) {
	claims := jwt.MapClaims{}
	_, err = v.parser(v.cfg.JWT.Algorithms, jwt.WithAudience(v.cfg.Audience)).
		ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
			if isWITType(t) {
				return nil, errors.New("WIT presented as a bearer token")
			}
			return v.jwtKeys.keyfunc(t)
		})
	if err != nil {
		return "", "", fmt.Errorf("JWT: %w", err)
	}
	issuer, _ = claims.GetIssuer()
	if !slices.Contains(v.cfg.JWT.Issuers, issuer) {
		return "", "", errors.New("JWT: issuer is not trusted")
	}
	subject, _ = claims.GetSubject()
	return subject, issuer, nil
}

// verifyWIT checks the WIT and that its cnf key is the key the client proved
// possession of in the TLS handshake.
func (v *Verifier) verifyWIT(raw string, leaf *x509.Certificate) (subject, issuer string, err error) {
	if leaf == nil {
		return "", "", errors.New("WIT requires an mTLS client certificate")
	}
	if len(v.cfg.WIT.Issuers) == 0 {
		return "", "", errors.New("WIT presented but no WIT issuers are configured")
	}
	claims := jwt.MapClaims{}
	_, err = v.parser(v.cfg.WIT.Algorithms).ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		if !isWITType(t) {
			return nil, fmt.Errorf("token typ is not %s", witType)
		}
		return v.witKeys.keyfunc(t)
	})
	if err != nil {
		return "", "", fmt.Errorf("WIT: %w", err)
	}
	issuer, _ = claims.GetIssuer()
	if !slices.Contains(v.cfg.WIT.Issuers, issuer) {
		return "", "", errors.New("WIT: issuer is not trusted")
	}
	subject, _ = claims.GetSubject()
	if subject == "" {
		return "", "", errors.New("WIT: sub is required")
	}
	cnf, _ := claims["cnf"].(map[string]any)
	jwk, _ := cnf["jwk"].(map[string]any)
	if jwk == nil {
		return "", "", errors.New("WIT: cnf.jwk is required")
	}
	bound, err := parseJWK(jwk)
	if err != nil {
		return "", "", fmt.Errorf("WIT: cnf.jwk: %w", err)
	}
	if !samePublicKey(bound, leaf.PublicKey) {
		return "", "", errors.New("WIT: not bound to the TLS client key")
	}
	return subject, issuer, nil
}

func samePublicKey(a, b crypto.PublicKey) bool {
	ab, err := x509.MarshalPKIXPublicKey(a)
	if err != nil {
		return false
	}
	bb, err := x509.MarshalPKIXPublicKey(b)
	if err != nil {
		return false
	}
	return bytes.Equal(ab, bb)
}
