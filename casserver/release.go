package casserver

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/TWI-Unified-Model/tacra/container"
)

// The key-block attributes and the validity of a credential that this Server
// releases from a Secret Vault it reads itself: a bearer credential, which the
// Workload presents to authenticate itself, valid for an hour before the
// Workload retrieves it again.
const (
	releasedPurpose         = "authenticate"
	releasedAlgorithm       = "opaque-bearer"
	releasedValiditySeconds = 3600
	kidLength               = 16
)

// release is Retrieval when this Server reads the Secret Vault itself: it
// appraises the Evidence as for Enrollment, with CEKpub as the subject of the
// binding, reads the credential for the Target and seals it to CEKpub in the
// hpke-base container.
func (a *Acquirer) release(ctx context.Context, p *Policy, in Retrieval, profile string) ([]byte, error) {
	suite, err := container.SuiteOfCEKPub(in.CEKPub)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	if !slices.ContainsFunc(p.AcceptableCEK, func(token string) bool {
		accepted, ok := container.SuiteOf(token)
		return ok && accepted == suite
	}) {
		return nil, status.Errorf(codes.InvalidArgument, "CEKpub is of the suite %s, which is not acceptable for Target %q", suite.KEM, p.Name)
	}
	res, err := a.appraise(ctx, p, in.Evidence, profile, BindingValue(in.FreshnessElement, in.Target, in.CEKPub))
	if err != nil {
		return nil, err
	}
	// The Credential Type is checked after the attestation, as in Enroll.
	if err := p.servesCredentialType(in.CredentialType); err != nil {
		return nil, err
	}
	stored, err := a.store.Read(ctx, p.SecretPath)
	switch {
	case errors.Is(err, ErrNoStoredCredential):
		return nil, status.Errorf(codes.NotFound, "%v", err)
	case err != nil:
		a.log.WithError(err).WithField("target", p.Name).Warn("Reading the Secret Vault failed")
		return nil, status.Errorf(codes.Unavailable, "%v", ErrVaultUnavailable)
	}
	if in.CredentialType != "" && stored.Type != in.CredentialType {
		return nil, status.Errorf(codes.Unimplemented, "the Secret Vault holds a credential of type %q for Target %q, not %q", stored.Type, p.Name, in.CredentialType)
	}
	group := groupID(res.Measurement, res.Family, in.Target, in.CredentialHint)
	notExportable := false
	sealed, err := container.Seal(in.CEKPub,
		container.AAD{GroupID: group, Target: container.B64(in.Target), Handle: in.FreshnessElement, CredentialHint: in.CredentialHint},
		container.Content{
			CredentialItems: []container.Item{{
				Type:       string(stored.Type),
				Format:     stored.Format,
				Value:      base64.RawURLEncoding.EncodeToString(stored.Value),
				Kid:        group[:kidLength],
				Purpose:    []string{releasedPurpose},
				Algorithm:  releasedAlgorithm,
				Exportable: &notExportable,
			}},
			Metadata: map[string]any{"secret_version": stored.Version, "validity_seconds": releasedValiditySeconds},
		})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "sealing the credential: %v", err)
	}
	raw, err := json.Marshal(sealed)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "encoding the container: %v", err)
	}
	a.log.WithFields(logrus.Fields{
		"target":      p.Name,
		"verifier":    res.Verifier,
		"family":      res.Family,
		"measurement": hex.EncodeToString(res.Measurement),
		"group":       group,
		"type":        string(stored.Type),
	}).Info("Credential released from the Secret Vault")
	return raw, nil
}

// groupID names the credential group of a release: the Workloads of one
// launch measurement on one platform family that retrieve for one Target with
// one Credential Hint. It is the SHA-256 of those four values, in hex.
func groupID(measurement []byte, family, target, hint string) string {
	digest := sha256.Sum256([]byte(hex.EncodeToString(measurement) + "|" + family + "|" + target + "|" + hint))
	return hex.EncodeToString(digest[:])
}
