package cai

import (
	"crypto"
	"crypto/hpke"
	"encoding/json"
	"fmt"

	"github.com/fxamacker/cbor/v2"

	"github.com/TWI-Unified-Model/tacra/container"
	"github.com/TWI-Unified-Model/tacra/platform"
)

// MaxValiditySeconds is the longest validity of a retrieved credential that
// the CAI accepts.
const MaxValiditySeconds = 3600

// freshnessElement returns the freshness element that the Evidence binds, as
// the plug-in reports it in the unsigned claims of the Evidence. For
// absent-timestamp the element originates in the plug-in. When the claims name
// none, the element is the Handle.
func freshnessElement(ev *platform.Evidence, handle []byte) []byte {
	var claims map[string]any
	if err := cbor.Unmarshal(ev.Claims, &claims); err == nil {
		if element, ok := claims[platform.TSMClaimFreshnessElement].([]byte); ok && len(element) > 0 {
			return element
		}
	}
	return handle
}

// openContainer checks and opens the hpke-base container of a Retrieval. The
// container must name the Target, the freshness element and the Credential
// Hint that the Evidence bound, be sealed to the CEK of this request, and carry
// only items that the CAI accepts: with their key-block attributes, not
// exportable, not shared among instances, and valid for at most
// MaxValiditySeconds. The credential returned is the value of the first item.
func openContainer(raw []byte, cekPrivate crypto.PrivateKey, cekPub []byte, req AcquisitionRequest, element []byte) ([]byte, error) {
	var bundle container.Bundle
	if err := json.Unmarshal(raw, &bundle); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnwrap, err)
	}
	cek, ok := cekPrivate.(hpke.PrivateKey)
	if !ok {
		var err error
		if cek, err = container.DHKEMPrivateKey(cekPrivate); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrUnwrap, err)
		}
	}
	content, err := container.Open(&bundle, container.Expect{
		Target:         req.Target,
		Handle:         element,
		CredentialHint: req.Hint,
		CEK:            cek,
		CEKPub:         cekPub,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnwrap, err)
	}
	if err := container.CheckItems(content, false, MaxValiditySeconds); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnwrap, err)
	}
	if len(content.CredentialItems) == 0 {
		return nil, ErrEmptyCredential
	}
	credential, err := container.ItemOctets(content.CredentialItems[0])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnwrap, err)
	}
	return credential, nil
}
