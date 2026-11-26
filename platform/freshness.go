package platform

import (
	"fmt"
	"time"
)

// FreshnessElement returns the value that a back-end binds as the freshness
// element for req: the Handle for the present kinds, the local epoch (which the
// CAI passes as the Handle) for absent-epoch, eight octets of Unix time for
// absent-timestamp (the Handle of the request when it carries them, now when it
// does not), and nothing for absent-none.
func FreshnessElement(req EvidenceRequest, now time.Time) ([]byte, error) {
	switch req.FreshnessKind {
	case FreshnessKindPresentNonce, FreshnessKindPresentEpoch, FreshnessKindAbsentEpoch:
		if n := len(req.FreshnessHandle); n < minNonceSize || n > maxNonceSize {
			return nil, fmt.Errorf("%w: %d octets", ErrInvalidFreshnessHandle, n)
		}
		return append([]byte(nil), req.FreshnessHandle...), nil
	case FreshnessKindAbsentTimestamp:
		if len(req.FreshnessHandle) == TimestampElementSize {
			return append([]byte(nil), req.FreshnessHandle...), nil
		}
		if len(req.FreshnessHandle) != 0 {
			return nil, fmt.Errorf("%w: absent-timestamp needs %d octets", ErrFreshnessElement, TimestampElementSize)
		}
		return TimestampElement(now.Unix()), nil
	case FreshnessKindAbsentNone:
		if len(req.FreshnessHandle) != 0 {
			return nil, fmt.Errorf("%w: absent-none needs none", ErrFreshnessElement)
		}
		return nil, nil
	default:
		return nil, fmt.Errorf("%w: kind %d", ErrFreshnessElement, req.FreshnessKind)
	}
}
