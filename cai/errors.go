package cai

import (
	"errors"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	ErrNilClient             = errors.New("cai: nil client")
	ErrNilPlugin             = errors.New("cai: platform plug-in is required")
	ErrNilCAAPI              = errors.New("cai: CAAPI client is required")
	ErrInvalidTarget         = errors.New("cai: invalid target")
	ErrInvalidCredentialType = errors.New("cai: invalid credential type")
	ErrInvalidChallenge      = errors.New("cai: verifier challenge must be 8-64 bytes")
	ErrUnsupportedMechanism  = errors.New("cai: unsupported credential acquisition mechanism")
	ErrEmptyCredential       = errors.New("cai: CAS returned an empty credential")
	ErrUnwrap                = errors.New("cai: failed to unwrap retrieved credential")
)

// Error is a CAAPI RPC failure, with the gRPC status preserved when present.
type Error struct {
	Op      string
	Message string
	Err     error
}

func (e *Error) Error() string {
	if e == nil {
		return "cai: <nil>"
	}
	if e.Message != "" {
		return fmt.Sprintf("cai: %s: %s", e.Op, e.Message)
	}
	return fmt.Sprintf("cai: %s: %v", e.Op, e.Err)
}

func (e *Error) Unwrap() error { return e.Err }

// GRPCStatus exposes the underlying gRPC status, if any.
func (e *Error) GRPCStatus() *status.Status {
	if e == nil {
		return nil
	}
	if st, ok := status.FromError(e.Err); ok {
		return st
	}
	return nil
}

func rpcError(op string, err error) error {
	if err == nil {
		return nil
	}
	st, ok := status.FromError(err)
	if !ok {
		return &Error{Op: op, Err: err, Message: err.Error()}
	}
	if st.Code() == codes.OK {
		return nil
	}
	return &Error{Op: op, Err: err, Message: st.Message()}
}
