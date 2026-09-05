// Package cai is the TACRA Credential Acquisition Interface (CAI).
//
// The Attester calls AcquireCredential; CAI talks to the platform plug-in
// (keys and Evidence) and to the CAS through CAAPI gRPC. Enrollment vs
// Retrieval is chosen by the CAS and is opaque to the Attester.
package cai
