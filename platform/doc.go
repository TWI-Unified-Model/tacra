// Package platform is the TACRA Platform Plug-In used by the Credential
// Acquisition Interface (CAI).
//
// CAI calls this package to generate Credential Encryption Keys (CEK),
// Credential Signing Keys (CSK), and Remote Attestation Evidence. Evidence is
// an RFC 9711 Entity Attestation Token serialized as a tagged COSE_Sign1
// (CBOR tag 18), which open-source RATS verifiers such as Veraison consume.
//
// This package ships a software-simulated plug-in. Hardware backends (Intel
// TDX, AMD SEV-SNP, and so on) can implement the same Plugin interface later.
package platform
