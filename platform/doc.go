// Package platform is the TACRA Platform Plug-In: the side of the Attester in
// draft-novak-rats-tacra, which the Credential Acquisition Interface (CAI) or
// an attested Workload calls to generate Credential Signing Keys (CSK) and
// Credential Encryption Keys (CEK), and Remote Attestation Evidence bound to
// them.
//
// The hardware back-ends are AMD SEV-SNP (sevsnp.go) and Intel TDX (tdx.go),
// through the Linux configfs-tsm interface: the Evidence is the report of the
// hardware, whose report data is the TACRA binding value (binding.go), with
// the certificates of the host, as the media type
// application/vnd.veraison.tsm-report+cbor. They ran on Google Cloud and AWS
// SEV-SNP guests and on Google Cloud TDX guests against a Veraison Verifier.
//
// The simulated plug-in, which runs without hardware, is the module sim in
// this directory, so that its dependencies stay out of the Workloads that
// import the hardware back-ends.
package platform
