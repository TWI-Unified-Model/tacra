# The CAS Server Plug-in

`casserver` is the Credential Acquisition System Server of TACRA
(draft-novak-rats-tacra) as a library: what a CAS Server does with a request,
written once. A CAS Server hosts the plug-in and carries the three calls to it.

| Host | How the calls reach the plug-in |
| --- | --- |
| SPIRE Server, in `TWI-Unified-Model/spiffe-spire` | the CredentialAcquisition Server API, which the SPIRE Agent calls for a Workload that it attested |
| EST Server, in `TWI-Unified-Model/globalsign-est` (`internal/cas`) | the resources `attest-initiate`, `attest-enroll` and `attest-retrieve` of draft-novak-lamps-tacra-est |

For a request, the plug-in issues the Freshness Handle, sends the Evidence to a
RATS Verifier, verifies the Attestation Results and the binding of the key of
the Attester to the Evidence, and applies the policy for the Target.

- In Enrollment the result names the CSR to certify. A host with a CA of its
  own mints the certificate, as SPIRE Server mints the X509-SVID. A host
  without one has the configured Credential Authority issue it.
- In Retrieval the plug-in is the conduit to a Secret Vault that appraises and
  seals, or it reads a Secret Vault that only holds the credential, and seals
  the credential itself in the hpke-base container of the `container` module.

## What a host calls

| Call | What it does |
| --- | --- |
| `New` | builds the `Acquirer` from the configuration, and refuses a configuration that it cannot serve |
| `Initiate` | Initiate-Credential-Acquisition: validates the Target, the Credential Type and the Credential Hint, and answers with the mode, the Freshness Kind and the Freshness Handle |
| `Enroll` | Enroll-Credential: checks the binding, the Evidence format, the CSR, the Handle and the Attestation Results, and returns the CSR to certify with what was admitted |
| `IssueCertificate` | has the configured Credential Authority certify the key of that CSR; a host with a CA of its own does not call it |
| `Retrieve` | Retrieve-Credential: returns the container that only the CEK of the Workload opens |

A refusal is a gRPC status that names the reason, and the host carries it in
its own protocol. `EntryID` and `AgentID` of a request name the Workload and
the CAS Client as the host knows them: the second call of an exchange must
come from the pair that initiated it. SPIRE Server passes the registration
entry of the Workload and the ID of the Agent; the EST Server leaves both
empty.

## Who decides what

The Verifier owns the appraisal of the Evidence. Its reference values say which
launches it knows; its policy says what is affirming. The plug-in configures no
part of that policy: it is provisioned at the Verifier.

The plug-in configures two things. First, which Verifiers it trusts and for
what: the URL of the challenge-response API, the certificate of the CA that
signed its TLS certificate, the key that signs its Attestation Results
(provisioned, never fetched), the Evidence it appraises, and the EAR
submodules it speaks for. Attestation Results signed by any other key, or
older than `ear_max_age`, or without the binding value as their nonce, are
refused. Second, its own policy as the Relying Party, for each Target: the
mode, the Credential Types, the Freshness Kind, the CSK algorithms, the
Verifiers whose results count, the launch measurements admitted, and the
platform rule.

A Secret Vault of kind `json` keeps a Relying Party policy of its own, and the
plug-in is the conduit. In the Passport RATS model the plug-in obtains the
Attestation Results from the Verifier and forwards them to the Secret Vault. In
the Background Check RATS model the plug-in forwards the Evidence, and the
Secret Vault asks the Verifier itself. A Secret Vault of kind `hashicorp` only
holds the credential: the plug-in appraises under the policy for the Target,
reads the credential and seals it to the CEK of the Workload.

## Configuration

The configuration is one block, `credential_acquisition`. SPIRE Server reads
it in HCL, in the `experimental` section of its configuration, and the EST
Server reads the same settings in JSON. The example is in HCL: a Target that
enrolls a certificate and releases a JWT from HashiCorp Vault, for a platform
whose Evidence is a PSA attestation token.

```hcl
credential_acquisition {
    acceptable_evidence = ["application/psa-attestation-token"]

    verifier "veraison" {
        url = "https://verifier.example:8443"
        ca_path = "/run/cas/tls/verifier-ca.crt"
        ear_key_path = "/run/cas/ear/veraison.jwk"
        evidence_media_types = ["application/psa-attestation-token"]
        submods = ["PSA_IOT"]
    }

    target "https://server.example:8443" {
        mode = "enroll"
        credential_types = ["x509"]
        verifiers = ["veraison"]
        # the measurements admitted, each as hex
        measurements = ["<measurement of an admitted launch>"]
        retrieve_credential_types = ["jwt"]
        secret_path = "tacra/server-token"
    }

    secret_vault {
        kind = "hashicorp"
        url = "https://vault.example:8200"
        ca_path = "/run/cas/tls/vault-ca.crt"
        token_path = "/run/cas/vault-token"
    }
}
```

`deploy/demo.sh up` writes both spellings for the demonstration in simulation:
`deploy/config/demo/spire-server/server.conf` and
`deploy/config/demo/est-server/estserver.json`.

Every duration is a string with its unit: `2m`, `90s`.

| `credential_acquisition` | Description | Default |
| --- | --- | --- |
| `acceptable_evidence` | The Evidence formats the plug-in forwards, by media type | required |
| `ear_max_age` | How old Attestation Results may be | `2m` |
| `ear_skew` | How far in the future Attestation Results may be dated | `5s` |
| `client_cert_path`, `client_key_path` | The certificate and key the plug-in presents to the Verifiers and the Secret Vault when they require mutual TLS | none |
| `platform_rule_path` | The JSON file with the platform rule, see below | none: only the debug and migration bits of the guest policy of SEV-SNP are refused |
| `sevsnp_products_path` | The JSON file with the product data of AMD for SEV-SNP, see below | the copy this module ships |
| `verifier "<name>"` | A Verifier the plug-in trusts, see below | one or more, unless every Target is in retrieve mode under the Background Check RATS model |
| `target "<name>"` | The policy for a Target, see below | at least one |
| `secret_vault` | The Secret Vault, see below | required when a Target is in retrieve mode or names `retrieve_credential_types` |
| `credential_authority` | The Credential Authority of a host without a CA of its own, see below | none |

| `verifier` | Description |
| --- | --- |
| `kind` | The kind of Verifier, how the plug-in sends it Evidence and reads its Attestation Results: `veraison`, the default and the one kind for now |
| `url` | The base URL of the API of the Verifier; for `veraison`, its challenge-response API |
| `ca_path` | The certificate of the CA that signed the TLS certificate of the Verifier |
| `provider` | The TSM report provider of the Evidence this Verifier appraises: `sev_guest` or `tdx_guest` |
| `evidence_media_types` | The media types of the Evidence this Verifier appraises when the Evidence is not a TSM report, `application/psa-attestation-token` for example; `provider` or `evidence_media_types` is required |
| `ear_key_path` | For `veraison`: the public key that signs the Attestation Results, an EC P-256 JWK or a PEM public key, provisioned |
| `submods` | For `veraison`: the EAR submodules it speaks for, each of a platform family: `SEVSNP`, `TDX` or `PSA_IOT` |

The policy for a Target names its Verifiers. Among them, the Evidence picks
one: the Verifier that lists the media type of the Evidence or, for Evidence in
a TSM report, the Verifier for the provider of the report.

| `target` | Description | Default |
| --- | --- | --- |
| `mode` | `enroll` or `retrieve` | required |
| `credential_types` | The Credential Types served for this Target; Enrollment serves `x509` and `wic` | `x509` in enroll mode |
| `freshness_kind` | The Freshness Kind; the plug-in issues `present-nonce` Handles | `present-nonce` |
| `expires_in` | The lifetime of a Freshness Handle; TACRA recommends at least `1m` | `5m` |
| `verifiers` | The Verifiers whose Attestation Results count for this Target | required, except in retrieve mode under the Background Check RATS model |
| `acceptable_csk` | The CSK algorithms accepted in Enrollment; `ecdsa-p256-sha256` is supported | all supported |
| `measurements` | The launch measurements admitted, as hex, or `allow_any_measurement = true` to leave that decision to the Verifier | one of the two is required in enroll mode, and in retrieve mode with a Secret Vault that the plug-in reads itself |
| `rats_model` | For retrieve mode with a Secret Vault of kind `json`: `passport` or `background-check` | `background-check` |
| `retrieve_credential_types` | For enroll mode: the Credential Types that the same Target releases by Retrieval, under the same Verifiers and launch measurements. A Workload that names one of them at initiation is answered in retrieve mode. It needs a Secret Vault that the plug-in reads itself | none |
| `secret_path` | With a Secret Vault that the plug-in reads itself: the path of the credential that Retrieval releases for the Target | required there |
| `acceptable_cek` | With such a Secret Vault: the suites of the hpke-base container that the plug-in seals under | both suites of the container |
| `certificate_name` | With a `credential_authority`: the name that it certifies for a Workload enrolled for the Target, as the common name and the DNS name of the certificate. The CSR does not choose the name | required there |
| `certificate_validity` | With a `credential_authority`: how long such a certificate is valid | `1h` |

| `secret_vault` | Description |
| --- | --- |
| `kind` | The kind of Secret Vault: `json`, the default, the TACRA calls forwarded as JSON over HTTPS to a Secret Vault that appraises and seals; or `hashicorp`, a HashiCorp Vault that the plug-in reads itself |
| `url` | The base URL of the API of the Secret Vault |
| `ca_path` | The certificate of the CA that signed the TLS certificate of the Secret Vault |
| `client_cert_path`, `client_key_path` | A certificate and key presented to the Secret Vault in place of the ones above |
| `mount` | For `hashicorp`: the mount of the key-value secrets engine, version 2; the default is `secret` |
| `token_path` | For `hashicorp`: the file with the token that the plug-in presents, read at each call; required |

The record of a credential in HashiCorp Vault has the fields `type`, a
Credential Type of TACRA; `value`, the credential as text; and, optionally,
`format`.

| `credential_authority` | Description |
| --- | --- |
| `kind` | The kind of Credential Authority: `step-ca`, the default and the one kind for now |
| `url` | The base URL of the Credential Authority |
| `ca_path` | The root certificate under which the Credential Authority serves TLS |
| `provisioner` | For `step-ca`: the name of the JWK provisioner that the plug-in requests certificates as; required |
| `provisioner_key_path` | For `step-ca`: the file with the private key of that provisioner, an EC P-256 JWK; required |

## The platform rule

Affirming Attestation Results say that the Evidence matched the reference
values of the Verifier. They do not say that the platform is one this CAS
Server accepts: that is the platform rule, applied by the plug-in to the fields
the Verifier annotated.

```json
{
  "sevsnp": {
    "require_machine_identity": false,
    "allowed_products": ["Milan", "Genoa", "Turin"],
    "tcb_floors": {
      "Milan": {"bl": 4, "snp": 29, "ucode": 222},
      "Genoa": {"snp": 28, "ucode": 86},
      "Turin": {"snp": 5, "ucode": 81}
    },
    "check_committed_tcb": true,
    "smt": "allow-with-microcode-floor",
    "required_mitigation_bits": {
      "Milan": {"1": "AMD-SB-3020 (CVE-2025-0033)", "4": "AMD-SB-3034 (CVE-2025-54510)"},
      "Genoa": {"1": "AMD-SB-3020 (CVE-2025-0033)"},
      "Turin": {"0": "AMD-SB-3020 (CVE-2025-0033)"}
    },
    "required_platform_info_bits": {
      "Milan": {"5": "AMD-SB-3015 (BadRAM, CVE-2024-21944): ALIAS_CHECK_COMPLETE"}
    },
    "mitigation_waivers": {"Milan": {"4": "admitted without bit 4, AMD-SB-3034"}}
  },
  "tdx": {"td_attributes_refused": "0x2000fff0"},
  "psa": {"implementation_ids": ["<Implementation ID of an admitted platform, as hex>"]}
}
```

For SEV-SNP the rule names the chips admitted (by CHIP_ID, or any chip that is
named), the product lines admitted (from the CPUID family and model of the
report), the floor of each TCB component per product line, applied to
REPORTED_TCB and, when asked, to COMMITTED_TCB, whether SMT is allowed, the
mitigation bits that must be set in both mitigation vectors with the reason
each refusal gives, the PLATFORM_INFO bits required, and the waivers. The guest
policy is the POLICY field of the report, the launch settings of the guest:
its debug and migration bits are refused with or without a rule. For TDX the
rule names the TD ATTRIBUTES bits refused. For PSA the rule names the
Implementation IDs admitted.

The rule has one entry per platform family, keyed by the name of the module of
the plug-in for the family: `sevsnp`, `tdx`, `psa`. A module is the counterpart
on the Server side of the platform plug-in of the Attester: it names the EAR
submodule the Verifier annotates for the family, parses and validates the
entry, and applies it to the Attestation Results. With a rule, a family without
an entry is refused. A new family, CCA for example, is a new module; the rest
of the plug-in does not change.

The module for SEV-SNP reads the report with the product data of AMD: which
product line a CPUID family and extended model names, and the byte of each
component in TCB_VERSION. That data grows with every product line AMD ships, so
it is a JSON file under version control, not code: the copy this module ships,
[sevsnp_products.json](sevsnp_products.json), or the file
`sevsnp_products_path` names, in the same format.

```json
{
  "products": [
    {
      "name": "Turin",
      "cpuid": [{"family": "0x1A", "extended_model": "0x0"}, {"family": "0x1A", "extended_model": "0x1"}],
      "tcb_layout": {"fmc": 0, "bl": 1, "tee": 2, "snp": 3, "ucode": 7},
      "source": "AMD 57230 Rev. 1.05, Table 4; AMD 56860 Rev. 1.59, Table 4"
    }
  ]
}
```

A product line without a layout is not decoded, so the rule refuses it; an
operator who has the layout adds it to the file. A rule that names a product
line the data does not have is refused when the host starts.

The module for PSA reads the claims of the PSA attestation token as the
Verifier annotates them. The token must report one software component: its
measurement is the launch measurement that the policy for a Target admits.

## Points of extension

The plug-in has four points of extension, each a list of implementations
behind one interface, named in the configuration or in the rule file. The data
that grows on its own schedule, the product lines of AMD, is in a file under
version control, not in the code.

| Point | Named by | Implementations |
| --- | --- | --- |
| Platform family: how the claims of a family are checked against the platform rule | the key of the entry in the rule file | `sevsnp`, `tdx`, `psa` |
| Verifier kind: how Evidence is sent to a Verifier and its Attestation Results are verified and read | `kind` of a `verifier` | `veraison` |
| Secret Vault kind: how the initiate and the retrieve parts of the flow are forwarded, or how the credential is read | `kind` of `secret_vault` | `json`, `hashicorp` |
| Credential Authority kind: how a certificate is requested | `kind` of `credential_authority` | `step-ca` |

The kind is chosen by the operator and confirmed by the plug-in, not guessed
from what arrives: a Verifier of kind `veraison` reads the profile an EAR names
in `eat_profile`, and refuses Attestation Results that name another, with both
names in the refusal.

## Refusals

The plug-in answers a refusal with the gRPC code that names its reason.

| Code | When |
| --- | --- |
| `InvalidArgument` | A malformed request: a call of the enroll mode for a Target in retrieve mode or the reverse, a Credential Type not defined by TACRA, a Freshness Kind or Handle that does not match the initiation, a binding or an Evidence format not accepted, a malformed CSR or one of another algorithm, a CEKpub of a suite not accepted |
| `NotFound` | A Target this CAS Server does not serve, or a Secret Vault that holds no credential for the Target |
| `Unimplemented` | A Credential Type this CAS Server does not serve for the Target, named with the ones it serves |
| `PermissionDenied` | Remote Attestation failed: Attestation Results not affirming, not signed by a Verifier of the policy, or reporting another nonce; a launch not admitted; the platform rule refused |
| `Unavailable` | No Verifier, Secret Vault or Credential Authority could be reached, or none is configured for the call |
| `ResourceExhausted` | The Secret Vault asked the CAS Server to slow down |
| `Internal` | A failure inside the plug-in, or a Secret Vault answer that breaks the contract |

A refusal of a Secret Vault of kind `json` is relayed with the gRPC code of its
HTTP status and the reason it gives.

## Logging

A refusal is a gRPC status that names the reason, and is not logged again
where it is returned. The plug-in logs at warning what the status does not
carry: Attestation Results refused, admissions under a waiver of the platform
rule, and a Secret Vault or a Credential Authority that failed. It logs at info
the configuration when the host starts, each certificate that the Credential
Authority issued and each credential released from a Secret Vault that it
reads, with the Verifier, the platform family and the launch measurement.
