# Demonstration in Simulation

Both steps of the TACRA demonstration on one computer, in Docker, without
confidential hardware.

| Step | What the Client does |
|------|----------------------|
| 1 | Acquires an X.509 certificate and a JWT through **SPIRE**, then authenticates with both to the Server. |
| 2 | Acquires an X.509 certificate and a JWT through **EST**, then authenticates with both to the Server. |

The Client and the Server are the programs of this repository, unmodified.
The same Client runs both steps. The only difference between the steps is
the CAS Client that the CAI sidecar of the Client reaches.

Each step shows the protocol at work and checks it from the outside: every
call of CAAPI as the sidecar made it, the signature of the Evidence, and the
TACRA binding value computed again from the request and compared with the
nonce of the Evidence.

## Run It

From the `tacra/` directory of a workspace that has the repositories side by
side, as in [readme_docker_build_deploy.md](readme_docker_build_deploy.md):

```bash
./deploy/demo.sh build     # the images; the first build is the long part
./deploy/demo.sh up        # configuration and start, half a minute
./deploy/demo.sh step1     # through SPIRE
./deploy/demo.sh step2     # through EST
./deploy/demo.sh refusals  # what is refused, and why
./deploy/demo.sh down      # remove everything
```

`./deploy/demo.sh all` runs `build`, `up`, both steps and the refusals, one
after the other.

From nothing but this repository:

```bash
./deploy/demo.sh workspace  # clone the other five repositories beside tacra
./deploy/demo.sh all
```

`up` starts from nothing every time: a demonstration that is already up is
removed first. `step1`, `step2` and `refusals` can be repeated in any order.

Needed on the computer: Docker with buildx, and bash. `build` also needs
make, git and jq, which the Veraison deployment asks for, about 40 GB of
disk, and 20 to 25 minutes the first time on eight cores.

The demonstration runs everything itself, Veraison included, on its own
network (`twi-demo`), in its own containers (`twi-demo-*`) and volumes, with
its configuration in `deploy/config/demo` (ignored by Git). It publishes no
port on the host. A local deployment made by `components.sh deploy`, its
Veraison included, is not touched, and `down` leaves nothing.

## What Runs

```
 Step 1                                             Step 2

 Client ── CAI ──► CAI sidecar                      Client ── CAI ──► CAI sidecar
                   (simulated platform)                               (simulated platform)
                        │ CAAPI                                            │ CAAPI
                        ▼                                                  ▼
                   SPIRE Agent                                        EST Client
                        │                                                  │ EST
                        ▼                                                  ▼
                   SPIRE Server ─────────► Veraison ◄──────────────── EST Server
                   (CAS Server Plug-in)                               (CAS Server Plug-in)
                        │                                                  │
              its own CA, HashiCorp Vault                      step-ca, HashiCorp Vault

 Client ── certificate + JWT ──► Server             Client ── certificate + JWT ──► Server
```

| Role | Component | Container |
|------|-----------|-----------|
| Client, the Attester | `client/` | `twi-demo-client`, one run for each step |
| CAI sidecar | `cai/cmd/sidecar` with the simulated platform | `twi-demo-cai-spire`, `twi-demo-cai-est` |
| CAS Client | SPIRE Agent; EST Client (`globalsign-est/cmd/estcasclient`) | `twi-demo-spire-agent`, `twi-demo-est-client` |
| CAS Server | SPIRE Server; EST Server; each with the CAS Server Plug-in (`casserver/`) | `twi-demo-spire-server`, `twi-demo-est-server` |
| Verifier | Veraison: its trust, provisioning and verification services, and Keycloak | `twi-demo-veraison-*` |
| Credential Authority | The CA of the SPIRE Server (step 1); step-ca (step 2) | `twi-demo-step-ca` |
| Secret Vault | HashiCorp Vault | `twi-demo-vault` |
| Server, a RATS-unaware Relying Party | `server/` | `twi-demo-server`, reached as `tacra-server` |

In both steps the Client makes the same two calls to its CAI sidecar for the
Target `https://tacra-server:8443`:

1. An X.509 certificate. The CAS Server has Veraison appraise the Evidence.
   In step 1 the SPIRE Server then signs an X509-SVID with its own CA. In
   step 2 the EST Server has step-ca issue the certificate.
2. A JWT. The CAS Server has Veraison appraise new Evidence, reads the JWT
   from HashiCorp Vault and returns it sealed in an hpke-base container that
   only the CEK of the Client opens.

The Server accepts a request that carries the certificate and the JWT
together.

## What a Step Prints

Three accounts of the same run: the output of the Client; the calls of CAAPI
as the CAI sidecar recorded them, checked; and what the CAS Server and the
Server recorded in their own logs. Step 2:

```
== Step 2: the Client acquires an X.509 certificate and a JWT through EST

   Client         Acquiring X.509 client certificate for https://tacra-server:8443 via CAI sidecar...
   Client         Acquired X.509 certificate.
   Client         Acquiring JWT for https://tacra-server:8443 via CAI sidecar...
   Client         Acquired JWT.
   Client         Received valid URI: https://example.com/received
   CAAPI          the calls of the CAI sidecar to its CAS Client, as the sidecar recorded them
                  Initiate   x509 for https://tacra-server:8443
                             <- enroll, present-nonce, Freshness Handle of 32 octets, CSK ECDSA-P256  (10 ms)
                  Enroll     Evidence: PSA attestation token, 387 octets; signature of the Attestation Key: valid
                             nonce of the token = SHA-512(Freshness Element, Target, CSR): equal  (7a8f61e07eb544f6...)
                             measurement 262ed2d2efde486c5f832d682457080780af7881ef8d18f656c164fdc2342f20: the Reference Value
                             <- X.509 certificate for tacra-demo-client.twi.local, issued by "TWI Demo Step CA Intermediate CA", valid until 2026-11-25T21:56:00Z  (43 ms)
                  Initiate   jwt for https://tacra-server:8443
                             <- retrieve, present-nonce, Freshness Handle of 32 octets, CEK MLKEM768-P256  (4 ms)
                  Retrieve   Evidence: PSA attestation token, 387 octets; signature of the Attestation Key: valid
                             nonce of the token = SHA-512(Freshness Element, Target, CEKpub): equal  (a5ff94dd7fea6b91...)
                             <- hpke-base container, MLKEM768-P256, 868 octets of ciphertext: only the CEK of the Workload opens it  (30 ms)
   EST Server     Evidence affirmed by veraison; certificate issued by the Credential Authority for tacra-demo-client.twi.local
                  measurement 262ed2d2efde486c5f832d682457080780af7881ef8d18f656c164fdc2342f20
   EST Server     Evidence affirmed by veraison; jwt released from the Secret Vault
   Server         accepted the request: formats [x509 jwt], subject tacra-demo-client.twi.local

Step 2 passed.
```

In step 1 the certificate is an X509-SVID for `spiffe://twi.local/workload`,
and the Server reports `formats [wic jwt]`.

The lines under `CAAPI` are not a log of the servers. The sidecar writes
every call of CAAPI that it makes to a file, and the command `caapi-trace`
reads the files and checks them with nothing but the public Attestation Key
of the platform:

- the signature of the PSA attestation token;
- the nonce of the token against the binding value that it computes itself
  from the request: SHA-512 over the Freshness Element, the Target, and the
  CSR or CEKpub. `equal` says that the Evidence is bound to this Freshness
  Handle, this Target and this key;
- the measurement against the Reference Value.

A step fails when one of these checks does not hold. The time at the end of
a call is how long the CAS Client took to answer it. Nothing secret crosses
CAAPI: the keys of the Client never leave the sidecar, a certificate is
public, and the JWT travels sealed. `--raw` prints the lines of the logs of
the servers as they are.

## What Is Refused

`refusals` makes five requests that must fail, and fails itself if one of
them succeeds.

| Request | Through | What the calls of CAAPI show | Who refuses, and why |
|---------|---------|------------------------------|----------------------|
| The CAI sidecar has one more octet at the end of its program. | SPIRE, then EST | Signature valid, binding value equal, measurement `NOT the Reference Value`. | The CAS Server: Veraison does not affirm the Evidence (`warning`). |
| The simulated platform signs with an Attestation Key that Veraison holds no trust anchor for. | SPIRE, then EST | Signature `DOES NOT VERIFY` under the endorsed key. | The CAS Server: Veraison does not affirm the Evidence (`contraindicated`). |
| A request to the Server carries the JWT and no certificate. | | | The Server: HTTP 401. |

The SPIRE Agent attests the altered sidecar as the same Workload: it is
still a process of the same user. Remote attestation is what tells the two
programs apart.

## What Is Simulated

Only the platform of the Client. Everything after the Evidence is what runs
on confidential hardware.

- The simulated platform (`platform/sim`) holds a software Attestation Key.
  Its Evidence is a PSA attestation token signed with that key. The nonce of
  the token is the TACRA binding value, and the measurement is the SHA-256
  of the CAI sidecar program.
- Veraison appraises that token as it appraises any other PSA token: the
  Veraison of the workspace, unmodified.
- `up` gives Veraison the Endorsements of the simulated platform: the
  Attestation Key as the trust anchor and the measurement as the Reference
  Value. The `cocli` of Veraison builds the CoRIM and submits it.
- The policy of each CAS Server for the Target admits that one measurement.

The JWT is signed at `up` by an issuer made for the run. The Server trusts
the key of that issuer, and HashiCorp Vault keeps the JWT as the secret of
the Target.

## Prebuilt Images

Whoever has built the images can push them, and anyone else can then run
the demonstration with no workspace and no build:

```bash
./deploy/demo.sh push --images registry.example/twi   # after build, once for each platform
./deploy/demo.sh all  --images registry.example/twi   # anywhere: pulls, starts, runs
```

The thirteen images go under the prefix by name, tagged for the platform
(`demo-linux-arm64`, `demo-linux-amd64`; `--tag` changes `demo`). With
`--images`, `up` pulls them and needs nothing but Docker, bash and this
repository.

## Limits

- The Attestation Key of the simulated platform is a file. A run in
  simulation shows that the protocol and the components work together. It
  does not show that a platform is trustworthy.
- The Veraison of the demonstration is the images of the Veraison
  deployment, with the keys and the passwords of that deployment.
- HashiCorp Vault listens without TLS inside the network of the
  demonstration, as the local configuration of this repository does.
- The registration entry of SPIRE selects the CAI sidecar by its user
  (`unix:uid:0`).
- Every key, certificate and token is created by `up` for one run and
  removed by `down`.

## Looking Inside

```bash
./deploy/demo.sh status              # the state of every container
./deploy/demo.sh logs spire-server   # the log of one component
ls deploy/config/demo                # the generated configuration
ls deploy/config/demo/trace          # the recorded calls of CAAPI, one file for each
```

The configuration of the CAS Server Plug-in is in
`deploy/config/demo/spire-server/server.conf` and
`deploy/config/demo/est-server/estserver.json`: the same Verifier, the same
Target and the same Secret Vault in both.

A sidecar records its calls of CAAPI when `CAI_TRACE_DIR` names a directory,
on any platform, and `caapi-trace DIRECTORY` reports them.
