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

## Run It

Prerequisites: Docker, and the workspace with the repositories side by side,
as in [readme_docker_build_deploy.md](readme_docker_build_deploy.md). Run the
commands from the `tacra/` directory.

```bash
./deploy/demo.sh build     # the images; the first build is the long part
./deploy/demo.sh up        # configuration and start, about a minute
./deploy/demo.sh step1     # through SPIRE
./deploy/demo.sh step2     # through EST
./deploy/demo.sh refusals  # what is refused, and why
./deploy/demo.sh down      # remove everything
```

`up` starts from nothing every time: a demonstration that is already up is
removed first. `step1`, `step2` and `refusals` can be repeated in any order.

The demonstration uses its own network (`twi-demo`), containers
(`twi-demo-*`), volumes and configuration directory
(`deploy/config/demo`, ignored by Git), and publishes no port on the host.
It does not touch a local deployment made by `components.sh deploy`. Veraison
is the one shared component: `up` starts it if it is stopped, and `down`
stops it only in that case.

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
| Verifier | Veraison | `verification-service` |
| Credential Authority | The CA of the SPIRE Server (step 1); step-ca (step 2) | `twi-demo-step-ca` |
| Secret Vault | HashiCorp Vault | `twi-demo-vault` |
| Server, a RATS-unaware Relying Party | `server/` | `twi-demo-server`, reached as `tacra-server` |

In both steps the Client makes the same two calls to its CAI sidecar for the
Target `https://tacra-server:8443`:

1. An X.509 certificate. The CAS Server has Veraison appraise the Evidence.
   In step 1 the SPIRE Server then signs an X509-SVID with its own CA. In
   step 2 the EST Server has step-ca issue the certificate.
2. A JWT. The CAS Server has Veraison appraise new Evidence, reads the JWT
   from HashiCorp Vault and returns it in a container that only the Client
   can open.

The Server accepts a request that carries the certificate and the JWT
together, and rejects a request that carries only one of them.

## What a Step Prints

The output of the Client, then what the CAS Server and the Server wrote to
their own logs during the step. Step 2:

```
== Step 2: the Client acquires an X.509 certificate and a JWT through EST
-- the Client (twi/tacra-client:local-linux-arm64 https://tacra-server:8443)
Acquiring X.509 client certificate for https://tacra-server:8443 via CAI sidecar...
Acquired X.509 certificate.
Acquiring JWT for https://tacra-server:8443 via CAI sidecar...
Acquired JWT.
Received valid URI: https://example.com/received
-- the record of the EST Server
... msg="Certificate issued by the Credential Authority" family=psa measurement=8329... name=tacra-demo-client.twi.local verifier=veraison
... msg="Credential released from the Secret Vault" family=psa group=5e73... measurement=8329... target="https://tacra-server:8443" type=jwt verifier=veraison
-- the record of the Server
Received authenticated request. Formats: [x509 jwt], subject: "tacra-demo-client.twi.local", Message: "Hello, world!", X-Greeting: "Hello, world!"

Step 2 passed.
```

In step 1 the record of the SPIRE Server names the X509-SVID, and the Server
reports `Formats: [wic jwt]` and the subject `spiffe://twi.local/workload`.

## What Is Refused

`refusals` makes five requests that must fail, and fails itself if one of
them succeeds.

| Request | Through | Who refuses, and why |
|---------|---------|----------------------|
| The CAI sidecar has one more octet at the end of its program, so its measurement is another. | SPIRE, then EST | The CAS Server: Veraison does not affirm the Evidence (`warning`, no Reference Value matches). |
| The simulated platform signs with an Attestation Key that Veraison holds no trust anchor for. | SPIRE, then EST | The CAS Server: Veraison does not affirm the Evidence (`contraindicated`). |
| A request to the Server carries the JWT and no certificate. | | The Server: HTTP 401. |

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

## Limits

- The Attestation Key of the simulated platform is a file. A run in
  simulation shows that the protocol and the components work together. It
  does not show that a platform is trustworthy.
- HashiCorp Vault listens without TLS inside the network of the
  demonstration, as the local configuration of this repository does.
- The registration entry of SPIRE selects the CAI sidecar by its user
  (`unix:uid:0`).
- Every key, certificate and token is created by `up` for one run and
  removed by `down`. The Endorsements of the simulated platform stay in the
  stores of Veraison.

## Looking Inside

```bash
./deploy/demo.sh status              # the state of every container
./deploy/demo.sh logs spire-server   # the log of one component
ls deploy/config/demo                # the generated configuration
```

The configuration of the CAS Server Plug-in is in
`deploy/config/demo/spire-server/server.conf` and
`deploy/config/demo/est-server/estserver.json`: the same Verifier, the same
Target and the same Secret Vault in both.
