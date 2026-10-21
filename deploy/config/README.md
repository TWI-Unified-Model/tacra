# Runtime Configuration

The TACRA deployment dispatcher reads runtime configuration from `--config-dir`
or `DEPLOY_CONFIG_DIR`. Its default is `tacra/deploy/config/local`, which is
ignored by Git through `.gitignore`.

Keep real configuration, keys, certificates, and passwords outside the source
tree or in an ignored local directory. The expected layout is:

```text
<config-dir>/
  globalsign-est/
    estserver.json
    certs/
      ca-certificates.pem
      ca-key.pem
      server-certificates.pem
      server-key.pem
      client-ca.pem
      mock-tee-provider-public-key.pem
  mock-tee-provider/
    key.pem                    # Attester tests; not mounted into EST
  hashicorp-vault/
    config/
      vault.hcl
  spiffe-spire/
    server.conf
    agent.conf                 # Optional; starts a local agent when present.
  step-ca/
    config/
      ca.json
    secrets/
      password
  rup/                         # Demo RATS-unaware Relying Party (tacra/server)
    rup.json
    certs/
      rup-ca.pem               # Clients trust the RUP via RUP_CA_FILE
      rup-ca-key.pem
      server-cert.pem
      server-key.pem
```

Copy `../../../globalsign-est/estserver.json.example` to
`globalsign-est/estserver.json` and replace every certificate path and secret
before deploying EST.

For disposable local EST, Vault, SPIRE server, and step-ca setups, deploy
automatically generates missing configuration under `config/local/`. You can
also run a generator explicitly:

```sh
./tacra/deploy/init-local-est-config.sh
./tacra/deploy/init-local-hashicorp-vault-config.sh
./tacra/deploy/init-local-spiffe-spire-config.sh
./tacra/deploy/init-local-step-ca-config.sh
./tacra/deploy/init-local-rup-config.sh    # not run by components.sh
```

The RUP generator creates a 30-day development CA and server certificate for
the demo RATS-unaware Relying Party and a `rup.json` under
`config/local/rup/`. It never generates client trust anchors: pass the
issuing CA and token-issuer public keys through `RUP_CLIENT_CA_FILE`,
`RUP_JWT_ISSUER`, `RUP_JWT_PUBLIC_KEY_FILE`, `RUP_WIT_ISSUER`, and
`RUP_WIT_PUBLIC_KEY_FILE` (or the `*_JWKS_FILE` variants). Without them the RUP
starts but rejects every request.

The EST generator creates a 30-day local CA, EST TLS certificate, client-CA
bundle, mock TEE provider key pair, and health-check password under
`config/local/globalsign-est/` (provider private key in
`config/local/mock-tee-provider/`). The Vault generator creates a local
file-storage and HTTP listener configuration under
`config/local/hashicorp-vault/`. The SPIRE generator creates an
evaluation-only SPIRE server configuration with SQLite, a disk key manager, and
join-token node attestation under `config/local/spiffe-spire/`. The step-ca
generator creates local CA certificates, keys, Badger database state, and a
password under `config/local/step-ca/`. Generators do not overwrite complete
configuration. The EST generator will add a missing mock TEE provider key to an
otherwise complete local EST tree; any other incomplete tree must be removed
before regenerating.

EST and Vault bind-mount those trees into non-root container users (`est`,
`vault`). Generated directories are `0755` and mounted files are readable so
Linux bind mounts work; `0700` host-only trees are not.

The GlobalSign `estserver` command uses `internal/mockca` and upstream labels
it as non-production. Its container wrapper is therefore for local testing and
demonstrations only.

Local values must never be committed. EST requires a locally generated CA key,
CA certificate, server key, server certificate, and health-check password.
Vault initialization creates an unseal-key set and root token after its server
starts; store them only under `local/hashicorp-vault/`. Step-ca creates or uses
its password under `local/step-ca/secrets/`. The generated SPIRE configuration
starts only a server; adding an agent requires a join token and deliberate
host-specific node/workload-attestation choices.

For Vault, use a non-development server configuration with persistent storage.
For SPIRE Agent, local Docker Desktop use is for testing only; a real agent
needs host-specific sockets and attestation configuration. The step-ca
directory is mounted read-write because step-ca manages state beneath
`/home/step`.