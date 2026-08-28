# Runtime Configuration

The Twium deployment dispatcher reads runtime configuration from `--config-dir`
or `DEPLOY_CONFIG_DIR`. Its default is `twium/deploy/config/local`, which is
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
```

Copy `../../../globalsign-est/estserver.json.example` to
`globalsign-est/estserver.json` and replace every certificate path and secret
before deploying EST.

For disposable local EST, Vault, SPIRE server, and step-ca setups, deploy
automatically generates missing configuration under `config/local/`. You can
also run a generator explicitly:

```sh
./twium/deploy/init-local-est-config.sh
./twium/deploy/init-local-hashicorp-vault-config.sh
./twium/deploy/init-local-spiffe-spire-config.sh
./twium/deploy/init-local-step-ca-config.sh
```

The EST generator creates a 30-day local CA, EST TLS certificate, client-CA
bundle, and health-check password under `config/local/globalsign-est/`. The
Vault generator creates a local file-storage and HTTP listener configuration
under `config/local/hashicorp-vault/`. The SPIRE generator creates an
evaluation-only SPIRE server configuration with SQLite, a disk key manager, and
join-token node attestation under `config/local/spiffe-spire/`. The step-ca
generator creates local CA certificates, keys, Badger database state, and a
password under `config/local/step-ca/`. Each generator refuses to overwrite
existing or incomplete configuration.

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