# Runtime Configuration

The Twium deployment dispatcher reads runtime configuration from `--config-dir`
or `DEPLOY_CONFIG_DIR`. Its default is this directory. For local development,
use `twium/deploy/config/local`; it is ignored by Git through `.gitignore`.

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

For the disposable local EST setup, generate the entire EST directory instead:

```sh
./twium/deploy/init-local-est-config.sh
```

The generator creates a 30-day local CA, EST TLS certificate, client-CA bundle,
and health-check password under `config/local/globalsign-est/`. It refuses to
overwrite an existing configuration.

The GlobalSign `estserver` command uses `internal/mockca` and upstream labels
it as non-production. Its container wrapper is therefore for local testing and
demonstrations only.

Local values must never be committed. EST requires a locally generated CA key,
CA certificate, server key, server certificate, and health-check password.
Vault initialization creates an unseal-key set and root token after its server
starts; store them only under `local/hashicorp-vault/`. Step-ca creates or uses
its password under `local/step-ca/secrets/`. SPIRE configuration may contain
trust-domain and node-attestation material and must also remain local.

For Vault, use a non-development server configuration with persistent storage.
For SPIRE Agent, local Docker Desktop use is for testing only; a real agent
needs host-specific sockets and attestation configuration. The step-ca
directory is mounted read-write because step-ca manages state beneath
`/home/step`.