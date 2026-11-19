# Warden operations

This class 1 app owns its identity and enforces auth on every run. Assign the real `owner` and
`operator` in `project.yaml`; keep passwords, API keys and signing keys outside the repository.
The agentic profile supplies MCP, capabilities and secrets; new tool handlers must use the service
layer and explicit scope authorization. Registry registration waits for the catalog's agreed interface.

## Install and bootstrap

Fleet-install owns the binary and its `~/.local/bin/warden` link. Cerberus supervises
that installed path with the native supervisor (`auto`: launchd on macOS, systemd user on Linux).
The process needs no checkout. `project.yaml` → `settings.runtime` selects the platform, inventory
host, port, binary link, release directory and SQLite backup path. Optional `env_file` is a reference
for operator configuration, never a credential value.

1. Build with the checked-in CI workflow for the selected platform. Review `folio deploy render . --plan`
   after descriptor edits, then use `--write` to refresh the generated deployment files. Resolve authored
   output conflicts deliberately; `--overwrite` explicitly replaces them. Platform edits also need a
   matching CI build target. Descriptor regeneration never changes application auth/code.
2. Review `fleet-install deploy warden --repo hollis-labs/warden --commit <sha> --dry-run`
   and the backup/restart plan before an authorized install. For monorepos, select the root build workflow
   `warden-build.yml` with `--workflow` when locating CI artifacts.
3. Bootstrap the owner offline using the installed binary (`docs/identity-bootstrap.md`). Login/setup
   does not create an owner over HTTP. Issue narrowly scoped machine keys for API/MCP callers.
4. Validate the downloaded `warden.cerberus.yaml`, register it, and apply the resource only
   after reviewing its installed command, credentials, health URL and runtime target. Fleet-install owns
   the binary; do not add Cerberus build_strategy or artifact_path.

## Configuration and state

`SUBSTRATE_CONFIG` explicitly selects an override file. Otherwise the binary discovers
`$XDG_CONFIG_HOME/warden/config.yaml` (fallback `~/.config/warden/config.yaml`).
Discovery creates nothing. Database and signing key live under `$WARDEN_DATA_DIR`, else
`$XDG_DATA_HOME/warden`, else `~/.local/share/warden`. Secret backend state uses
`$XDG_STATE_HOME/warden` or `~/.local/state/warden`. Absolute operator paths are
preserved. If you change the database location, update `settings.runtime.backup_database` to match it.

`serve --managed --addr 127.0.0.1:<port>` uses the projected listener address. Auth downgrade config is
refused even on loopback. Browser login assets remain public; API and MCP calls require verified identity
and scopes. Set allowed_hosts explicitly before exposing an app beyond local development.

## Verify, back up and recover

A healthy response alone does not prove the expected binary is running. Compare the running executable
with the fleet-installed link (Linux `/proc/<pid>/exe`; macOS `lsof -p <pid>`), then exercise authenticated
read/write operations. Check unauthorized requests are refused and identity setup remains offline.

The fleet descriptor preserves the SQLite backup preflight. Retain the database, identity signing key,
operator config and secret backend state together; losing the signing key invalidates issued identities.
Review schema changes before deployment: binary rollback does not automatically restore a database.
Use the fleet-install rollback plan for the previous release; restore a database backup only with the
operator's explicit decision and the service stopped. Never copy a live SQLite file as a backup.

## Releases

Review the changelog and full CI gate before creating a semver tag. Standalone tags are `vX.Y.Z`;
monorepo tags are `./vX.Y.Z` when the location is not `.`. The generated
release workflow validates the project prefix and version, builds the selected target, and publishes
artifacts with SHA256SUMS. Signing can be added when an approved signing facility is available.
Folio generation and `deploy render` never create tags, releases, installations or live services.

## Warden configuration

The `warden:` block of the config file (see `internal/settings/settings.go` for every key):

```yaml
httphost: { addr: "127.0.0.1:18212" }
warden:
  public_url: https://warden.example      # what clients use; also the token issuer (iss) unless `issuer` is set
  allowed_hosts: [warden.example]         # Host names served beyond loopback
  policy_file: ""                         # empty: the embedded starter rules (internal/policy/default-rules.yaml)
  approvals:
    mode: gatecrasher                     # fake (development), gatecrasher, or off (elevated/critical stay pending)
    url: https://gatecrasher.example
    jwks_url: https://gatecrasher.example/api/gate/v1/jwks.json   # or jwks_file: a pinned JWKS
    token_file: ~/.config/warden/gatecrasher.token                 # 0600; the bearer Warden presents
    owner: human:owner                                             # Gatecrasher approvals.owner.sub: the only critical decider
```

Resource servers trust Warden with the auth module's existing settings: `auth.issuer` = Warden's issuer,
`auth.jwks_url` = `<public_url>/.well-known/jwks.json`, `auth.denylist_url` = `<public_url>/v1/denylist`,
audience = the app's id. Nothing else changes in them.

## State Warden owns

Keep these together, back them up together, and never commit them:

- `$WARDEN_DATA_DIR/warden.db` holds principals, grants, families, hashed parents, requests, the
  deny-list and the audit log.
- `$WARDEN_DATA_DIR/issuer/` holds the signing keys (`<kid>.key`, 0600), `keys.json` and `jwks.json`.
  Losing these invalidates every live token. Clients recover by refreshing once a new key exists, because
  parent credentials do not depend on the signing key.
- `$WARDEN_DATA_DIR/identity-signing.key` and the identity tables hold the owner's sign-in.

Keys rotate automatically every 30 days. Rotate by hand with `POST /api/v1/keys/rotate` (owner): the old
key keeps verifying for 70 minutes.

## Day-two operations (owner)

```sh
export WARDEN_URL=https://warden.example WARDEN_TOKEN_FILE=~/.config/warden/owner.key
warden request list --all --status pending        # what is waiting
warden grants --principal app:surface             # what a principal holds
warden grants revoke grt_…  --reason "rotated"    # revoke; its live tokens are denied at once
warden device approve BCDF-GHJK                   # approve a device sign-in (or --deny)
curl -H "Authorization: Bearer $(cat $WARDEN_TOKEN_FILE)" $WARDEN_URL/api/v1/audit
curl -X POST -H "Authorization: Bearer $(cat $WARDEN_TOKEN_FILE)" -d '{"sub":"agent:x","reason":"leaked"}' $WARDEN_URL/api/v1/principals/disable
```

A replayed parent credential revokes its family on its own. The audit log shows `family.revoke` with
reason `reuse detected`. The legitimate holder re-enrolls, and the owner approves it (re-enrollment is
critical).

## Pilot: the Surface classifier's llm-gateway key

1. The owner enrolls Surface (approved at once, because the owner asked):
   `warden enroll --token-file owner.key --sub app:surface --kind app --out ~/.config/surface/warden.token`
2. Surface requests its grant, which is ground tier and granted at once:
   `warden request --credential ~/.config/surface/warden.token --audience llm-gateway --scope llm-gateway.decide,llm-gateway.embed`
3. Surface mints 60-minute tokens and the parent file rotates:
   `warden token --credential ~/.config/surface/warden.token --audience llm-gateway`.
   In Go, use `client.Minter{...}.Refresher()`.
4. llm-gateway trusts Warden. This is the llm-gateway owner's change, routed through Cerberus:
   `auth.issuer`, `auth.jwks_url` and `auth.denylist_url` as above, plus scopes `llm-gateway.decide` and
   `llm-gateway.embed`.

Rollback: revoke the grant (`warden grants revoke`) and switch Surface back to its hand-issued key.

## Postgres

Warden keeps two kinds of data apart:

- **The default store is a small local SQLite file.** It holds the identity module's owner, sessions and
  API keys. The identity module creates its tables itself at start, so this store must allow DDL.
- **The named store `data` holds Warden's own tables** when it is configured: principals, grants,
  families, requests and audit. In production it is Postgres. Its runtime login has no DDL rights, and
  the schema is applied by a deploy step that uses the migration login.

With no `data` store configured, everything stays in the default store. That is the development
setup.

```yaml
database:
  sqlite: { path: warden.db }                  # default store: identity
  stores:
    data:
      driver: postgres                         # required: true and schema_mode: verify are the defaults
      postgres:
        dsn_file: ~/.config/warden/pg-runtime.dsn          # 0600; runtime login (DML only)
        migrate_dsn_file: ~/.config/warden/pg-migrate.dsn  # 0600; migration login, read only by `db migrate`
```

Deploy order:

0. **First install only.** fleet-install rolls back when the health check fails, and a new service is not
   up yet (no owner, schema not migrated). Point the symlink at the new release by hand for the first
   install, then use fleet-install for later ones.
1. Run `warden db migrate --store data` with the migration login. It must become the schema owner, so set
   the role at connection start: add `options=-c role=<owner>` to the migration DSN.
2. Start Warden. It verifies the schema and refuses to start while the schema is behind.

The runtime login needs `USAGE` on the schema, plus `SELECT`, `INSERT`, `UPDATE` and `DELETE` on the
tables and `USAGE` and `SELECT` on the sequences that the owner creates. Grant them as default privileges
for the owner role.

The connection strings are secrets: compose them file to file from the provisioned password files, and
never put them in config or on a command line. Put the schema in the DSN (`search_path=<schema>`). Use
`sslmode=verify-full` with the server's certificate name and `sslrootcert`, not a bare `require`.

Back up the default store, `warden.db` (identity), and the `issuer/` key directory together, in addition
to the Postgres database.
