# Warden

Warden is the credentials service for non-human principals: agents, sessions, machines and apps. It is
the one issuer of their tokens. It does four things:

- **Issues tokens.** EdDSA JWTs, each for one audience, with short lives: 15 minutes for agents and
  sessions, 60 minutes for apps and machines. Its JWKS rotates keys with an overlap, and it publishes
  RFC 8414 discovery metadata and a deny-list.
- **Exchanges and refreshes them.** Token exchange follows RFC 8693 and can only narrow scopes. Refresh
  uses opaque parent credentials that rotate on every use: replaying an old one revokes its whole family.
- **Grants access on request.** A principal asks for an audience and scopes. Policy sorts the request into
  a tier. Ground tier is granted at once. Elevated and critical requests go to
  [Gatecrasher](https://github.com/hollis-labs/gatecrasher), and Warden acts only on a decision
  Gatecrasher signed. Every grant is a durable, audited record.
- **Will store secrets (milestone 2).** A vault with envelope encryption. Callers will hold `warden://`
  references and short-lived tokens instead of real secrets. Milestone 1 ships the storage interface and
  the encryption, not the service.

Status: experimental, milestone 1 (the core). Not deployed anywhere yet.

## What Warden is not

- **Not an approval UI.** Warden never asks a person anything. Approvals are delivered and decided in
  Gatecrasher, which renders them wherever the owner is.
- **Not the place people sign in.** People sign in to each app as they do today. Warden's own owner is
  created offline through the Substrate identity module.
- **Not the registry of who exists.** The Registry is the source of truth for agents and roles. A Warden
  principal's `sub` is its Registry id; Warden only records what credentials and grants it holds.
- **Not a general secret manager for people.** 1Password stays the owner's own store.

## Build

You need Go 1.26.11 or later, with the module versions the Substrate BOM pins.

```sh
go build ./cmd/warden
go test -race ./...
```

Warden is scaffolded from Folio's `substrate-app` preset. It is a class 1 Substrate app-host with
enforced auth, offline identity bootstrap, authenticated MCP and Cerberus supervision. I chose
`substrate-app` over `substrate-service` because Warden is a networked central daemon that other machines
call. `substrate-service` is a class 2 loopback daemon.

## Run locally

```sh
./warden identity setup --username owner                        # offline; the password is typed twice
./warden identity key create --name owner-cli --scope '*' --out ~/.config/warden/owner.key
./warden serve                                                  # listens on 127.0.0.1:8080
```

With no configuration, approvals use an in-process **fake** Gatecrasher. A pending elevated or critical
request is decided by the owner with `warden dev approvals` and `warden dev decide`. Set
`warden.approvals.mode: gatecrasher` (see `docs/runbook.md`) to use the real one.

The pilot from the design (§7) shows the whole cycle for the Surface classifier's llm-gateway key:

```sh
export WARDEN_URL=http://127.0.0.1:8080
warden enroll  --token-file ~/.config/warden/owner.key --sub app:surface --kind app --out ~/.config/surface/warden.token
warden request --credential ~/.config/surface/warden.token --audience llm-gateway --scope llm-gateway.decide,llm-gateway.embed
warden token   --credential ~/.config/surface/warden.token --audience llm-gateway   # a 60-minute token
```

## How it works

| Piece | What it does |
|---|---|
| Principal | `agent`, `session` (a child of an agent), `machine`, `app` or `human`. `sub` is the Registry id. |
| Grant | One principal, one audience and a scope set, plus constraints, tier, approver, evidence and expiry. It may be revoked. Tokens name their grant in the `grant` claim. |
| Family | A line of parent credentials from one enrollment or sign-in. Its id is the token's `sid`, so revoking the family denies every token it minted. |
| Parent credential | `wdn_p_…`, opaque. Warden stores only its SHA-256 hash. It is spent on use and replaced by the next one. |
| Access token | EdDSA JWT with `iss sub aud scope exp nbf iat jti kind sid par grant act`. These are the claims `libs/security/auth` already verifies, so resource servers trust Warden through configuration alone. |

Endpoints:

| Endpoint | Auth | Purpose |
|---|---|---|
| `GET /.well-known/jwks.json` | open | Signing keys, active and in overlap |
| `GET /.well-known/oauth-authorization-server` | open | RFC 8414 metadata |
| `GET /v1/denylist` | open | `{jti,sub,sid}` with ETag, in the `libs/security/auth` format |
| `POST /v1/token` | parent credential, device code or subject token | `refresh_token`, `urn:ietf:params:oauth:grant-type:token-exchange`, `urn:ietf:params:oauth:grant-type:device_code` |
| `POST /v1/enroll`, `POST /v1/enroll/{id}/poll` | poll token | Anonymous enrollment for agents and apps |
| `POST /v1/device/code` | open | RFC 8628 device authorization |
| `/api/v1/...` | Warden token or owner key, with a scope per route | Requests, grants, families, whoami, plus owner-only device approval, disable, audit and key rotation |
| `/mcp` | `warden.mcp` | Tools `warden_request`, `warden_request_status`, `warden_grants_list` |

Token rules (tests in `internal/service/tokens_test.go`):

- **Scopes only narrow.** A refresh mints within the chosen grant. An exchange may drop scopes or time.
  Wildcards are never issued.
- **One audience per token, bound to a grant.** A token for a resource server cannot be exchanged for
  another audience. Only a Warden-audience token can be, and only toward an audience the principal holds
  a live grant for.
- **Parents rotate, and reuse revokes.** A refused mint does not spend the parent. A replayed parent
  revokes the family and denies every token the family minted.
- **Short TTLs.** 15 or 60 minutes. A token never outlives its grant or its family. Parents go idle after
  30 days, and a family ends after 90.
- **Revocation.** Revoking a grant, a family or a principal denies every live token it covers.

Tiers come from `internal/policy/default-rules.yaml`, which you can override with `warden.policy_file`.
Some floors are fixed in code and no rules file can lower them. These are always critical: admin or
wildcard scopes, `user/*` data, authority over Warden itself, human principals, device sign-in,
re-enrollment, and requests for another principal. A renewal inside an existing grant is always ground.

## Authentication

Every run enforces authentication, including on loopback. Configuration cannot turn it off. Warden's
guard accepts three things:

- Warden's own tokens for audience `warden`, verified in process through the same `libs/security/auth`
  verifier resource servers use.
- The owner's identity-module sessions.
- API keys, created offline.

The protocol endpoints authenticate themselves: a parent credential, a poll token, a device code or a
subject token. Warden stores no secret in plaintext, logs none and returns none twice.

## Further reading

- `docs/runbook.md`: configuration, keys, backup, Gatecrasher wiring and the pilot.
- `docs/gatecrasher-contract.md`: the approval contract with Gatecrasher.
- `docs/identity-bootstrap.md`: how the owner is created offline.
- `SECURITY.md`, `CONTRIBUTING.md`, `AGENTS.md`.

## License

MIT. See [LICENSE](LICENSE).
