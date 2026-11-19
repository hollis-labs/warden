# warden

Warden issues and manages credentials for non-human principals: one issuer, token exchange and refresh,
tiered grants, and a vault (milestone 2).

It is not: an approval UI (Gatecrasher owns approvals), a place people sign in, the registry of who exists
(the Registry is), or a place a secret is ever stored or logged in plaintext.

## Start Here

- `README.md`: what Warden is, the token rules and the endpoints.
- `cmd/warden/serve.go`: the composition root. It wires settings, policy, the approver (fake or
  Gatecrasher), the service, scopes, MCP tools, the routes and mounts, and the background workers.
- `cmd/warden/config.go`: opens the issuer keys before boot, so the auth module verifies Warden's own
  tokens in process.
- `internal/issuer/`: Ed25519 key ring (rotation with overlap, JWKS) and the JWT format. Pure crypto and
  files.
- `internal/service/`: the only code that runs SQL. `tokens.go` covers refresh, rotation, reuse
  detection, mint and exchange. `requests.go` covers tiers and Gatecrasher sync. `enroll.go` covers
  enrollment and the device flow. `revoke.go` covers revocation and audit.
- `internal/policy/`: the tier PDP (a libs/security/policy PDP), its fixed floors, and
  `default-rules.yaml`.
- `internal/approval/`: the Gatecrasher contract, the signed-decision verifier, the HTTP client and the
  fake.
- `internal/vault/`: milestone-2 skeleton. It defines `warden://` refs, envelope encryption and the
  Backend interface.
- `internal/api/`: `api.go` holds the guarded `/api/v1` routes and their scopes. `protocol.go` holds the
  open protocol endpoints.
- `client/`: the public Go client and the rotation-aware Minter that apps plug into libs auth's
  Refresher.
- `docs/gatecrasher-contract.md`, `docs/runbook.md`.

## Commands

```sh
gofmt -l .
go vet ./...
go test -race -count=1 ./...
GOWORK=off golangci-lint run ./...
GOWORK=off golangci-lint run --config .golangci.transport.yml ./...
go run github.com/hollis-labs/substrate/cmd/substrate scan-public --ref HEAD
```

CI (`.github/workflows/check.yml`) is the full gate.

## Boundaries

- Never weaken a token rule without its test: narrowing-only scopes, one audience per token bound to a
  grant, rotate-on-use parents with reuse detection, short TTLs, and deny on revoke.
- The policy floors in `internal/policy/policy.go` encode the owner's 2026-11-19 ruling. Do not move them
  into the rules file.
- Warden builds no approval UI. Elevated and critical requests go to Gatecrasher, and only a decision
  Gatecrasher signed is acted on. A `request_secret` value goes write-only to Warden, never through
  Gatecrasher or a model transcript.
- No secret in plaintext. Store parent credentials, poll tokens and device codes as hashes only, and
  never log a token.
- Do not change other repos from here (Tether, Substrate, libs, llm-gateway, mcp-gateway). Write the ask
  down and route it.
- Edit pins only in the Substrate `bom/bom.yaml`, then run `substrate pins sync --app .`.
- Transports (`internal/api`, `internal/mcp`) never import `internal/storage`, the database module or
  `database/sql`.
- A guarded route without a scope is refused. Add it to `Routes()` (`TestEveryRouteHasAScope`).
- No secret, host name, address or personal path in a file, a commit or CI. `substrate scan-public`
  must stay clean. Deployment descriptors are templates with no target hosts.
