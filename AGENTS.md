# warden

Shared credentials service: one issuer, token exchange, tiered grants and a vault for non-human principals

It is not: TODO(author) — the mistake this repo attracts.

## Start Here

- `cmd/warden/substrate.yaml` — the manifest: modules and config defaults. `substrate_wiring.go` is generated from it (`substrate generate`); never edit it.
- `cmd/warden/serve.go` — the HTTP handler stack: Host check, identity middleware, the host (guard, routes, SPA).
- `internal/api/api.go` — every route and the scope it needs. The owner of a row is the verified principal, never a request field.
- `internal/service/service.go` — the service layer, the only code that runs SQL; handlers call it. `.golangci.transport.yml` (second lint run) enforces that; `docs/transport-boundary.md` says how.
- `internal/storage/migrations/sqlite/00001_init.sql` — the schema. Until the first release this is the only migration.
- `docs/identity-bootstrap.md` — the owner is created offline; there is no open setup over HTTP.
- `.github/workflows/check.yml` — the full CI gate (vet, pins, wiring current, race tests, both lint runs, scan-public).

## Commands

```sh
gofmt -l .
go vet ./...
go test -race -count=1 ./...
```

CI (`.github/workflows/check.yml`) is the full gate.

## Boundaries

- Pins are edited only in the Substrate `bom/bom.yaml`: run `substrate pins sync --app .`, never hand-edit a version in `go.mod`.
- Transports (`internal/api`, later `internal/mcp`, `internal/cli`) never import `internal/storage`, the Substrate `database` module or `database/sql`; go through `internal/service`.
- A route without a scope is refused in `enforce`: add it to `Routes()` in `internal/api/api.go` (`TestEveryRouteHasAScope` guards this).
- Reads go through `Reader()`, writes through `WriteTx` or one `ExecContext`; never write while a cursor is open on the write handle (SQLite has one write connection).
- No secret, host name, address or personal path in a file, a commit or CI: `substrate scan-public --ref HEAD` must stay clean.
