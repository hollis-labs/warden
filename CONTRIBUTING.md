# Contributing

This is how a change gets from your clone into `main`. It is short on purpose: `AGENTS.md` is the
orientation, and the docs sit next to what they describe.

## Before your first change

`README.md` has the build and run steps. Run `lefthook install` first: a tracked config installs no hooks
by itself.

## The sequence

1. **Branch.** Name it `<type>/<short-slug>`, where the type matches the change: `feat`, `fix`, `docs`
   or `chore`.
2. **Change one thing.**
3. **Run the checks:** `go vet ./...`, `go test -race ./...`, both golangci-lint runs (the second one
   with `--config .golangci.transport.yml`), and `substrate scan-public --ref HEAD`. After editing
   `cmd/warden/substrate.yaml`, run `substrate generate -f cmd/warden/substrate.yaml` and commit what it
   writes.
4. **Push, and open a pull request** against `main`.

Commit subjects follow the conventional-commit shape: a type, an optional scope, a colon, then the summary.

## What a pull request should carry

Say what the change does, what it deliberately leaves alone, and the evidence that it works: the commands
you ran and what came back.

A change to a token rule, a policy floor or the approval verifier needs a test that fails without it.

## Things that surprise people

- **The parent credential in a file is spent every time it is used.** Copying a parent file and using
  both copies revokes the family. That is reuse detection working, not a bug.
- **The policy floors are in code, not in the rules file.** That is deliberate; see `AGENTS.md`.
- **`approvals.mode` defaults to `fake`.** Elevated and critical requests stay pending until the owner
  decides them with `warden dev decide`.
- **No secrets or real config in the repository.** It is public, and `scan-public` is a CI check.
- **Use a disposable data directory** (`WARDEN_DATA_DIR`, or the XDG variables) for experiments.

## What this does not cover

- **Which change is worth making.** That conversation happens in issues.
- **Release.** Tags and releases are cut by the maintainer. Prepare the CHANGELOG entry; do not tag.
