# Warden ↔ Gatecrasher approval contract (gate v1)

Status: Gatecrasher published version 1 (draft) on 2026-11-19. Its spec is
`api/openapi/gate-v1.yaml` and its Go types are `pkg/approvalapi` in hollis-labs/gatecrasher. That is
the authority, and this document is Warden's summary of it. Warden implements it in `internal/approval`.

On 2026-11-19 this was verified against a local Gatecrasher daemon built from main: submit (digest
accepted), approval by an approver agent, the signed decision verified by Warden, and withdraw.
`TestDigestMatchesGatecrasher` pins Warden's digest to vectors computed by Gatecrasher's own code. The
in-process fake (`approvals.mode: fake`) applies Gatecrasher's submit validation and digest check.

Warden never renders or collects an approval. It submits a request, polls for its status, and acts only
on a decision Gatecrasher has signed.

## Submit

`POST /api/gate/v1/approvals` (scope `gatecrasher.approval.submit`). Submitting is idempotent on
`idempotency_key`: the same key returns the same approval.

```json
{
  "idempotency_key": "req_…",            // the Warden request id
  "source": "warden",
  "kind": "credential_grant",
  "tier": "elevated | critical",
  "approver_class": "approve.enroll",    // elevated only: the approve.<class> a decider must hold
  "principal": {"sub": "app:surface", "kind": "app", "act": [{"sub": "agent:lead", "kind": "agent"}]},
  "requested": {"audience": "llm-gateway", "scopes": ["llm-gateway.decide"],
                "ttl_seconds": 2592000, "constraints": {}},
  "purpose": "free text shown to the approver",
  "evidence": {"task_id": "…", "session_id": "…", "policy_rule": "llm-gateway-use"},
  "request_digest": "sha256:<hex>",
  "expires_at": "RFC 3339"
}
```

Answer `201 {"approval_id": "…", "status": "pending"}`.

`request_digest` is `sha256:` plus the hex SHA-256 of the RFC 8785 (JCS) canonical JSON of
`{"principal", "requested", "tier"}`. In that JSON, `act` is omitted when empty, `constraints` is always
an object and `scopes` is always an array. Gatecrasher recomputes it and refuses a mismatch.

Every `act` entry needs a `kind`. `requested` needs a non-empty audience and a positive `ttl_seconds`.
`approver_class` is required for elevated requests, allowed only for them, and must be a class
configured in Gatecrasher.

Warden maps its three request kinds as follows:

- **Grant:** the grant itself.
- **Enrollment:** its first grant, or the Warden base scopes (`warden.mcp warden.read warden.request`)
  when none was asked for, for 90 days.
- **Device sign-in:** the Warden base scopes for 90 days, with the user code in `purpose`.

## Status

- `GET /api/gate/v1/approvals/{id}` returns the current status.
- `GET /api/gate/v1/approvals/{id}/await?timeout=30s` long-polls until the status changes.

Both need scope `gatecrasher.approval.read`. So does the decision key set,
`GET /api/gate/v1/jwks.json`, which Warden reads with the same bearer. The answer is
`{"approval_id", "status": "pending|approved|denied|expired|withdrawn", "decision": "<compact JWS>"}`,
and `decision` is present once the status is approved or denied.

## Withdraw

`POST /api/gate/v1/approvals/{id}/withdraw`. Warden calls it when a request is withdrawn, when it
expires, or when the owner decides a device code directly.

## Signed decision

A compact JWS with `alg: EdDSA` and a `kid` header. The keys are at Gatecrasher's JWKS URL, or in a
pinned JWKS file. Payload:

```json
{"iss": "gatecrasher", "aud": "warden", "approval_id": "…", "request_id": "req_…",
 "request_digest": "sha256:…", "outcome": "approved | denied", "tier": "critical",
 "decider": {"sub": "user:…", "kind": "human"}, "decided_at": "RFC 3339", "exp": 1790000000,
 "narrowed": {"scopes": ["…"], "ttl_seconds": 600}}
```

Warden refuses a decision (and logs and audits the refusal) unless all of these hold:

- The signature verifies against a known key.
- `iss` matches the configured issuer and `aud` is `warden`.
- `approval_id`, `request_id`, `request_digest` and `tier` all match what Warden submitted.
- `outcome` is approved or denied.
- `exp` is in the future, and the decision lives at most 10 minutes after `decided_at`.
- The decider is neither the principal nor the requester.
- For critical, `decider.kind` is `human` and, when `warden.approvals.owner` is set, `decider.sub`
  equals it (Gatecrasher's `approvals.owner.sub`). For elevated, `decider.kind` is `agent` or `human`.
- `narrowed` only narrows: scopes are a subset, and the TTL is no longer than requested.

## Gatecrasher configuration Warden needs

- **Producer.** A Gatecrasher API key with `gatecrasher.approval.submit` and `gatecrasher.approval.read`,
  audience `gatecrasher`. Map it in `approvals.producers` to source `warden`. Warden reads it from
  `warden.approvals.token_file`.
- **Classes.** Warden's starter rules send elevated requests to `approve.enroll` and
  `approve.credentials` (the default). Configure both in `approvals.classes`, with agents and ceilings.
  Gatecrasher refuses a submit naming a class it does not know.
- **Owner.** Set `approvals.owner.sub` in Gatecrasher and `warden.approvals.owner` in Warden to the
  same registry id.

## Authentication

Warden calls Gatecrasher with a bearer read from `warden.approvals.token_file`. In the target design that
is a Warden token for audience `gatecrasher`. Until Gatecrasher trusts Warden's JWKS, a Gatecrasher API
key with the two scopes above works.

## request_secret (milestone 2)

Warden opens a one-use intake: `{intake_id, intake_url, expires_at}`. Gatecrasher's card form posts the
value write-only, straight to `intake_url` on Warden. Gatecrasher never receives, stores or logs the
value, and neither does any model transcript, even when the card renders inside a chat.
