# Warden ↔ Gatecrasher approval contract (v0)

Status: proposed by Warden on 2026-11-19 and sent to the Gatecrasher builder. Warden codes against it
through `internal/approval`, with an in-process fake (`approvals.mode: fake`) until Gatecrasher ships it.
Gatecrasher owns the API, and this document follows whatever Gatecrasher publishes.

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
  "principal": {"sub": "app:surface", "kind": "app", "act": [{"sub": "agent:lead"}]},
  "requested": {"action": "grant | enroll | device", "audience": "llm-gateway",
                "scopes": ["llm-gateway.decide"], "ttl_seconds": 2592000, "constraints": {}},
  "purpose": "free text shown to the approver",
  "evidence": {"task_id": "…", "session_id": "…", "user_code": "BCDF-GHJK"},
  "request_digest": "sha256:<hex>",
  "expires_at": "RFC 3339"
}
```

Answer `201 {"approval_id": "…", "status": "pending"}`.

`request_digest` is the SHA-256 of the JSON object
`{"principal": …, "requested": …, "tier": …}`, with fields in the order shown above and scopes sorted
(`approval.Digest`). The decision must carry it back unchanged.

## Status

- `GET /api/gate/v1/approvals/{id}` returns the current status.
- `GET /api/gate/v1/approvals/{id}/await?timeout=30s` long-polls until the status changes.

Both need scope `gatecrasher.approval.read`. The answer is
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
- For critical, `decider.kind` is `human` (the owner). For elevated, it is `agent` or `human`.
- `narrowed` only narrows: scopes are a subset, and the TTL is no longer than requested.

## Authentication

Warden calls Gatecrasher with a bearer read from `warden.approvals.token_file`. In the target design that
is a Warden token for audience `gatecrasher`. Until Gatecrasher trusts Warden's JWKS, a Gatecrasher API
key with the two scopes above works.

## request_secret (milestone 2)

Warden opens a one-use intake: `{intake_id, intake_url, expires_at}`. Gatecrasher's card form posts the
value write-only, straight to `intake_url` on Warden. Gatecrasher never receives, stores or logs the
value, and neither does any model transcript, even when the card renders inside a chat.
