# Changelog

All notable changes to warden are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Write the entry for a release here BEFORE cutting its tag: the release workflow
refuses a tag whose CHANGELOG has no heading for it.

## Unreleased

### Added

- Initial scaffold from Folio `substrate-app` 0.1.0 (class 1 app-host, enforced auth, MCP, Cerberus supervision).
- Issuer: Ed25519 key ring with rotation and a 70-minute overlap. JWKS, RFC 8414 metadata and a deny-list endpoint (libs auth format, ETag).
- `POST /v1/token`: refresh with rotate-on-use parent credentials and reuse detection that revokes the family. RFC 8693 token exchange (narrowing only; changing audience needs a Warden token and a grant; `act` chain). RFC 8628 device-code redemption.
- Access tokens: one audience each, with `grant`, `act`, `sid` (family) and `par` claims. TTL 15 minutes for agents, sessions and humans, 60 minutes for apps and machines, bounded by the grant and the family.
- Enrollment: anonymous `POST /v1/enroll` with a poll token and exactly-once delivery, authenticated `/api/v1/enroll`, and agents enrolling their own sessions at ground tier.
- Requests and grants: `/api/v1` API, MCP tools `warden_request`, `warden_request_status` and `warden_grants_list`, and the `warden request|grants|token|enroll|device|whoami` CLI.
- Policy: a libs/security/policy PDP with a declarative rules file and fixed critical floors. Ground is auto-approved; elevated and critical go to Gatecrasher.
- Gatecrasher gate v1 client (`docs/gatecrasher-contract.md`): the RFC 8785 request digest, pinned to Gatecrasher's vectors; a signed-decision verifier bound to the digest, the tier, the owner and no self-approval; and an in-process fake that applies Gatecrasher's submit validation.
- Revocation of grants, families and principals, applied to live tokens through the deny-list. Audit log.
- Vault skeleton: `warden://` references, AES-256-GCM envelope encryption (per-secret DEK, KEK file), Backend interface and memory backend.
- `client` package: a rotation-aware Minter for libs auth's Refresher, holding an exclusive lock on the parent file.
