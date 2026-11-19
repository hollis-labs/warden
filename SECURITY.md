# Security policy

## Supported versions

Warden is pre-1.0, experimental software. Security fixes go to `main` and ship as a new patch version.
There are no backports.

## Report a vulnerability

Do not put an exploit, token, parent credential, signing key, database or other sensitive material in a
public issue.

Report privately through GitHub's private vulnerability reporting, if the repository's Security tab
offers it. If it does not, contact a maintainer privately through a channel published on the Hollis Labs
organization or a maintainer's profile. Include:

- the affected commit and operating system
- the part involved: `/v1/token`, enrollment, the device flow, `/api/v1`, `/mcp`, the policy or the
  approval verifier
- how it was reached: loopback, tailnet or a proxy
- the steps to reproduce it, and its security impact
- a safe way to reach you to coordinate

Maintainers acknowledge private reports, investigate them and coordinate disclosure. Response times are
best effort.

## What Warden protects, and how

- **Signing keys.** Ed25519 seeds live in 0600 files in a 0700 directory under the data directory.
  Warden refuses looser files. Rotated keys are published only through their overlap window.
- **Parent credentials, poll tokens and device codes.** Warden stores only their SHA-256 hashes. A parent
  is spent on use, and replaying a spent one revokes its whole family.
- **Access tokens.** Short-lived, one audience each, and narrowing-only. Revocation denies them by
  `jti`, `sid` (the family) or `sub`.
- **Approvals.** Warden acts only on a decision Gatecrasher signed for exactly the request it asked
  about: same request id, same digest, same tier, not expired, and not decided by the requester or the
  principal. A critical decision must come from a human.
- **Policy floors.** Admin and wildcard scopes, owner data, authority over Warden, human principals,
  device sign-in, re-enrollment and requests for another principal are always critical, whatever the
  rules file says.

## Deployment boundary

- Authentication is enforced on every listener, including loopback.
- The open endpoints (`/v1/token`, `/v1/enroll`, `/v1/device/code`) authenticate themselves or only
  create pending requests. Pending enrollments and device codes are capped.
- `approvals.mode: fake` is for development only. It lets the owner decide approvals through owner-only
  dev routes. Do not run it where other people's credentials are issued.
- Set `warden.allowed_hosts` and `warden.public_url` before exposing Warden beyond loopback. Put it behind
  TLS when it leaves the machine.

Known limits in milestone 1: parent credentials are bearer, not yet sender-constrained (DPoP is planned).
A client that crashes between Warden rotating its parent and the client saving the new one must
re-enroll. Storage is SQLite; Postgres comes with deployment.
