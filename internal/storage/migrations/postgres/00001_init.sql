-- Warden's schema, Postgres dialect (parity with ../sqlite). One migration. Until the first release this is the ONLY migration: a schema change
-- edits this file, because there are no deployed databases to migrate. After the first release changes
-- are new numbered files. The sqlite and postgres directories stay in parity (same versions, same tables
-- and columns); only types differ. Times are fixed-width RFC 3339 UTC text in both, so they compare as
-- strings. No table holds a secret: parent credentials, poll tokens
-- and device codes are stored as SHA-256 hashes only.
--
-- Not here, on purpose: the owner's account, password, sessions and API keys are the identity module's
-- identity_* tables.

-- +goose Up

-- Who holds credentials. sub is the Registry canonical id (a string for now).
CREATE TABLE principals (
	sub TEXT PRIMARY KEY,
	kind TEXT NOT NULL CHECK (kind IN ('agent','session','machine','app','human')),
	display TEXT NOT NULL DEFAULT '',
	parent TEXT REFERENCES principals(sub),
	created_at TEXT NOT NULL,
	disabled_at TEXT
);

-- What they may do: one audience, a scope set, constraints, and how it was approved.
CREATE TABLE grants (
	id TEXT PRIMARY KEY,
	principal TEXT NOT NULL REFERENCES principals(sub),
	audience TEXT NOT NULL,
	scopes TEXT NOT NULL,
	constraints TEXT NOT NULL DEFAULT '{}',
	tier TEXT NOT NULL,
	rule TEXT NOT NULL DEFAULT '',
	approver TEXT NOT NULL DEFAULT '',
	approval_ref TEXT NOT NULL DEFAULT '',
	request_id TEXT NOT NULL DEFAULT '',
	evidence TEXT NOT NULL DEFAULT '{}',
	created_at TEXT NOT NULL,
	expires_at TEXT NOT NULL,
	last_used_at TEXT,
	revoked_at TEXT,
	revoke_reason TEXT NOT NULL DEFAULT ''
);
CREATE INDEX grants_principal ON grants(principal, audience);

-- A family is one line of rotating parent credentials (one enrollment or sign-in). Replaying a rotated
-- member revokes the family.
CREATE TABLE families (
	id TEXT PRIMARY KEY,
	principal TEXT NOT NULL REFERENCES principals(sub),
	origin TEXT NOT NULL,
	actor TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL,
	expires_at TEXT NOT NULL,
	revoked_at TEXT,
	revoke_reason TEXT NOT NULL DEFAULT ''
);

CREATE TABLE parents (
	id TEXT PRIMARY KEY,
	family TEXT NOT NULL REFERENCES families(id),
	hash TEXT NOT NULL UNIQUE,
	status TEXT NOT NULL CHECK (status IN ('active','rotated','revoked')),
	created_at TEXT NOT NULL,
	idle_expires_at TEXT NOT NULL,
	used_at TEXT
);
CREATE INDEX parents_family ON parents(family);

-- Every access token minted (ids only), so revoking a family or a grant can deny what it already issued.
CREATE TABLE minted (
	jti TEXT PRIMARY KEY,
	family TEXT NOT NULL DEFAULT '',
	grant_id TEXT NOT NULL DEFAULT '',
	sub TEXT NOT NULL,
	aud TEXT NOT NULL,
	expires_at TEXT NOT NULL
);
CREATE INDEX minted_family ON minted(family);
CREATE INDEX minted_grant ON minted(grant_id);

CREATE TABLE requests (
	id TEXT PRIMARY KEY,
	action TEXT NOT NULL,
	principal TEXT NOT NULL,
	principal_kind TEXT NOT NULL,
	requester TEXT NOT NULL DEFAULT '',
	audience TEXT NOT NULL DEFAULT '',
	scopes TEXT NOT NULL DEFAULT '',
	ttl_seconds BIGINT NOT NULL DEFAULT 0,
	constraints TEXT NOT NULL DEFAULT '{}',
	purpose TEXT NOT NULL DEFAULT '',
	evidence TEXT NOT NULL DEFAULT '{}',
	tier TEXT NOT NULL,
	rule TEXT NOT NULL DEFAULT '',
	status TEXT NOT NULL CHECK (status IN ('pending','approved','denied','expired','withdrawn')),
	approval_id TEXT NOT NULL DEFAULT '',
	digest TEXT NOT NULL DEFAULT '',
	decided_by TEXT NOT NULL DEFAULT '',
	decision TEXT NOT NULL DEFAULT '',
	grant_id TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL,
	expires_at TEXT NOT NULL
);
CREATE INDEX requests_principal ON requests(principal);
CREATE INDEX requests_status ON requests(status);

-- Agent-facing enrollment: the poll token is how the enrolling process collects its first parent.
CREATE TABLE enrollments (
	id TEXT PRIMARY KEY,
	request_id TEXT NOT NULL REFERENCES requests(id),
	sub TEXT NOT NULL,
	kind TEXT NOT NULL,
	display TEXT NOT NULL DEFAULT '',
	parent TEXT NOT NULL DEFAULT '',
	poll_hash TEXT NOT NULL UNIQUE,
	status TEXT NOT NULL CHECK (status IN ('pending','ready','delivered','refused')),
	created_at TEXT NOT NULL,
	expires_at TEXT NOT NULL,
	delivered_at TEXT
);

-- RFC 8628 device authorization.
CREATE TABLE device_codes (
	id TEXT PRIMARY KEY,
	request_id TEXT NOT NULL REFERENCES requests(id),
	device_hash TEXT NOT NULL UNIQUE,
	user_code TEXT NOT NULL UNIQUE,
	sub TEXT NOT NULL,
	kind TEXT NOT NULL,
	display TEXT NOT NULL DEFAULT '',
	status TEXT NOT NULL CHECK (status IN ('pending','approved','denied','consumed','expired')),
	interval_seconds INTEGER NOT NULL,
	last_poll_at TEXT,
	created_at TEXT NOT NULL,
	expires_at TEXT NOT NULL
);

CREATE TABLE deny (
	kind TEXT NOT NULL CHECK (kind IN ('jti','sub','sid')),
	value TEXT NOT NULL,
	until TEXT,
	reason TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL,
	PRIMARY KEY (kind, value)
);

CREATE TABLE audit (
	id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
	at TEXT NOT NULL,
	actor TEXT NOT NULL,
	action TEXT NOT NULL,
	subject TEXT NOT NULL DEFAULT '',
	detail TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX audit_subject ON audit(subject);

-- +goose Down

DROP TABLE audit;
DROP TABLE deny;
DROP TABLE device_codes;
DROP TABLE enrollments;
DROP TABLE requests;
DROP TABLE minted;
DROP TABLE parents;
DROP TABLE families;
DROP TABLE grants;
DROP TABLE principals;
