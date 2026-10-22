PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS invitations (
    id TEXT PRIMARY KEY,
    code_hmac BLOB NOT NULL UNIQUE,
    relative_name TEXT NOT NULL,
    device_name TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    max_attempts INTEGER NOT NULL DEFAULT 5 CHECK (max_attempts BETWEEN 1 AND 20),
    failed_attempts INTEGER NOT NULL DEFAULT 0 CHECK (failed_attempts >= 0),
    used_at INTEGER,
    revoked_at INTEGER,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY,
    invitation_id TEXT NOT NULL REFERENCES invitations(id),
    relative_name TEXT NOT NULL,
    device_name TEXT NOT NULL,
    platform TEXT NOT NULL,
    credential_ref TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL CHECK (state IN ('pending', 'active', 'revoked', 'revoke_pending')),
    created_at INTEGER NOT NULL,
    revoked_at INTEGER
);

CREATE INDEX IF NOT EXISTS devices_created_at_idx ON devices(created_at DESC);
CREATE INDEX IF NOT EXISTS invitations_expires_at_idx ON invitations(expires_at);

-- The bearer token itself is never stored. token_hmac is an HMAC-SHA256 made
-- with the same server-side pepper as invitation codes.
CREATE TABLE IF NOT EXISTS subscription_tokens (
    token_hmac BLOB PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    last_used_at INTEGER,
    revoked_at INTEGER
);
CREATE INDEX IF NOT EXISTS subscription_tokens_device_idx ON subscription_tokens(device_id);
CREATE INDEX IF NOT EXISTS subscription_tokens_expires_idx ON subscription_tokens(expires_at);

CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    subject_id TEXT,
    remote_ip_hmac TEXT,
    detail TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS audit_events_created_at_idx ON audit_events(created_at DESC);

CREATE TABLE IF NOT EXISTS activation_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_hmac TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS activation_attempts_ip_time_idx ON activation_attempts(ip_hmac, created_at);

CREATE TABLE IF NOT EXISTS rate_limit_state (
    ip_hmac TEXT PRIMARY KEY,
    failures INTEGER NOT NULL DEFAULT 0,
    blocked_until INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS code_attempts (
    code_hmac BLOB PRIMARY KEY,
    attempts INTEGER NOT NULL,
    last_attempt_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS admin_invitation_creations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS admin_invitation_creations_time_idx ON admin_invitation_creations(created_at);

CREATE TABLE IF NOT EXISTS access_requests (
    id TEXT PRIMARY KEY,
    token_hmac BLOB NOT NULL UNIQUE,
    relative_name TEXT NOT NULL,
    device_name TEXT NOT NULL,
    platform TEXT NOT NULL,
    remote_ip_hmac TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending', 'approved', 'denied', 'expired')),
    invitation_id TEXT REFERENCES invitations(id),
    encrypted_code BLOB,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    decided_at INTEGER
);
CREATE INDEX IF NOT EXISTS access_requests_expires_idx ON access_requests(expires_at);
CREATE INDEX IF NOT EXISTS access_requests_ip_time_idx ON access_requests(remote_ip_hmac, created_at);
