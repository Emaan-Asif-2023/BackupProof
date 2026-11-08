PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    password_hash   TEXT    NOT NULL,
    role            TEXT    NOT NULL CHECK (role IN ('admin', 'operator', 'viewer')),
    is_active       INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until    TEXT,
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE TABLE IF NOT EXISTS assets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    description TEXT    NOT NULL DEFAULT '',
    created_by  INTEGER NOT NULL REFERENCES users(id),
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE TABLE IF NOT EXISTS backups (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    public_id         TEXT    NOT NULL UNIQUE,          -- server-generated, used in URLs
    asset_id          INTEGER NOT NULL REFERENCES assets(id) ON DELETE RESTRICT,
    original_filename TEXT    NOT NULL,                 -- display only, never used as a path
    stored_filename   TEXT    NOT NULL UNIQUE,          -- server-generated name on disk
    size_bytes        INTEGER NOT NULL CHECK (size_bytes > 0),
    sha256            TEXT    NOT NULL CHECK (length(sha256) = 64),  -- baseline checksum
    source            TEXT    NOT NULL CHECK (source IN ('upload', 'register')),
    status            TEXT    NOT NULL DEFAULT 'registered',
    retention_days    INTEGER NOT NULL CHECK (retention_days BETWEEN 1 AND 3650),
    notes             TEXT    NOT NULL DEFAULT '',
    created_by        INTEGER NOT NULL REFERENCES users(id),
    created_at        TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_backups_asset ON backups(asset_id);
CREATE INDEX IF NOT EXISTS idx_backups_created ON backups(created_at);

-- Append-only audit trail: triggers block any UPDATE or DELETE.
CREATE TABLE IF NOT EXISTS audit_log (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    actor   TEXT NOT NULL,
    action  TEXT NOT NULL,
    target  TEXT,
    outcome TEXT NOT NULL CHECK (outcome IN ('success', 'failure', 'denied')),
    detail  TEXT,
    ip      TEXT
);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;


INSERT OR IGNORE INTO users
    (username, password_hash, role, is_active)
VALUES
    ('admin',
     'pbkdf2:sha256:600000$BackupProofAdminSalt$4ef3f8e23925cb5ff2c472e3875377eda703def7ce496e2d0b21ad9dc71de337',
     'admin',
     1);


INSERT OR IGNORE INTO users
    (username, password_hash, role, is_active)
VALUES
    ('operator',
     'pbkdf2:sha256:600000$BackupProofOperatorSalt$382f013e6feca5cd378dc690a577bc3804df24c899e01a555b25b4fa62564856',
     'operator',
     1);

INSERT OR IGNORE INTO users
    (username, password_hash, role, is_active)
VALUES
    ('viewer',
     'pbkdf2:sha256:600000$BackupProofViewerSalt$93f9256166d7750fbb98838329b1da32e108c51235fe776af87cf637ad586cd5',
     'viewer',
     1);