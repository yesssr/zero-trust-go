
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL,
    token_hash  TEXT NOT NULL UNIQUE,
    expires_at  TEXT NOT NULL,
    revoked_at  TEXT,
    created_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS service_clients (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id    TEXT NOT NULL UNIQUE,
    secret_hash  TEXT NOT NULL,
    name         TEXT NOT NULL,
    active       INTEGER NOT NULL DEFAULT 1
                 CHECK (active IN (0, 1)),
    created_at   TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS transcripts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id   INTEGER NOT NULL UNIQUE,
    total_credits INTEGER NOT NULL DEFAULT 0,
    gpa          REAL NOT NULL DEFAULT 0,
    synced_at    TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (student_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    subject     TEXT,
    endpoint    TEXT NOT NULL,
    device_id   TEXT,
    decision    TEXT NOT NULL
                CHECK (decision IN ('allow', 'deny')),
    reason      TEXT NOT NULL
);
