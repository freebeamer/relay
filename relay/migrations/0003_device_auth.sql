-- clients.api_key_hash was NOT NULL UNIQUE, and a paired client no
-- longer has one — SQLite's ALTER TABLE can't drop or relax that
-- constraint in place, so the table is rebuilt. Existing rows (the old
-- static-API-key model) get a NULL public_key: they can never pass
-- challenge verification and must be re-paired to authenticate again.
CREATE TABLE clients_new (
    id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    public_key BLOB,
    created_at TIMESTAMP NOT NULL,
    revoked_at TIMESTAMP
);
INSERT INTO clients_new (id, display_name, public_key, created_at, revoked_at)
    SELECT id, display_name, NULL, created_at, revoked_at FROM clients;
DROP TABLE clients;
ALTER TABLE clients_new RENAME TO clients;

CREATE TABLE IF NOT EXISTS pairing_links (
    token_hash TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    consumed_at TIMESTAMP,
    client_id TEXT
);

CREATE TABLE IF NOT EXISTS device_sessions (
    token_hash TEXT PRIMARY KEY,
    client_id TEXT NOT NULL REFERENCES clients(id),
    issued_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    revoked_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_device_sessions_client ON device_sessions(client_id);

PRAGMA user_version = 3;
