CREATE TABLE IF NOT EXISTS clients (
    id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    api_key_hash TEXT NOT NULL UNIQUE,
    created_at TIMESTAMP NOT NULL,
    revoked_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS samples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id TEXT NOT NULL REFERENCES clients(id),
    device_id TEXT NOT NULL,
    ts_client TIMESTAMP NOT NULL,
    ts_received TIMESTAMP NOT NULL,
    values_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_samples_client_received ON samples(client_id, ts_received);
