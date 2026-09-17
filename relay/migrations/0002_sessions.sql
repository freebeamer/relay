ALTER TABLE samples ADD COLUMN sample_json TEXT;
ALTER TABLE samples ADD COLUMN session_id TEXT;
ALTER TABLE samples ADD COLUMN sequence INTEGER;
CREATE UNIQUE INDEX idx_sample_identity ON samples(client_id, session_id, sequence) WHERE session_id IS NOT NULL;
CREATE TABLE telemetry_sessions (
 client_id TEXT NOT NULL,
 session_id TEXT NOT NULL,
 device_id TEXT NOT NULL,
 metadata_json TEXT NOT NULL,
 PRIMARY KEY (client_id, session_id)
);
PRAGMA user_version = 2;
