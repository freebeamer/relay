package relay

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/freebeamer/core/pkg/telemetry"

	_ "modernc.org/sqlite"
)

//go:embed migrations/0001_init.sql
var initSchema string

//go:embed migrations/0002_sessions.sql
var sessionSchema string

//go:embed migrations/0003_device_auth.sql
var deviceAuthSchema string

// SQLiteStore is a Store backed by modernc.org/sqlite, a pure-Go
// driver — chosen so the relay binary and its Docker image stay
// cgo-free. This is a short rolling buffer for live-feed reconnect and
// backfill, not durable analytics storage; see PruneSamplesOlderThan
// and the pruning loop in server.go.
//
// database/sql's connection pool doesn't serialize SQLite writers
// safely on its own. Rather than a custom writer-goroutine, this store
// takes the simplest correct fix for v0's scope (a short rolling
// buffer, not a high-throughput store): WAL mode plus a single
// connection (SetMaxOpenConns(1)), so every read and write serializes
// through one connection. That caps read concurrency too, which is an
// acceptable trade at this data volume — revisit if the relay ever
// needs to serve many simultaneous live feeds against heavy ingest.
type SQLiteStore struct {
	db *sql.DB
}

// NewSQLiteStore opens (creating if needed) a SQLite database at path
// and applies the schema in migrations/0001_init.sql.
func NewSQLiteStore(path string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("relay: open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)

	if _, err := db.Exec(`PRAGMA journal_mode = WAL`); err != nil {
		db.Close()
		return nil, fmt.Errorf("relay: enable WAL: %w", err)
	}
	if _, err := db.Exec(`PRAGMA busy_timeout = 5000`); err != nil {
		db.Close()
		return nil, fmt.Errorf("relay: set busy_timeout: %w", err)
	}
	if _, err := db.Exec(initSchema); err != nil {
		db.Close()
		return nil, fmt.Errorf("relay: apply schema: %w", err)
	}
	var version int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		db.Close()
		return nil, err
	}
	if version > 3 {
		db.Close()
		return nil, fmt.Errorf("relay: unsupported schema version %d", version)
	}
	if version < 2 {
		tx, err := db.Begin()
		if err != nil {
			db.Close()
			return nil, err
		}
		if _, err = tx.Exec(sessionSchema); err != nil {
			tx.Rollback()
			db.Close()
			return nil, fmt.Errorf("relay: migrate sessions: %w", err)
		}
		if err = tx.Commit(); err != nil {
			db.Close()
			return nil, err
		}
	}
	if version < 3 {
		tx, err := db.Begin()
		if err != nil {
			db.Close()
			return nil, err
		}
		if _, err = tx.Exec(deviceAuthSchema); err != nil {
			tx.Rollback()
			db.Close()
			return nil, fmt.Errorf("relay: migrate device auth: %w", err)
		}
		if err = tx.Commit(); err != nil {
			db.Close()
			return nil, err
		}
	}
	return &SQLiteStore{db: db}, nil
}

func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

// normalizeTime strips a time.Time's monotonic clock reading (present
// on any value from time.Now()) and forces UTC. Without this, two
// timestamps taken microseconds apart can serialize to strings whose
// lexicographic order doesn't match their chronological order
// (the monotonic component's textual width varies with process
// uptime) — every timestamp this store binds as a query parameter
// goes through this first so comparisons/ordering stay correct.
func normalizeTime(t time.Time) time.Time {
	return t.Round(0).UTC()
}

func (s *SQLiteStore) ListClients(ctx context.Context) ([]Client, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, display_name, public_key, created_at, revoked_at FROM clients ORDER BY created_at`,
	)
	if err != nil {
		return nil, fmt.Errorf("relay: list clients: %w", err)
	}
	defer rows.Close()

	var clients []Client
	for rows.Next() {
		client, err := scanClient(rows)
		if err != nil {
			return nil, fmt.Errorf("relay: list clients: %w", err)
		}
		clients = append(clients, client)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("relay: list clients: %w", err)
	}
	return clients, nil
}

func (s *SQLiteStore) RevokeClient(ctx context.Context, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("relay: revoke client: %w", err)
	}
	defer tx.Rollback()

	now := normalizeTime(time.Now())
	result, err := tx.ExecContext(ctx,
		`UPDATE clients SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`,
		now, id,
	)
	if err != nil {
		return fmt.Errorf("relay: revoke client: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("relay: revoke client: %w", err)
	}
	if affected == 0 {
		return ErrClientNotFound
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE device_sessions SET revoked_at = ? WHERE client_id = ? AND revoked_at IS NULL`,
		now, id,
	); err != nil {
		return fmt.Errorf("relay: revoke client sessions: %w", err)
	}
	return tx.Commit()
}

func (s *SQLiteStore) LookupClientByID(ctx context.Context, id string) (Client, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, display_name, public_key, created_at, revoked_at FROM clients WHERE id = ? AND revoked_at IS NULL`,
		id,
	)
	client, err := scanClient(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Client{}, ErrClientNotFound
	}
	if err != nil {
		return Client{}, fmt.Errorf("relay: lookup client: %w", err)
	}
	return client, nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanClient(row rowScanner) (Client, error) {
	var (
		client    Client
		publicKey []byte
		revokedAt sql.NullTime
	)
	if err := row.Scan(&client.ID, &client.DisplayName, &publicKey, &client.CreatedAt, &revokedAt); err != nil {
		return Client{}, err
	}
	client.PublicKey = publicKey
	if revokedAt.Valid {
		client.RevokedAt = &revokedAt.Time
	}
	return client, nil
}

func (s *SQLiteStore) CreatePairingLink(ctx context.Context, tokenHash, displayName string, expiresAt time.Time) (PairingLink, error) {
	now := normalizeTime(time.Now())
	expiresAt = normalizeTime(expiresAt)
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO pairing_links (token_hash, display_name, created_at, expires_at) VALUES (?, ?, ?, ?)`,
		tokenHash, displayName, now, expiresAt,
	)
	if err != nil {
		return PairingLink{}, fmt.Errorf("relay: create pairing link: %w", err)
	}
	return PairingLink{TokenHash: tokenHash, DisplayName: displayName, CreatedAt: now, ExpiresAt: expiresAt}, nil
}

// ConsumePairingLink is the one place a Client row gets created —
// clients only ever come from a successful pairing. The UPDATE's
// WHERE clause (unconsumed, unexpired) is the sole race guard; combined
// with SetMaxOpenConns(1) serializing every statement through one
// connection, a second concurrent redemption of the same token always
// affects zero rows and loses.
func (s *SQLiteStore) ConsumePairingLink(ctx context.Context, tokenHash, newClientID string, publicKey []byte) (Client, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Client{}, fmt.Errorf("relay: consume pairing link: %w", err)
	}
	defer tx.Rollback()

	now := normalizeTime(time.Now())
	var displayName string
	if err := tx.QueryRowContext(ctx,
		`SELECT display_name FROM pairing_links WHERE token_hash = ? AND consumed_at IS NULL AND expires_at > ?`,
		tokenHash, now,
	).Scan(&displayName); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Client{}, ErrPairingLinkInvalid
		}
		return Client{}, fmt.Errorf("relay: consume pairing link: %w", err)
	}

	result, err := tx.ExecContext(ctx,
		`UPDATE pairing_links SET consumed_at = ?, client_id = ? WHERE token_hash = ? AND consumed_at IS NULL AND expires_at > ?`,
		now, newClientID, tokenHash, now,
	)
	if err != nil {
		return Client{}, fmt.Errorf("relay: consume pairing link: %w", err)
	}
	if affected, err := result.RowsAffected(); err != nil || affected == 0 {
		if err != nil {
			return Client{}, fmt.Errorf("relay: consume pairing link: %w", err)
		}
		return Client{}, ErrPairingLinkInvalid
	}

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO clients (id, display_name, public_key, created_at) VALUES (?, ?, ?, ?)`,
		newClientID, displayName, publicKey, now,
	); err != nil {
		return Client{}, fmt.Errorf("relay: consume pairing link: create client: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return Client{}, fmt.Errorf("relay: consume pairing link: %w", err)
	}
	return Client{ID: newClientID, DisplayName: displayName, PublicKey: publicKey, CreatedAt: now}, nil
}

func (s *SQLiteStore) CreateDeviceSession(ctx context.Context, tokenHash, clientID string, expiresAt time.Time) (DeviceSession, error) {
	now := normalizeTime(time.Now())
	expiresAt = normalizeTime(expiresAt)
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO device_sessions (token_hash, client_id, issued_at, expires_at) VALUES (?, ?, ?, ?)`,
		tokenHash, clientID, now, expiresAt,
	)
	if err != nil {
		return DeviceSession{}, fmt.Errorf("relay: create device session: %w", err)
	}
	return DeviceSession{TokenHash: tokenHash, ClientID: clientID, IssuedAt: now, ExpiresAt: expiresAt}, nil
}

func (s *SQLiteStore) LookupDeviceSession(ctx context.Context, tokenHash string) (DeviceSession, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT token_hash, client_id, issued_at, expires_at, revoked_at FROM device_sessions
		 WHERE token_hash = ? AND revoked_at IS NULL AND expires_at > ?`,
		tokenHash, normalizeTime(time.Now()),
	)
	var (
		session   DeviceSession
		revokedAt sql.NullTime
	)
	if err := row.Scan(&session.TokenHash, &session.ClientID, &session.IssuedAt, &session.ExpiresAt, &revokedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return DeviceSession{}, ErrSessionInvalid
		}
		return DeviceSession{}, fmt.Errorf("relay: lookup device session: %w", err)
	}
	if revokedAt.Valid {
		session.RevokedAt = &revokedAt.Time
	}
	return session, nil
}

func (s *SQLiteStore) RevokeDeviceSession(ctx context.Context, tokenHash string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE device_sessions SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL`,
		normalizeTime(time.Now()), tokenHash,
	)
	if err != nil {
		return fmt.Errorf("relay: revoke device session: %w", err)
	}
	return nil
}

func (s *SQLiteStore) SaveSample(ctx context.Context, clientID string, sample telemetry.Sample) error {
	if err := sample.Validate(); err != nil {
		return err
	}
	received := normalizeTime(time.Now())
	if sample.ReceivedAt != nil {
		received = normalizeTime(*sample.ReceivedAt)
	}
	sample.ReceivedAt = nil
	sample.Timestamp = normalizeTime(sample.Timestamp)
	encoded, err := json.Marshal(sample)
	if err != nil {
		return err
	}
	valuesJSON, err := json.Marshal(sample.Values)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var sessionID any
	var sequence any
	if sample.Session != nil {
		sessionID = sample.Session.ID
		sequence = *sample.Sequence
		metadata, err := json.Marshal(sample.Session)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO telemetry_sessions(client_id,session_id,device_id,metadata_json) VALUES(?,?,?,?) ON CONFLICT DO NOTHING`, clientID, sessionID, sample.DeviceID, string(metadata))
		if err != nil {
			return err
		}
		var device, existing string
		if err = tx.QueryRowContext(ctx, `SELECT device_id,metadata_json FROM telemetry_sessions WHERE client_id=? AND session_id=?`, clientID, sessionID).Scan(&device, &existing); err != nil {
			return err
		}
		if device != sample.DeviceID || existing != string(metadata) {
			return ErrSampleConflict
		}
		var prior string
		err = tx.QueryRowContext(ctx, `SELECT sample_json FROM samples WHERE client_id=? AND session_id=? AND sequence=?`, clientID, sessionID, sequence).Scan(&prior)
		if err == nil {
			if prior == string(encoded) {
				return ErrDuplicateSample
			}
			return ErrSampleConflict
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO samples(client_id,device_id,ts_client,ts_received,values_json,sample_json,session_id,sequence) VALUES(?,?,?,?,?,?,?,?)`, clientID, sample.DeviceID, sample.Timestamp, received, string(valuesJSON), string(encoded), sessionID, sequence)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLiteStore) RecentSamples(ctx context.Context, clientID string, limit int) ([]telemetry.Sample, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT device_id, ts_client, values_json, sample_json, ts_received FROM samples
		 WHERE client_id = ?
		 ORDER BY id DESC
		 LIMIT ?`,
		clientID, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("relay: recent samples: %w", err)
	}
	defer rows.Close()

	var samples []telemetry.Sample
	for rows.Next() {
		var (
			sample     telemetry.Sample
			valuesJSON string
			encoded    sql.NullString
			received   time.Time
		)
		if err := rows.Scan(&sample.DeviceID, &sample.Timestamp, &valuesJSON, &encoded, &received); err != nil {
			return nil, fmt.Errorf("relay: recent samples: %w", err)
		}
		if err := json.Unmarshal([]byte(valuesJSON), &sample.Values); err != nil {
			return nil, fmt.Errorf("relay: recent samples: unmarshal values: %w", err)
		}
		if encoded.Valid {
			if err := json.Unmarshal([]byte(encoded.String), &sample); err != nil {
				return nil, err
			}
		}
		sample.ReceivedAt = &received
		samples = append(samples, sample)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("relay: recent samples: %w", err)
	}

	// Query is newest-first (so LIMIT keeps the most recent rows);
	// reverse to oldest-first, the order a backfill burst should
	// replay in.
	for i, j := 0, len(samples)-1; i < j; i, j = i+1, j-1 {
		samples[i], samples[j] = samples[j], samples[i]
	}
	return samples, nil
}

func (s *SQLiteStore) PruneSamplesOlderThan(ctx context.Context, cutoff time.Time) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `DELETE FROM samples WHERE ts_received < ?`, normalizeTime(cutoff))
	if err != nil {
		return 0, err
	}
	_, err = tx.ExecContext(ctx, `DELETE FROM telemetry_sessions WHERE NOT EXISTS (SELECT 1 FROM samples WHERE samples.client_id=telemetry_sessions.client_id AND samples.session_id=telemetry_sessions.session_id)`)
	if err != nil {
		return 0, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	return count, tx.Commit()
}
