package relay

import (
	"context"
	"errors"
	"time"

	"github.com/freebeamer/core/pkg/telemetry"
)

// ErrClientNotFound is returned by Store lookups when no client
// matches (an unknown or revoked client ID).
var ErrClientNotFound = errors.New("relay: client not found")

var ErrDuplicateSample = errors.New("relay: duplicate sample")
var ErrSampleConflict = errors.New("relay: sample/session identity conflict")

// ErrPairingLinkInvalid is returned when a pairing token doesn't match
// any link, or matches one that's expired or already been consumed —
// deliberately one error for all three cases, so the endpoint can't be
// used to distinguish "wrong token" from "someone already used it".
var ErrPairingLinkInvalid = errors.New("relay: pairing link invalid, expired, or already used")

// ErrSessionInvalid is returned when a device session token doesn't
// match any session, or matches one that's expired or revoked.
var ErrSessionInvalid = errors.New("relay: session token invalid, expired, or revoked")

// Client is one paired device: the owner of an Ed25519 keypair it
// generated locally, used to attribute uploaded telemetry.Sample
// values to it and to authorize short-lived sessions (see
// requireDeviceSession in auth.go). PublicKey is nil for a client
// created before pairing existed (the old static-API-key model) —
// such a client can never pass challenge verification and must be
// re-paired.
type Client struct {
	ID          string
	DisplayName string
	PublicKey   []byte // raw Ed25519 public key, 32 bytes
	CreatedAt   time.Time
	RevokedAt   *time.Time
}

// PairingLink is a short-lived, single-use token an admin mints (see
// pairingHandler) for one device to redeem via pairHandler. Only its
// hash is ever stored — the raw token is shown to the admin once, at
// creation, the same convention Client API keys used to follow.
type PairingLink struct {
	TokenHash   string
	DisplayName string
	CreatedAt   time.Time
	ExpiresAt   time.Time
	ConsumedAt  *time.Time
	ClientID    *string
}

// DeviceSession is a short-lived bearer token issued after a device
// proves possession of its paired private key (see sessionHandler). It
// authorizes device-facing endpoints only — never the admin surface.
type DeviceSession struct {
	TokenHash string
	ClientID  string
	IssuedAt  time.Time
	ExpiresAt time.Time
	RevokedAt *time.Time
}

// Store is everything the relay needs to persist. It's an interface
// specifically so a later store_postgres.go (if retention/analytics
// needs grow past this package's v0 rolling-buffer scope) is a new
// implementation, not a rewrite of the handlers that use it.
type Store interface {
	ListClients(ctx context.Context) ([]Client, error)
	// RevokeClient marks a client revoked and immediately revokes every
	// device session it currently holds, so kicking a device (a lost
	// phone, a shop ending a session) takes effect at once rather than
	// only blocking its next re-authentication.
	RevokeClient(ctx context.Context, id string) error
	LookupClientByID(ctx context.Context, id string) (Client, error)

	// CreatePairingLink stores a new pairing link, keyed by the SHA-256
	// hash of its raw token.
	CreatePairingLink(ctx context.Context, tokenHash, displayName string, expiresAt time.Time) (PairingLink, error)
	// ConsumePairingLink atomically validates tokenHash (exists,
	// unexpired, unconsumed), creates a new Client with newClientID and
	// publicKey, and marks the link consumed — all as one transaction,
	// so a second redemption of the same token always loses the race
	// and gets ErrPairingLinkInvalid.
	ConsumePairingLink(ctx context.Context, tokenHash, newClientID string, publicKey []byte) (Client, error)

	// CreateDeviceSession stores a new session, keyed by the SHA-256
	// hash of its raw token.
	CreateDeviceSession(ctx context.Context, tokenHash, clientID string, expiresAt time.Time) (DeviceSession, error)
	// LookupDeviceSession returns ErrSessionInvalid if tokenHash doesn't
	// match any session, or matches one that's expired or revoked.
	LookupDeviceSession(ctx context.Context, tokenHash string) (DeviceSession, error)
	RevokeDeviceSession(ctx context.Context, tokenHash string) error

	SaveSample(ctx context.Context, clientID string, sample telemetry.Sample) error
	// RecentSamples returns up to limit of the most recently received
	// samples for clientID, oldest first (the order a live feed's
	// backfill burst should replay them in).
	RecentSamples(ctx context.Context, clientID string, limit int) ([]telemetry.Sample, error)
	// PruneSamplesOlderThan deletes every sample received before
	// cutoff, across all clients, and reports how many were removed.
	PruneSamplesOlderThan(ctx context.Context, cutoff time.Time) (int64, error)

	Close() error
}
