package relay

import (
	"context"
	"errors"
	"time"

	"github.com/freebeamer/core/pkg/telemetry"
)

// ErrClientNotFound is returned by Store lookups when no client
// matches (an unknown ID, or an API key hash that isn't registered).
var ErrClientNotFound = errors.New("relay: client not found")

var ErrDuplicateSample = errors.New("relay: duplicate sample")
var ErrSampleConflict = errors.New("relay: sample/session identity conflict")

// Client is one onboarded FreeBeamer customer: the owner of an API key
// used to attribute uploaded telemetry.Sample values to them.
type Client struct {
	ID          string
	DisplayName string
	APIKeyHash  string
	CreatedAt   time.Time
	RevokedAt   *time.Time
}

// Store is everything the relay needs to persist. It's an interface
// specifically so a later store_postgres.go (if retention/analytics
// needs grow past this package's v0 rolling-buffer scope) is a new
// implementation, not a rewrite of the handlers that use it.
type Store interface {
	CreateClient(ctx context.Context, id, displayName, apiKeyHash string) (Client, error)
	ListClients(ctx context.Context) ([]Client, error)
	RevokeClient(ctx context.Context, id string) error
	// LookupClientByKeyHash returns ErrClientNotFound if apiKeyHash
	// doesn't match any client, or matches one that's been revoked.
	LookupClientByKeyHash(ctx context.Context, apiKeyHash string) (Client, error)

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
