package relay

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/freebeamer/core/pkg/telemetry"
)

func newTestStore(t *testing.T) *SQLiteStore {
	t.Helper()
	store, err := NewSQLiteStore(filepath.Join(t.TempDir(), "relay.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

// createTestClient pairs a new client the same way a real device
// would (a pairing link, consumed with a freshly generated Ed25519
// keypair) and returns both the resulting Client and its private key,
// so a caller can go on to sign a challenge with it.
func createTestClient(t *testing.T, store *SQLiteStore, id, displayName string) (Client, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	token := id + "-pairing-token"
	ctx := context.Background()
	if _, err := store.CreatePairingLink(ctx, hashToken(token), displayName, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	client, err := store.ConsumePairingLink(ctx, hashToken(token), id, pub)
	if err != nil {
		t.Fatal(err)
	}
	return client, priv
}

func TestSQLiteStoreClientLifecycle(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	created, _ := createTestClient(t, store, "client-1", "Test Client")
	if created.RevokedAt != nil {
		t.Fatalf("new client has RevokedAt = %v, want nil", created.RevokedAt)
	}

	found, err := store.LookupClientByID(ctx, "client-1")
	if err != nil {
		t.Fatal(err)
	}
	if found.ID != "client-1" || found.DisplayName != "Test Client" {
		t.Fatalf("LookupClientByID = %+v", found)
	}

	clients, err := store.ListClients(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(clients) != 1 || clients[0].ID != "client-1" {
		t.Fatalf("ListClients = %+v", clients)
	}

	if err := store.RevokeClient(ctx, "client-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LookupClientByID(ctx, "client-1"); !errors.Is(err, ErrClientNotFound) {
		t.Fatalf("LookupClientByID after revoke: err = %v, want ErrClientNotFound", err)
	}
	if err := store.RevokeClient(ctx, "client-1"); !errors.Is(err, ErrClientNotFound) {
		t.Fatalf("re-revoking: err = %v, want ErrClientNotFound", err)
	}
	if err := store.RevokeClient(ctx, "no-such-client"); !errors.Is(err, ErrClientNotFound) {
		t.Fatalf("revoking unknown client: err = %v, want ErrClientNotFound", err)
	}
}

func TestSQLiteStoreLookupUnknownClient(t *testing.T) {
	store := newTestStore(t)
	if _, err := store.LookupClientByID(context.Background(), "no-such-id"); !errors.Is(err, ErrClientNotFound) {
		t.Fatalf("err = %v, want ErrClientNotFound", err)
	}
}

func TestSQLiteStorePairingLinkIsSingleUse(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tokenHash := hashToken("a-pairing-token")
	if _, err := store.CreatePairingLink(ctx, tokenHash, "Bay 3", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	client, err := store.ConsumePairingLink(ctx, tokenHash, "client-1", pub)
	if err != nil {
		t.Fatal(err)
	}
	if client.ID != "client-1" || client.DisplayName != "Bay 3" {
		t.Fatalf("client = %+v", client)
	}

	// A second redemption of the same token — whether a retry or a
	// different device that saw the same link — must fail.
	if _, err := store.ConsumePairingLink(ctx, tokenHash, "client-2", pub); !errors.Is(err, ErrPairingLinkInvalid) {
		t.Fatalf("second consume: err = %v, want ErrPairingLinkInvalid", err)
	}
}

func TestSQLiteStorePairingLinkExpires(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tokenHash := hashToken("expired-token")
	if _, err := store.CreatePairingLink(ctx, tokenHash, "Bay 3", time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumePairingLink(ctx, tokenHash, "client-1", pub); !errors.Is(err, ErrPairingLinkInvalid) {
		t.Fatalf("err = %v, want ErrPairingLinkInvalid", err)
	}
}

func TestSQLiteStoreConsumeUnknownPairingLink(t *testing.T) {
	store := newTestStore(t)
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumePairingLink(context.Background(), hashToken("no-such-token"), "client-1", pub); !errors.Is(err, ErrPairingLinkInvalid) {
		t.Fatalf("err = %v, want ErrPairingLinkInvalid", err)
	}
}

func TestSQLiteStoreDeviceSessionLifecycle(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	createTestClient(t, store, "client-1", "Test Client")

	tokenHash := hashToken("a-session-token")
	if _, err := store.CreateDeviceSession(ctx, tokenHash, "client-1", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	session, err := store.LookupDeviceSession(ctx, tokenHash)
	if err != nil {
		t.Fatal(err)
	}
	if session.ClientID != "client-1" {
		t.Fatalf("session = %+v", session)
	}

	if err := store.RevokeDeviceSession(ctx, tokenHash); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LookupDeviceSession(ctx, tokenHash); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("after revoke: err = %v, want ErrSessionInvalid", err)
	}
}

func TestSQLiteStoreDeviceSessionExpires(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	createTestClient(t, store, "client-1", "Test Client")

	tokenHash := hashToken("an-expired-session-token")
	if _, err := store.CreateDeviceSession(ctx, tokenHash, "client-1", time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LookupDeviceSession(ctx, tokenHash); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("err = %v, want ErrSessionInvalid", err)
	}
}

func TestSQLiteStoreRevokeClientRevokesItsSessions(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	createTestClient(t, store, "client-1", "Test Client")

	tokenHash := hashToken("a-session-token")
	if _, err := store.CreateDeviceSession(ctx, tokenHash, "client-1", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeClient(ctx, "client-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LookupDeviceSession(ctx, tokenHash); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("session after client revoke: err = %v, want ErrSessionInvalid", err)
	}
}

func TestSQLiteStoreSamplesOldestFirst(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	createTestClient(t, store, "client-1", "Test Client")

	base := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	for i, deviceID := range []string{"a", "b", "c"} {
		sample := telemetry.Sample{
			DeviceID:  deviceID,
			Timestamp: base.Add(time.Duration(i) * time.Second),
			Values:    map[string]float64{"RPM": float64(800 + i)},
		}
		if err := store.SaveSample(ctx, "client-1", sample); err != nil {
			t.Fatal(err)
		}
	}

	samples, err := store.RecentSamples(ctx, "client-1", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) != 3 {
		t.Fatalf("len(samples) = %d, want 3", len(samples))
	}
	wantOrder := []string{"a", "b", "c"}
	for i, want := range wantOrder {
		if samples[i].DeviceID != want {
			t.Fatalf("samples[%d].DeviceID = %q, want %q (order = %v)", i, samples[i].DeviceID, want, samples)
		}
	}
	if samples[2].Values["RPM"] != 802 {
		t.Fatalf("samples[2].Values[RPM] = %v, want 802", samples[2].Values["RPM"])
	}
}

func TestSQLiteStoreRecentSamplesRespectsLimit(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	createTestClient(t, store, "client-1", "Test Client")

	base := time.Now()
	for i := 0; i < 5; i++ {
		sample := telemetry.Sample{DeviceID: "a", Timestamp: base.Add(time.Duration(i) * time.Second), Values: map[string]float64{"RPM": float64(i)}}
		if err := store.SaveSample(ctx, "client-1", sample); err != nil {
			t.Fatal(err)
		}
	}
	samples, err := store.RecentSamples(ctx, "client-1", 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) != 2 {
		t.Fatalf("len(samples) = %d, want 2", len(samples))
	}
	// The most recent 2 of 5 (RPM 3, 4), oldest-first.
	if samples[0].Values["RPM"] != 3 || samples[1].Values["RPM"] != 4 {
		t.Fatalf("samples = %+v", samples)
	}
}

func TestSQLiteStorePruneSamplesOlderThan(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	createTestClient(t, store, "client-1", "Test Client")

	old := telemetry.Sample{DeviceID: "a", Timestamp: time.Now(), Values: map[string]float64{"RPM": 1}}
	if err := store.SaveSample(ctx, "client-1", old); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	cutoff := time.Now()
	time.Sleep(10 * time.Millisecond)
	recent := telemetry.Sample{DeviceID: "b", Timestamp: time.Now(), Values: map[string]float64{"RPM": 2}}
	if err := store.SaveSample(ctx, "client-1", recent); err != nil {
		t.Fatal(err)
	}

	pruned, err := store.PruneSamplesOlderThan(ctx, cutoff)
	if err != nil {
		t.Fatal(err)
	}
	if pruned != 1 {
		t.Fatalf("pruned = %d, want 1", pruned)
	}

	samples, err := store.RecentSamples(ctx, "client-1", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) != 1 || samples[0].DeviceID != "b" {
		t.Fatalf("samples after prune = %+v", samples)
	}
}
