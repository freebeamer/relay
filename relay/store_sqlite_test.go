package relay

import (
	"context"
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

func TestSQLiteStoreClientLifecycle(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	created, err := store.CreateClient(ctx, "client-1", "Test Client", "hash-1")
	if err != nil {
		t.Fatal(err)
	}
	if created.RevokedAt != nil {
		t.Fatalf("new client has RevokedAt = %v, want nil", created.RevokedAt)
	}

	found, err := store.LookupClientByKeyHash(ctx, "hash-1")
	if err != nil {
		t.Fatal(err)
	}
	if found.ID != "client-1" || found.DisplayName != "Test Client" {
		t.Fatalf("LookupClientByKeyHash = %+v", found)
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
	if _, err := store.LookupClientByKeyHash(ctx, "hash-1"); !errors.Is(err, ErrClientNotFound) {
		t.Fatalf("LookupClientByKeyHash after revoke: err = %v, want ErrClientNotFound", err)
	}
	if err := store.RevokeClient(ctx, "client-1"); !errors.Is(err, ErrClientNotFound) {
		t.Fatalf("re-revoking: err = %v, want ErrClientNotFound", err)
	}
	if err := store.RevokeClient(ctx, "no-such-client"); !errors.Is(err, ErrClientNotFound) {
		t.Fatalf("revoking unknown client: err = %v, want ErrClientNotFound", err)
	}
}

func TestSQLiteStoreLookupUnknownKey(t *testing.T) {
	store := newTestStore(t)
	if _, err := store.LookupClientByKeyHash(context.Background(), "no-such-hash"); !errors.Is(err, ErrClientNotFound) {
		t.Fatalf("err = %v, want ErrClientNotFound", err)
	}
}

func TestSQLiteStoreSamplesOldestFirst(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	if _, err := store.CreateClient(ctx, "client-1", "Test Client", "hash-1"); err != nil {
		t.Fatal(err)
	}

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
	if _, err := store.CreateClient(ctx, "client-1", "Test Client", "hash-1"); err != nil {
		t.Fatal(err)
	}
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
	if _, err := store.CreateClient(ctx, "client-1", "Test Client", "hash-1"); err != nil {
		t.Fatal(err)
	}

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
