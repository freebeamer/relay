package relay

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/freebeamer/core/pkg/relayapi"
	"github.com/freebeamer/core/pkg/telemetry"
	"github.com/gorilla/websocket"
)

func contractSample(t *testing.T) telemetry.Sample {
	t.Helper()
	data, err := os.ReadFile("../testdata/public/telemetry/v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var sample telemetry.Sample
	if err = json.Unmarshal(data, &sample); err != nil {
		t.Fatal(err)
	}
	return sample
}

func TestSessionStorageIdentityAndClockSkew(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	sample := contractSample(t)
	if err := store.SaveSample(ctx, "client-1", sample); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveSample(ctx, "client-1", sample); !errors.Is(err, ErrDuplicateSample) {
		t.Fatalf("retry: %v", err)
	}
	sample.Values["RPM"] = 900
	if err := store.SaveSample(ctx, "client-1", sample); !errors.Is(err, ErrSampleConflict) {
		t.Fatalf("conflict: %v", err)
	}
	sample = contractSample(t)
	seq := uint64(1)
	sample.Sequence = &seq
	sample.DeviceID = "different-device"
	if err := store.SaveSample(ctx, "client-1", sample); !errors.Is(err, ErrSampleConflict) {
		t.Fatalf("device conflict: %v", err)
	}
	sample = contractSample(t)
	sample.Sequence = &seq
	sample.Timestamp = sample.Timestamp.Add(-time.Hour)
	if err := store.SaveSample(ctx, "client-1", sample); err != nil {
		t.Fatal(err)
	}
	rows, err := store.RecentSamples(ctx, "client-1", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || *rows[0].Sequence != 0 || *rows[1].Sequence != 1 || rows[0].ReceivedAt == nil {
		t.Fatalf("rows: %+v", rows)
	}
	if !rows[1].Timestamp.Before(rows[0].Timestamp) {
		t.Fatal("acquisition clock was altered")
	}
	if err := store.SaveSample(ctx, "client-2", sample); err != nil {
		t.Fatal("identity leaked across clients", err)
	}
	sample.Session.ID = "new-session"
	seq = 0
	if err := store.SaveSample(ctx, "client-1", sample); err != nil {
		t.Fatal("session restart", err)
	}
}

func TestLegacyDatabaseMigratesAndReopens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(initSchema); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err = db.Exec(`INSERT INTO samples(client_id,device_id,ts_client,ts_received,values_json) VALUES(?,?,?,?,?)`, "client-1", "legacy", now, now, `{"RPM":800}`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	for range 2 {
		store, err := NewSQLiteStore(path)
		if err != nil {
			t.Fatal(err)
		}
		rows, err := store.RecentSamples(context.Background(), "client-1", 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 || rows[0].Session != nil || rows[0].Sequence != nil || rows[0].Version != 0 || rows[0].Values["RPM"] != 800 {
			t.Fatalf("migration invented/changed data: %+v", rows)
		}
		store.Close()
	}
}

func TestV2FeedRetainsIdentityAndSuppressesDuplicate(t *testing.T) {
	server, key := newTestServer(t)
	sample := contractSample(t)
	// A caller cannot forge receipt time.
	forged := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	sample.ReceivedAt = &forged
	for range 2 {
		resp := postTelemetry(t, server.URL, key, sample)
		resp.Body.Close()
		if resp.StatusCode != 202 {
			t.Fatal(resp.Status)
		}
	}
	url := "ws" + strings.TrimPrefix(server.URL, "http") + "/v1/live?client_id=client-1"
	conn, _, err := websocket.DefaultDialer.Dial(url, http.Header{"Authorization": []string{"Bearer " + testAdminToken}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var backfill relayapi.LiveEnvelope
	if err = conn.ReadJSON(&backfill); err != nil {
		t.Fatal(err)
	}
	if !backfill.Backfill || backfill.Version != 2 || backfill.Session.ID != sample.Session.ID || *backfill.Sequence != 0 || backfill.ReceivedAt == nil || backfill.ReceivedAt.Year() == 2000 {
		t.Fatalf("backfill: %+v", backfill)
	}
	// Retry while connected, followed by the next sample. The next received
	// envelope must be sequence 1, proving neither duplicate was published.
	resp := postTelemetry(t, server.URL, key, sample)
	resp.Body.Close()
	seq := uint64(1)
	sample.Sequence = &seq
	resp = postTelemetry(t, server.URL, key, sample)
	resp.Body.Close()
	if resp.StatusCode != 202 {
		t.Fatal(resp.Status)
	}
	var live relayapi.LiveEnvelope
	if err = conn.ReadJSON(&live); err != nil {
		t.Fatal(err)
	}
	if live.Backfill || *live.Sequence != 1 || live.Session.ID != sample.Session.ID {
		t.Fatalf("live: %+v", live)
	}
	sample.Values["RPM"] = 1200
	resp = postTelemetry(t, server.URL, key, sample)
	resp.Body.Close()
	if resp.StatusCode != 409 {
		t.Fatalf("conflict status: %s", resp.Status)
	}
	sample.Version = 99
	resp = postTelemetry(t, server.URL, key, sample)
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("version status: %s", resp.Status)
	}
}

func TestCatalogRequiresAdminAndExposesProvenance(t *testing.T) {
	server, _ := newTestServer(t)
	resp, err := http.Get(server.URL + "/v1/catalog")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatal(resp.Status)
	}
	req, _ := http.NewRequest(http.MethodGet, server.URL+"/v1/catalog", nil)
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var catalog telemetry.Catalog
	if err = json.NewDecoder(resp.Body).Decode(&catalog); err != nil {
		t.Fatal(err)
	}
	if catalog.ID != telemetry.MG1CatalogID || len(catalog.Channels) != 19 || catalog.Channels[0].SourceUnit != "l/min" {
		t.Fatalf("catalog: %+v", catalog)
	}
}

func TestProducerCapabilitiesUseClientAuthentication(t *testing.T) {
	server, key := newTestServer(t)
	resp, err := http.Get(server.URL + "/v1/capabilities")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatal(resp.Status)
	}
	uploader := telemetry.Uploader{Endpoint: server.URL + "/v1/telemetry", APIKey: key}
	version, err := uploader.Negotiate()
	if err != nil || version != 2 {
		t.Fatalf("negotiate: %d %v", version, err)
	}
}
