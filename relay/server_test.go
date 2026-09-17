package relay

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/freebeamer/core/pkg/relayapi"
	"github.com/freebeamer/core/pkg/telemetry"
)

const testAdminToken = "test-admin-token"

// newTestServer builds a full Server (real SQLite store, temp file)
// wrapped in an httptest.Server, and pre-registers one client with a
// known raw API key. Returns the httptest server and the raw key.
func newTestServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	store, err := NewSQLiteStore(filepath.Join(t.TempDir(), "relay.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	const rawKey = "test-raw-api-key"
	sum := sha256.Sum256([]byte(rawKey))
	if _, err := store.CreateClient(context.Background(), "client-1", "Test Client", hex.EncodeToString(sum[:])); err != nil {
		t.Fatal(err)
	}

	server, err := NewServer("127.0.0.1:0", Config{Store: store, AdminToken: testAdminToken})
	if err != nil {
		t.Fatal(err)
	}
	httpTestServer := httptest.NewServer(server.httpServer.Handler)
	t.Cleanup(httpTestServer.Close)
	return httpTestServer, rawKey
}

func TestNewServerRequiresAdminToken(t *testing.T) {
	store, err := NewSQLiteStore(filepath.Join(t.TempDir(), "relay.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := NewServer("127.0.0.1:0", Config{Store: store}); err == nil {
		t.Fatal("expected an error for a missing admin token")
	}
}

func TestHealthz(t *testing.T) {
	server, _ := newTestServer(t)
	resp, err := http.Get(server.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

func postTelemetry(t *testing.T, serverURL, bearer string, sample telemetry.Sample) *http.Response {
	t.Helper()
	body, err := json.Marshal(sample)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, serverURL+"/v1/telemetry", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestTelemetryIngestRequiresValidAPIKey(t *testing.T) {
	server, rawKey := newTestServer(t)
	sample := telemetry.Sample{DeviceID: "phone-1", Timestamp: time.Now(), Values: map[string]float64{"RPM": 800}}

	if resp := postTelemetry(t, server.URL, "", sample); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no token: status = %d, want 401", resp.StatusCode)
	}
	if resp := postTelemetry(t, server.URL, "wrong-key", sample); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong token: status = %d, want 401", resp.StatusCode)
	}
	resp := postTelemetry(t, server.URL, rawKey, sample)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("valid token: status = %d, want 202", resp.StatusCode)
	}
}

func TestTelemetryIngestRejectsMalformedBody(t *testing.T) {
	server, rawKey := newTestServer(t)
	req, err := http.NewRequest(http.MethodPost, server.URL+"/v1/telemetry", strings.NewReader("not json"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+rawKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestClientsEndpointRequiresAdminToken(t *testing.T) {
	server, _ := newTestServer(t)

	req, _ := http.NewRequest(http.MethodGet, server.URL+"/v1/clients", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no token: status = %d, want 401", resp.StatusCode)
	}

	req, _ = http.NewRequest(http.MethodGet, server.URL+"/v1/clients", nil)
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin token: status = %d, want 200", resp.StatusCode)
	}
	var clients []relayapi.ClientSummary
	if err := json.NewDecoder(resp.Body).Decode(&clients); err != nil {
		t.Fatal(err)
	}
	if len(clients) != 1 || clients[0].ID != "client-1" {
		t.Fatalf("clients = %+v", clients)
	}
}

func TestLiveFeedBackfillThenLive(t *testing.T) {
	server, rawKey := newTestServer(t)

	// One sample uploaded before the live feed connects: should
	// arrive as a backfill=true message.
	backfillSample := telemetry.Sample{DeviceID: "phone-1", Timestamp: time.Now(), Values: map[string]float64{"RPM": 800}}
	if resp := postTelemetry(t, server.URL, rawKey, backfillSample); resp.StatusCode != http.StatusAccepted {
		t.Fatalf("seed sample: status = %d", resp.StatusCode)
	}

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/v1/live?client_id=client-1"
	header := http.Header{"Authorization": []string{"Bearer " + testAdminToken}}
	conn, resp, err := websocket.DefaultDialer.Dial(wsURL, header)
	if err != nil {
		t.Fatalf("dial: %v (status %v)", err, resp)
	}
	defer conn.Close()

	var backfillMsg relayapi.LiveEnvelope
	if err := conn.ReadJSON(&backfillMsg); err != nil {
		t.Fatal(err)
	}
	if !backfillMsg.Backfill || backfillMsg.DeviceID != "phone-1" {
		t.Fatalf("backfill message = %+v", backfillMsg)
	}

	// A sample uploaded after connecting should arrive live
	// (backfill=false).
	liveSample := telemetry.Sample{DeviceID: "phone-2", Timestamp: time.Now(), Values: map[string]float64{"RPM": 1200}}
	if resp := postTelemetry(t, server.URL, rawKey, liveSample); resp.StatusCode != http.StatusAccepted {
		t.Fatalf("live sample: status = %d", resp.StatusCode)
	}

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var liveMsg relayapi.LiveEnvelope
	if err := conn.ReadJSON(&liveMsg); err != nil {
		t.Fatal(err)
	}
	if liveMsg.Backfill || liveMsg.DeviceID != "phone-2" || liveMsg.Values["RPM"] != 1200 {
		t.Fatalf("live message = %+v", liveMsg)
	}
}

func TestLiveFeedRequiresAdminToken(t *testing.T) {
	server, _ := newTestServer(t)
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/v1/live?client_id=client-1"
	_, resp, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err == nil {
		t.Fatal("expected the WebSocket handshake to fail without an admin token")
	}
	if resp == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("resp = %+v", resp)
	}
}

func TestLiveFeedRequiresClientID(t *testing.T) {
	server, _ := newTestServer(t)
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/v1/live"
	header := http.Header{"Authorization": []string{"Bearer " + testAdminToken}}
	_, resp, err := websocket.DefaultDialer.Dial(wsURL, header)
	if err == nil {
		t.Fatal("expected the WebSocket handshake to fail without client_id")
	}
	if resp == nil || resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("resp = %+v", resp)
	}
}
