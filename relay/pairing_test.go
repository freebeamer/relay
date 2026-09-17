package relay

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/freebeamer/core/pkg/relayapi"
)

func createPairingLinkViaHTTP(t *testing.T, serverURL, adminToken, displayName string) relayapi.PairingLinkResponse {
	t.Helper()
	body, _ := json.Marshal(relayapi.PairingLinkRequest{DisplayName: displayName})
	req, _ := http.NewRequest(http.MethodPost, serverURL+"/v1/pairing-links", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create pairing link: status = %d", resp.StatusCode)
	}
	var out relayapi.PairingLinkResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

func pairViaHTTP(t *testing.T, serverURL, pairingToken string, publicKey ed25519.PublicKey) (*http.Response, relayapi.PairResponse) {
	t.Helper()
	body, _ := json.Marshal(relayapi.PairRequest{
		PairingToken: pairingToken,
		PublicKey:    base64.StdEncoding.EncodeToString(publicKey),
	})
	resp, err := http.Post(serverURL+"/v1/pair", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out relayapi.PairResponse
	if resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatal(err)
		}
	}
	return resp, out
}

func TestPairingLinkRequiresAdminToken(t *testing.T) {
	server, _ := newTestServer(t)
	body, _ := json.Marshal(relayapi.PairingLinkRequest{DisplayName: "Bay 3"})
	resp, err := http.Post(server.URL+"/v1/pairing-links", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestPairThenSessionThenTelemetry(t *testing.T) {
	server, _ := newTestServer(t)
	link := createPairingLinkViaHTTP(t, server.URL, testAdminToken, "Bay 3 - N55")
	if link.PairingToken == "" || link.DisplayName != "Bay 3 - N55" {
		t.Fatalf("link = %+v", link)
	}

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, pairResp := pairViaHTTP(t, server.URL, link.PairingToken, pub)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("pair: status = %d", resp.StatusCode)
	}
	if pairResp.ClientID == "" || pairResp.DisplayName != "Bay 3 - N55" {
		t.Fatalf("pairResp = %+v", pairResp)
	}

	// A second device redeeming the same (now-consumed) token must fail.
	otherPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	resp2, _ := pairViaHTTP(t, server.URL, link.PairingToken, otherPub)
	if resp2.StatusCode != http.StatusGone {
		t.Fatalf("re-pair with consumed token: status = %d, want 410", resp2.StatusCode)
	}

	sessionToken := authenticateViaHTTP(t, server.URL, pairResp.ClientID, priv)

	sample := `{"device_id":"phone-1","timestamp":"2026-09-17T00:00:00Z","values":{"RPM":800}}`
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/v1/telemetry", bytes.NewReader([]byte(sample)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+sessionToken)
	telResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if telResp.StatusCode != http.StatusAccepted {
		t.Fatalf("telemetry with session token: status = %d, want 202", telResp.StatusCode)
	}

	// The hard requirement: a device session token must never work on
	// the admin surface.
	adminReq, _ := http.NewRequest(http.MethodGet, server.URL+"/v1/clients", nil)
	adminReq.Header.Set("Authorization", "Bearer "+sessionToken)
	adminResp, err := http.DefaultClient.Do(adminReq)
	if err != nil {
		t.Fatal(err)
	}
	if adminResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("session token on /v1/clients: status = %d, want 401", adminResp.StatusCode)
	}

	catalogReq, _ := http.NewRequest(http.MethodGet, server.URL+"/v1/catalog", nil)
	catalogReq.Header.Set("Authorization", "Bearer "+sessionToken)
	catalogResp, err := http.DefaultClient.Do(catalogReq)
	if err != nil {
		t.Fatal(err)
	}
	if catalogResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("session token on /v1/catalog: status = %d, want 401", catalogResp.StatusCode)
	}

	linkReq, _ := http.NewRequest(http.MethodPost, server.URL+"/v1/pairing-links", bytes.NewReader(mustJSON(t, relayapi.PairingLinkRequest{DisplayName: "x"})))
	linkReq.Header.Set("Authorization", "Bearer "+sessionToken)
	linkResp, err := http.DefaultClient.Do(linkReq)
	if err != nil {
		t.Fatal(err)
	}
	if linkResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("session token on /v1/pairing-links: status = %d, want 401", linkResp.StatusCode)
	}

	// And, symmetrically, the admin token must never work on the
	// device-facing ingest endpoint.
	adminOnTelemetry, _ := http.NewRequest(http.MethodPost, server.URL+"/v1/telemetry", bytes.NewReader([]byte(sample)))
	adminOnTelemetry.Header.Set("Content-Type", "application/json")
	adminOnTelemetry.Header.Set("Authorization", "Bearer "+testAdminToken)
	adminOnTelemetryResp, err := http.DefaultClient.Do(adminOnTelemetry)
	if err != nil {
		t.Fatal(err)
	}
	if adminOnTelemetryResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("admin token on /v1/telemetry: status = %d, want 401", adminOnTelemetryResp.StatusCode)
	}
}

func TestPairRejectsExpiredOrUnknownToken(t *testing.T) {
	server, _ := newTestServer(t)
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, _ := pairViaHTTP(t, server.URL, "no-such-token", pub)
	if resp.StatusCode != http.StatusGone {
		t.Fatalf("unknown token: status = %d, want 410", resp.StatusCode)
	}
}

func TestPairRejectsMalformedPublicKey(t *testing.T) {
	server, _ := newTestServer(t)
	link := createPairingLinkViaHTTP(t, server.URL, testAdminToken, "Bay 3")
	body, _ := json.Marshal(relayapi.PairRequest{PairingToken: link.PairingToken, PublicKey: "not-base64!!"})
	resp, err := http.Post(server.URL+"/v1/pair", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestPairingLinkDeepLinkOnlyWithPublicURL(t *testing.T) {
	server, _ := newTestServer(t)

	withoutURL := createPairingLinkViaHTTP(t, server.URL, testAdminToken, "Bay 3")
	if withoutURL.DeepLink != "" {
		t.Fatalf("DeepLink = %q, want empty without public_url", withoutURL.DeepLink)
	}

	body, _ := json.Marshal(relayapi.PairingLinkRequest{DisplayName: "Bay 3", PublicURL: "https://telemetry.example.com"})
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/v1/pairing-links", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testAdminToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var withURL relayapi.PairingLinkResponse
	if err := json.NewDecoder(resp.Body).Decode(&withURL); err != nil {
		t.Fatal(err)
	}
	if withURL.DeepLink == "" {
		t.Fatal("DeepLink is empty even though public_url was given")
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
