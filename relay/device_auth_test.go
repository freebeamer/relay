package relay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/freebeamer/core/pkg/relayapi"
)

// authenticateViaHTTP runs the full challenge/response dance for
// clientID against a running server and returns the resulting device
// session token.
func authenticateViaHTTP(t *testing.T, serverURL, clientID string, priv ed25519.PrivateKey) string {
	t.Helper()
	challengeBody, _ := json.Marshal(relayapi.ChallengeRequest{ClientID: clientID})
	resp, err := http.Post(serverURL+"/v1/auth/challenge", "application/json", bytes.NewReader(challengeBody))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("challenge: status = %d", resp.StatusCode)
	}
	var challenge relayapi.ChallengeResponse
	if err := json.NewDecoder(resp.Body).Decode(&challenge); err != nil {
		t.Fatal(err)
	}
	nonce, err := base64.StdEncoding.DecodeString(challenge.Nonce)
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(priv, nonce)

	sessionBody, _ := json.Marshal(relayapi.SessionRequest{
		ClientID:  clientID,
		Signature: base64.StdEncoding.EncodeToString(signature),
	})
	sessResp, err := http.Post(serverURL+"/v1/auth/session", "application/json", bytes.NewReader(sessionBody))
	if err != nil {
		t.Fatal(err)
	}
	defer sessResp.Body.Close()
	if sessResp.StatusCode != http.StatusOK {
		t.Fatalf("session: status = %d", sessResp.StatusCode)
	}
	var session relayapi.SessionResponse
	if err := json.NewDecoder(sessResp.Body).Decode(&session); err != nil {
		t.Fatal(err)
	}
	if session.SessionToken == "" {
		t.Fatal("session token is empty")
	}
	return session.SessionToken
}

func pairFreshDevice(t *testing.T, serverURL, displayName string) (clientID string, priv ed25519.PrivateKey) {
	t.Helper()
	link := createPairingLinkViaHTTP(t, serverURL, testAdminToken, displayName)
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, pairResp := pairViaHTTP(t, serverURL, link.PairingToken, pub)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("pair: status = %d", resp.StatusCode)
	}
	return pairResp.ClientID, priv
}

func TestSessionRejectsWrongSignature(t *testing.T) {
	server, _ := newTestServer(t)
	clientID, _ := pairFreshDevice(t, server.URL, "Bay 3")
	_, otherPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	challengeBody, _ := json.Marshal(relayapi.ChallengeRequest{ClientID: clientID})
	resp, err := http.Post(server.URL+"/v1/auth/challenge", "application/json", bytes.NewReader(challengeBody))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var challenge relayapi.ChallengeResponse
	if err := json.NewDecoder(resp.Body).Decode(&challenge); err != nil {
		t.Fatal(err)
	}
	nonce, _ := base64.StdEncoding.DecodeString(challenge.Nonce)
	wrongSig := ed25519.Sign(otherPriv, nonce) // signed with the wrong key

	sessionBody, _ := json.Marshal(relayapi.SessionRequest{ClientID: clientID, Signature: base64.StdEncoding.EncodeToString(wrongSig)})
	sessResp, err := http.Post(server.URL+"/v1/auth/session", "application/json", bytes.NewReader(sessionBody))
	if err != nil {
		t.Fatal(err)
	}
	defer sessResp.Body.Close()
	if sessResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", sessResp.StatusCode)
	}
}

func TestChallengeIsSingleUse(t *testing.T) {
	server, _ := newTestServer(t)
	clientID, priv := pairFreshDevice(t, server.URL, "Bay 3")

	challengeBody, _ := json.Marshal(relayapi.ChallengeRequest{ClientID: clientID})
	resp, err := http.Post(server.URL+"/v1/auth/challenge", "application/json", bytes.NewReader(challengeBody))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var challenge relayapi.ChallengeResponse
	if err := json.NewDecoder(resp.Body).Decode(&challenge); err != nil {
		t.Fatal(err)
	}
	nonce, _ := base64.StdEncoding.DecodeString(challenge.Nonce)
	signature := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, nonce))

	sessionBody, _ := json.Marshal(relayapi.SessionRequest{ClientID: clientID, Signature: signature})
	first, err := http.Post(server.URL+"/v1/auth/session", "application/json", bytes.NewReader(sessionBody))
	if err != nil {
		t.Fatal(err)
	}
	first.Body.Close()
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first use: status = %d, want 200", first.StatusCode)
	}

	// Replaying the exact same (now-consumed) challenge/signature must fail.
	second, err := http.Post(server.URL+"/v1/auth/session", "application/json", bytes.NewReader(sessionBody))
	if err != nil {
		t.Fatal(err)
	}
	second.Body.Close()
	if second.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replay: status = %d, want 401", second.StatusCode)
	}
}

func TestChallengeRejectsUnknownClient(t *testing.T) {
	server, _ := newTestServer(t)

	body, _ := json.Marshal(relayapi.ChallengeRequest{ClientID: "no-such-client"})
	resp, err := http.Post(server.URL+"/v1/auth/challenge", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unknown client: status = %d, want 401", resp.StatusCode)
	}
}

// TestChallengeRejectsRevokedClient builds its own server (rather than
// using newTestServer) so the test can reach the underlying Store
// directly to revoke a client — there's no HTTP route for that today,
// only the CLI's `client revoke` (see cmd/freebeamer-relay).
func TestChallengeRejectsRevokedClient(t *testing.T) {
	store := newTestStore(t)
	client, _ := createTestClient(t, store, "client-1", "Bay 3")
	server, err := NewServer("127.0.0.1:0", Config{Store: store, AdminToken: testAdminToken})
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(server.httpServer.Handler)
	t.Cleanup(httpServer.Close)

	if err := store.RevokeClient(context.Background(), client.ID); err != nil {
		t.Fatal(err)
	}

	body, _ := json.Marshal(relayapi.ChallengeRequest{ClientID: client.ID})
	resp, err := http.Post(httpServer.URL+"/v1/auth/challenge", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked client: status = %d, want 401", resp.StatusCode)
	}
}

func TestLogoutRevokesSessionImmediately(t *testing.T) {
	server, _ := newTestServer(t)
	clientID, priv := pairFreshDevice(t, server.URL, "Bay 3")
	sessionToken := authenticateViaHTTP(t, server.URL, clientID, priv)

	logoutReq, _ := http.NewRequest(http.MethodPost, server.URL+"/v1/auth/logout", nil)
	logoutReq.Header.Set("Authorization", "Bearer "+sessionToken)
	logoutResp, err := http.DefaultClient.Do(logoutReq)
	if err != nil {
		t.Fatal(err)
	}
	logoutResp.Body.Close()
	if logoutResp.StatusCode != http.StatusNoContent {
		t.Fatalf("logout: status = %d, want 204", logoutResp.StatusCode)
	}

	sample := []byte(`{"device_id":"phone-1","timestamp":"2026-09-17T00:00:00Z","values":{"RPM":800}}`)
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/v1/telemetry", bytes.NewReader(sample))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+sessionToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("telemetry after logout: status = %d, want 401", resp.StatusCode)
	}

	// The device can still re-authenticate afterward — logout ends the
	// session, it doesn't unpair the device.
	newToken := authenticateViaHTTP(t, server.URL, clientID, priv)
	if newToken == sessionToken {
		t.Fatal("re-authentication returned the same (revoked) token")
	}
}
