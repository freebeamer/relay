package relay

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/freebeamer/core/pkg/relayapi"
)

// pairingTokenBytes matches the entropy of the old static API keys
// (see generateAPIKey in cmd/freebeamer-relay) — this token is only
// ever live for defaultTTL and single-use, but there's no reason to
// weaken it just because its exposure window is short.
const pairingTokenBytes = 32

// pairingHandler handles POST /v1/pairing-links (admin-only): mints a
// short-lived, single-use token a device redeems via pairHandler. The
// raw token is returned exactly once — the store only ever keeps its
// hash (see hashToken) — the same convention the old client API keys
// followed.
func pairingHandler(store Store, defaultTTL time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req relayapi.PairingLinkRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "malformed request")
			return
		}
		if req.DisplayName == "" {
			writeError(w, http.StatusBadRequest, "display_name is required")
			return
		}

		raw := make([]byte, pairingTokenBytes)
		if _, err := rand.Read(raw); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to generate pairing token")
			return
		}
		token := base64.RawURLEncoding.EncodeToString(raw)

		expiresAt := time.Now().Add(defaultTTL).UTC()
		if _, err := store.CreatePairingLink(r.Context(), hashToken(token), req.DisplayName, expiresAt); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to create pairing link")
			return
		}

		resp := relayapi.PairingLinkResponse{
			PairingToken: token,
			DisplayName:  req.DisplayName,
			ExpiresAt:    expiresAt,
		}
		if req.PublicURL != "" {
			resp.DeepLink = pairingDeepLink(req.PublicURL, token, req.DisplayName)
		}
		writeJSON(w, http.StatusCreated, resp)
	}
}

// pairingDeepLink mirrors cmd/freebeamer-relay's provisioningLink and
// mobile/lib/data/models/provisioning_payload.dart's
// ProvisioningPayload.tryParse — all three must stay in sync. Unlike
// the old link, this one carries no long-lived secret: pairing_token
// is single-use and expires, and the relay_url it hands the device is
// the ingest endpoint the device will call once paired.
func pairingDeepLink(publicURL, pairingToken, displayName string) string {
	relayURL := strings.TrimSuffix(publicURL, "/") + "/v1/telemetry"
	query := url.Values{"relay_url": {relayURL}, "pairing_token": {pairingToken}, "name": {displayName}}
	link := url.URL{Scheme: "freebeamer", Host: "connect", RawQuery: query.Encode()}
	return link.String()
}

// pairHandler handles POST /v1/pair (public — this is the trust
// bootstrap, so it can't itself require a credential the device
// doesn't have yet). A device redeems a still-valid pairing link with
// the public half of an Ed25519 keypair it generated locally; the
// relay creates a Client for it and disposes of the pairing link,
// permanently — a second POST /v1/pair with the same token, whether a
// retry or another device that saw the same link, always fails.
func pairHandler(store Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req relayapi.PairRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "malformed request")
			return
		}
		if req.PairingToken == "" || req.PublicKey == "" {
			writeError(w, http.StatusBadRequest, "pairing_token and public_key are required")
			return
		}
		publicKey, err := base64.StdEncoding.DecodeString(req.PublicKey)
		if err != nil || len(publicKey) != ed25519.PublicKeySize {
			writeError(w, http.StatusBadRequest, "public_key must be a base64-encoded 32-byte Ed25519 key")
			return
		}

		client, err := store.ConsumePairingLink(r.Context(), hashToken(req.PairingToken), uuid.NewString(), publicKey)
		if err != nil {
			if errors.Is(err, ErrPairingLinkInvalid) {
				writeError(w, http.StatusGone, "pairing link is invalid, expired, or already used")
				return
			}
			writeError(w, http.StatusInternalServerError, "failed to pair device")
			return
		}
		writeJSON(w, http.StatusOK, relayapi.PairResponse{ClientID: client.ID, DisplayName: client.DisplayName})
	}
}
