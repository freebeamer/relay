package relay

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/freebeamer/core/pkg/relayapi"
)

const (
	challengeNonceBytes = 32
	sessionTokenBytes   = 32
)

// challenge is one outstanding "prove you hold the private key" nonce
// for a client, issued by challengeHandler and consumed by
// sessionHandler.
type challenge struct {
	nonce     []byte
	expiresAt time.Time
}

// challengeStore holds outstanding auth challenges in memory rather
// than in SQLite: they're seconds-scale and single-process, the same
// tradeoff Hub (hub.go) already makes for live-feed subscriptions. A
// relay restart just means an outstanding challenge must be
// re-requested — cheap, and not worth schema churn to avoid.
type challengeStore struct {
	mu       sync.Mutex
	byClient map[string]challenge
}

func newChallengeStore() *challengeStore {
	return &challengeStore{byClient: make(map[string]challenge)}
}

// issue replaces any outstanding challenge for clientID with a fresh
// one — only the most recently issued challenge is ever valid, so a
// device that requests a new one abandons the last.
func (c *challengeStore) issue(clientID string, ttl time.Duration) (nonce []byte, expiresAt time.Time, err error) {
	nonce = make([]byte, challengeNonceBytes)
	if _, err = rand.Read(nonce); err != nil {
		return nil, time.Time{}, err
	}
	expiresAt = time.Now().Add(ttl)
	c.mu.Lock()
	c.byClient[clientID] = challenge{nonce: nonce, expiresAt: expiresAt}
	c.mu.Unlock()
	return nonce, expiresAt, nil
}

// verify checks sig against pub over clientID's outstanding challenge,
// consuming it either way (single-use, whether it succeeds or fails)
// so a signature can never be replayed against the same nonce twice.
func (c *challengeStore) verify(clientID string, sig []byte, pub ed25519.PublicKey) bool {
	c.mu.Lock()
	ch, ok := c.byClient[clientID]
	delete(c.byClient, clientID)
	c.mu.Unlock()

	if !ok || time.Now().After(ch.expiresAt) || len(pub) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(pub, ch.nonce, sig)
}

// challengeHandler handles POST /v1/auth/challenge (public): the first
// half of a paired device's re-authentication. Returns the same 401 a
// missing client would for an already-revoked one, so the endpoint
// can't be used to probe which client IDs exist.
func challengeHandler(store Store, challenges *challengeStore, ttl time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req relayapi.ChallengeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "malformed request")
			return
		}
		if req.ClientID == "" {
			writeError(w, http.StatusBadRequest, "client_id is required")
			return
		}
		if _, err := store.LookupClientByID(r.Context(), req.ClientID); err != nil {
			writeError(w, http.StatusUnauthorized, "unknown or revoked client")
			return
		}
		nonce, expiresAt, err := challenges.issue(req.ClientID, ttl)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to issue challenge")
			return
		}
		writeJSON(w, http.StatusOK, relayapi.ChallengeResponse{
			Nonce:     base64.StdEncoding.EncodeToString(nonce),
			ExpiresAt: expiresAt,
		})
	}
}

// sessionHandler handles POST /v1/auth/session (public): the second
// half. A valid signature over the outstanding challenge mints a
// short-lived session token scoped to device-facing endpoints only
// (see requireDeviceSession) — this is the only place that token is
// ever handed out.
func sessionHandler(store Store, challenges *challengeStore, sessionTTL time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req relayapi.SessionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "malformed request")
			return
		}
		if req.ClientID == "" || req.Signature == "" {
			writeError(w, http.StatusBadRequest, "client_id and signature are required")
			return
		}
		client, err := store.LookupClientByID(r.Context(), req.ClientID)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid signature")
			return
		}
		signature, err := base64.StdEncoding.DecodeString(req.Signature)
		if err != nil || !challenges.verify(req.ClientID, signature, ed25519.PublicKey(client.PublicKey)) {
			writeError(w, http.StatusUnauthorized, "invalid signature")
			return
		}

		raw := make([]byte, sessionTokenBytes)
		if _, err := rand.Read(raw); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to create session")
			return
		}
		token := base64.RawURLEncoding.EncodeToString(raw)
		expiresAt := time.Now().Add(sessionTTL).UTC()
		if _, err := store.CreateDeviceSession(r.Context(), hashToken(token), client.ID, expiresAt); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to create session")
			return
		}
		writeJSON(w, http.StatusOK, relayapi.SessionResponse{SessionToken: token, ExpiresAt: expiresAt})
	}
}

// logoutHandler handles POST /v1/auth/logout (device session auth):
// revokes the presented session token immediately, so it can't be
// reused even if it leaked. The device is expected to keep its paired
// keypair and simply request a new session (challenge → sign → session)
// next time it reconnects — logout only ends the current session, it
// doesn't unpair the device.
func logoutHandler(store Store) http.HandlerFunc {
	return requireDeviceSession(store, func(w http.ResponseWriter, r *http.Request) {
		session, ok := sessionFromContext(r.Context())
		if !ok {
			writeError(w, http.StatusUnauthorized, "missing session")
			return
		}
		if err := store.RevokeDeviceSession(r.Context(), session.TokenHash); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to revoke session")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
