package relay

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"strings"
)

type contextKey string

const (
	clientContextKey  contextKey = "relay.client"
	sessionContextKey contextKey = "relay.session"
)

// hashToken returns the stored form of any raw opaque token this
// package issues (a pairing token or a device session token): it never
// stores or logs the raw value itself, only its SHA-256 hash
// (hex-encoded).
func hashToken(rawToken string) string {
	sum := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(sum[:])
}

// bearerToken extracts the token from a standard "Authorization:
// Bearer <token>" header, or "" if the header is missing/malformed.
func bearerToken(r *http.Request) string {
	header := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return ""
	}
	return strings.TrimPrefix(header, prefix)
}

// requireDeviceSession resolves the request's bearer token to a
// DeviceSession (and its owning Client) via store, rejecting the
// request with 401 on any failure, and otherwise calls next with both
// attached to the request context. This is the device-facing auth
// tier — issued by sessionHandler after a signed challenge — and is
// deliberately never accepted on the admin surface (see
// requireAdminAuth); the two tokens are unrelated secrets.
func requireDeviceSession(store Store, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := bearerToken(r)
		if token == "" {
			writeError(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		session, err := store.LookupDeviceSession(r.Context(), hashToken(token))
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid or expired session token")
			return
		}
		client, err := store.LookupClientByID(r.Context(), session.ClientID)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid or expired session token")
			return
		}
		ctx := context.WithValue(r.Context(), clientContextKey, client)
		ctx = context.WithValue(ctx, sessionContextKey, session)
		next(w, r.WithContext(ctx))
	}
}

func clientFromContext(ctx context.Context) (Client, bool) {
	client, ok := ctx.Value(clientContextKey).(Client)
	return client, ok
}

func sessionFromContext(ctx context.Context) (DeviceSession, bool) {
	session, ok := ctx.Value(sessionContextKey).(DeviceSession)
	return session, ok
}

// requireAdminAuth rejects the request with 401 unless its bearer
// token exactly matches adminToken (constant-time compare, so a
// mismatch's timing doesn't leak how many leading bytes matched). This
// is the operator-facing auth tier (desktop app, pairing-link
// creation) — a device session token never satisfies it.
func requireAdminAuth(adminToken string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := bearerToken(r)
		if token == "" || subtle.ConstantTimeCompare([]byte(token), []byte(adminToken)) != 1 {
			writeError(w, http.StatusUnauthorized, "invalid admin token")
			return
		}
		next(w, r)
	}
}
