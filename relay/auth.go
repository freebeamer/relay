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

const clientContextKey contextKey = "relay.client"

// hashAPIKey returns the stored form of a raw client API key: this
// package never stores or logs the raw key itself, only its SHA-256
// hash (hex-encoded) — the same hash cmd/freebeamer-relay's `client add`
// computes once, at issuance.
func hashAPIKey(rawKey string) string {
	sum := sha256.Sum256([]byte(rawKey))
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

// requireClientAuth resolves the request's bearer token to a Client
// via store, rejecting the request with 401 on any failure, and
// otherwise calls next with the Client attached to the request
// context (see clientFromContext).
func requireClientAuth(store Store, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := bearerToken(r)
		if token == "" {
			writeError(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		client, err := store.LookupClientByKeyHash(r.Context(), hashAPIKey(token))
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid API key")
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), clientContextKey, client)))
	}
}

func clientFromContext(ctx context.Context) (Client, bool) {
	client, ok := ctx.Value(clientContextKey).(Client)
	return client, ok
}

// requireAdminAuth rejects the request with 401 unless its bearer
// token exactly matches adminToken (constant-time compare, so a
// mismatch's timing doesn't leak how many leading bytes matched).
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
