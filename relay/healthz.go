package relay

import (
	"encoding/json"
	"net/http"
)

// healthzHandler handles GET /healthz: an unauthenticated liveness
// check for the reverse proxy / container orchestration in front of
// the relay.
func healthzHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "ok",
			"service": "freebeamer-relay",
		})
	}
}
