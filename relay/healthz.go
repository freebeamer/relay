package relay

import "net/http"

// healthzHandler handles GET /healthz: an unauthenticated liveness
// check for the reverse proxy / container orchestration in front of
// the relay.
func healthzHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}
}
