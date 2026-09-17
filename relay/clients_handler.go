package relay

import (
	"net/http"

	"github.com/freebeamer/core/pkg/relayapi"
)

// clientsHandler handles GET /v1/clients (admin-only): lists active
// (non-revoked) clients for the desktop app's feed picker.
func clientsHandler(store Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clients, err := store.ListClients(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to list clients")
			return
		}
		summaries := make([]relayapi.ClientSummary, 0, len(clients))
		for _, c := range clients {
			if c.RevokedAt != nil {
				continue
			}
			summaries = append(summaries, relayapi.ClientSummary{
				ID:          c.ID,
				DisplayName: c.DisplayName,
				CreatedAt:   c.CreatedAt,
			})
		}
		writeJSON(w, http.StatusOK, summaries)
	}
}
