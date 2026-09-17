package relay

import (
	"encoding/json"
	"net/http"

	"github.com/freebeamer/core/pkg/relayapi"
)

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, relayapi.ErrorResponse{Error: message})
}
