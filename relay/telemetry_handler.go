package relay

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/freebeamer/core/pkg/telemetry"
)

// maxTelemetryBodyBytes caps a single POST /v1/telemetry body — a
// generous multiple of a real encoded telemetry.Sample (a few hundred
// bytes for pkg/mhd's 19 fields), purely as a sanity guard against a
// malformed or hostile request, not a real capacity limit.
const maxTelemetryBodyBytes = 64 * 1024

// telemetryHandler handles POST /v1/telemetry: ingest one
// telemetry.Sample from an authenticated client device, persist it,
// and fan it out to any live subscribers for that client.
func telemetryHandler(store Store, hub *Hub) http.HandlerFunc {
	return requireDeviceSession(store, func(w http.ResponseWriter, r *http.Request) {
		client, _ := clientFromContext(r.Context())

		r.Body = http.MaxBytesReader(w, r.Body, maxTelemetryBodyBytes)
		var sample telemetry.Sample
		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&sample); err != nil {
			writeError(w, http.StatusBadRequest, "malformed sample: "+err.Error())
			return
		}

		if err := decoder.Decode(new(any)); err != io.EOF {
			writeError(w, http.StatusBadRequest, "expected one JSON sample")
			return
		}
		if err := sample.Validate(); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		now := time.Now().UTC()
		sample.ReceivedAt = &now
		if err := store.SaveSample(r.Context(), client.ID, sample); err != nil {
			if errors.Is(err, ErrDuplicateSample) {
				w.WriteHeader(http.StatusAccepted)
				return
			}
			if errors.Is(err, ErrSampleConflict) {
				writeError(w, http.StatusConflict, err.Error())
				return
			}
			writeError(w, http.StatusInternalServerError, "failed to store sample")
			return
		}
		hub.Publish(client.ID, sample)
		w.WriteHeader(http.StatusAccepted)
	})
}
