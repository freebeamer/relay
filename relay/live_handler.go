package relay

import (
	"log"
	"net/http"
	"time"

	"github.com/gorilla/websocket"

	"github.com/freebeamer/core/pkg/relayapi"
	"github.com/freebeamer/core/pkg/telemetry"
)

const (
	// backfillLimit bounds how many recently stored samples a newly
	// connected live feed replays before switching to live push —
	// enough to catch a viewer up, not a full history dump.
	backfillLimit    = 50
	liveWriteTimeout = 10 * time.Second
	livePingInterval = 30 * time.Second
)

// upgrader has no Origin restriction: the relay is consumed by
// FreeBeamer's own desktop app over a direct WebSocket connection, not
// embedded in a browser page, so cross-origin isn't a meaningful
// concept here.
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

// liveHandler handles GET /v1/live?client_id=ID (admin-only):
// upgrades to a WebSocket, sends a short backfill burst of recently
// stored samples for client_id, then streams new samples as they're
// published to hub for it.
func liveHandler(store Store, hub *Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientID := r.URL.Query().Get("client_id")
		if clientID == "" {
			writeError(w, http.StatusBadRequest, "client_id is required")
			return
		}

		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return // Upgrade already wrote its own error response.
		}
		defer conn.Close()

		// A WebSocket connection needs something reading it to notice
		// a client-initiated close (or any read error); this
		// discards incoming messages (v0 has no subscribe/control
		// channel) purely to detect disconnection.
		closed := make(chan struct{})
		go func() {
			defer close(closed)
			for {
				if _, _, err := conn.ReadMessage(); err != nil {
					return
				}
			}
		}()

		ch, unsubscribe := hub.Subscribe(clientID)
		defer unsubscribe()

		backfill, err := store.RecentSamples(r.Context(), clientID, backfillLimit)
		if err != nil {
			log.Printf("relay: live: backfill for client %s: %v", clientID, err)
		}
		for _, sample := range backfill {
			if err := writeLiveEnvelope(conn, sample, true); err != nil {
				return
			}
		}

		ping := time.NewTicker(livePingInterval)
		defer ping.Stop()
		for {
			select {
			case <-closed:
				return
			case sample, ok := <-ch:
				if !ok {
					return
				}
				if err := writeLiveEnvelope(conn, sample, false); err != nil {
					return
				}
			case <-ping.C:
				conn.SetWriteDeadline(time.Now().Add(liveWriteTimeout))
				if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
					return
				}
			}
		}
	}
}

func writeLiveEnvelope(conn *websocket.Conn, sample telemetry.Sample, backfill bool) error {
	conn.SetWriteDeadline(time.Now().Add(liveWriteTimeout))
	return conn.WriteJSON(relayapi.LiveEnvelope{
		Version: sample.Version, Session: sample.Session, Sequence: sample.Sequence, ReceivedAt: sample.ReceivedAt,
		DeviceID:  sample.DeviceID,
		Timestamp: sample.Timestamp,
		Values:    sample.Values,
		Backfill:  backfill,
	})
}
