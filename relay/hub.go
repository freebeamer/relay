package relay

import (
	"sync"

	"github.com/freebeamer/core/pkg/telemetry"
)

// Hub fans out newly ingested samples to whichever GET /v1/live
// WebSocket connections are currently subscribed to a given client_id.
// It holds no persistence of its own — Store is where samples actually
// live; Hub only exists to push new arrivals to live viewers without
// them polling.
type Hub struct {
	mu   sync.Mutex
	subs map[string]map[chan telemetry.Sample]struct{}
}

func NewHub() *Hub {
	return &Hub{subs: make(map[string]map[chan telemetry.Sample]struct{})}
}

// Subscribe registers a new listener for clientID's samples. Call
// unsubscribe when done (typically via defer) to release it; it's
// safe to call more than once.
func (h *Hub) Subscribe(clientID string) (ch <-chan telemetry.Sample, unsubscribe func()) {
	c := make(chan telemetry.Sample, 16)

	h.mu.Lock()
	if h.subs[clientID] == nil {
		h.subs[clientID] = make(map[chan telemetry.Sample]struct{})
	}
	h.subs[clientID][c] = struct{}{}
	h.mu.Unlock()

	var once sync.Once
	unsubscribe = func() {
		once.Do(func() {
			h.mu.Lock()
			delete(h.subs[clientID], c)
			if len(h.subs[clientID]) == 0 {
				delete(h.subs, clientID)
			}
			h.mu.Unlock()
			close(c)
		})
	}
	return c, unsubscribe
}

// Publish delivers sample to every current subscriber of clientID. A
// subscriber that isn't draining its channel is skipped rather than
// blocked on — this runs on the ingest path (telemetryHandler), and a
// live feed that's fallen behind should just reconnect (which
// triggers a fresh backfill) rather than slow down ingest for every
// other client.
func (h *Hub) Publish(clientID string, sample telemetry.Sample) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for c := range h.subs[clientID] {
		select {
		case c <- sample:
		default:
		}
	}
}
