package relay

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/freebeamer/core/pkg/telemetry"
	"log"
	"net/http"
	"time"
)

// errAdminTokenRequired guards against booting the relay with admin
// endpoints unintentionally open — NewServer fails closed rather than
// silently accepting an empty admin token.
var errAdminTokenRequired = errors.New("relay: admin token is required")

// Config configures a Server.
type Config struct {
	Store      Store
	AdminToken string
	// PruneAfter is how long a sample is retained before the
	// background sweep deletes it; defaults to 30 minutes if zero.
	// This is a short rolling buffer for live-feed reconnect/backfill,
	// not durable telemetry storage.
	PruneAfter time.Duration
	// PruneInterval is how often the sweep runs; defaults to 5
	// minutes if zero.
	PruneInterval time.Duration
}

// Server is the relay's HTTP server: routes, auth, the live-feed hub
// tying ingest to delivery, and a background retention sweep.
type Server struct {
	httpServer *http.Server
	store      Store
	pruneAfter time.Duration
	pruneEvery time.Duration
}

// NewServer builds a Server listening on addr. Call Serve to run it.
func NewServer(addr string, cfg Config) (*Server, error) {
	if cfg.AdminToken == "" {
		return nil, errAdminTokenRequired
	}
	pruneAfter := cfg.PruneAfter
	if pruneAfter == 0 {
		pruneAfter = 30 * time.Minute
	}
	pruneEvery := cfg.PruneInterval
	if pruneEvery == 0 {
		pruneEvery = 5 * time.Minute
	}

	hub := NewHub()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/telemetry", telemetryHandler(cfg.Store, hub))
	mux.HandleFunc("GET /v1/capabilities", requireClientAuth(cfg.Store, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(telemetry.RelayCapabilities())
	}))
	mux.HandleFunc("GET /v1/live", requireAdminAuth(cfg.AdminToken, liveHandler(cfg.Store, hub)))
	mux.HandleFunc("GET /v1/clients", requireAdminAuth(cfg.AdminToken, clientsHandler(cfg.Store)))
	mux.HandleFunc("GET /healthz", healthzHandler())
	mux.HandleFunc("GET /v1/catalog", requireAdminAuth(cfg.AdminToken, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(telemetry.MonitorCatalog())
	}))

	return &Server{
		httpServer: &http.Server{Addr: addr, Handler: mux},
		store:      cfg.Store,
		pruneAfter: pruneAfter,
		pruneEvery: pruneEvery,
	}, nil
}

// Handler returns the Server's routed HTTP handler, for embedding in an
// httptest.Server (e.g. a fault-injecting wrapper) instead of binding a
// real listener via Serve.
func (s *Server) Handler() http.Handler { return s.httpServer.Handler }

// Serve runs the HTTP server and the background pruning loop until
// ctx is cancelled, then shuts the HTTP server down gracefully.
func (s *Server) Serve(ctx context.Context) error {
	go s.pruneLoop(ctx)

	errCh := make(chan error, 1)
	go func() { errCh <- s.httpServer.ListenAndServe() }()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.httpServer.Shutdown(shutdownCtx)
	}
}

func (s *Server) pruneLoop(ctx context.Context) {
	ticker := time.NewTicker(s.pruneEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cutoff := time.Now().Add(-s.pruneAfter)
			if _, err := s.store.PruneSamplesOlderThan(ctx, cutoff); err != nil {
				log.Printf("relay: prune: %v", err)
			}
		}
	}
}
