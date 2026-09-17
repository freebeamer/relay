package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/freebeamer/relay/relay"
)

func serveCommand(args []string, stdout, stderr io.Writer) error {
	set := flag.NewFlagSet("serve", flag.ContinueOnError)
	set.SetOutput(stderr)
	addr := set.String("addr", ":8080", "address to listen on")
	dbPath := set.String("db", "freebeamer-relay.sqlite", "path to the SQLite database file")
	adminToken := set.String("admin-token", os.Getenv("FREEBEAMER_RELAY_ADMIN_TOKEN"), "admin bearer token (defaults to $FREEBEAMER_RELAY_ADMIN_TOKEN)")
	pruneAfter := set.Duration("prune-after", 30*time.Minute, "how long to retain samples before pruning")
	pruneInterval := set.Duration("prune-interval", 5*time.Minute, "how often to run the retention sweep")
	if err := set.Parse(args); err != nil {
		return err
	}
	if *adminToken == "" {
		return errors.New("serve: --admin-token or $FREEBEAMER_RELAY_ADMIN_TOKEN is required")
	}

	store, err := relay.NewSQLiteStore(*dbPath)
	if err != nil {
		return err
	}
	defer store.Close()

	server, err := relay.NewServer(*addr, relay.Config{
		Store:         store,
		AdminToken:    *adminToken,
		PruneAfter:    *pruneAfter,
		PruneInterval: *pruneInterval,
	})
	if err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	fmt.Fprintf(stdout, "freebeamer-relay: listening on %s (db=%s)\n", *addr, *dbPath)
	if err := server.Serve(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
