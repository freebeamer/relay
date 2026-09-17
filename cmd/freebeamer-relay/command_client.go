package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/google/uuid"

	"github.com/freebeamer/relay/relay"
)

func clientCommand(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: freebeamer-relay client add|list|revoke")
	}
	switch args[0] {
	case "add":
		return clientAdd(args[1:], stdout, stderr)
	case "list":
		return clientList(args[1:], stdout, stderr)
	case "revoke":
		return clientRevoke(args[1:], stdout, stderr)
	default:
		return errors.New("usage: freebeamer-relay client add|list|revoke")
	}
}

func clientAdd(args []string, stdout, stderr io.Writer) error {
	set := flag.NewFlagSet("client add", flag.ContinueOnError)
	set.SetOutput(stderr)
	name := set.String("name", "", "display name for the new client")
	dbPath := set.String("db", "freebeamer-relay.sqlite", "path to the SQLite database file")
	publicURL := set.String("public-url", "", "this relay's public base URL (e.g. https://telemetry.example.com), used to print a freebeamer://connect provisioning link")
	if err := set.Parse(args); err != nil {
		return err
	}
	if *name == "" {
		return errors.New("client add: --name is required")
	}

	store, err := relay.NewSQLiteStore(*dbPath)
	if err != nil {
		return err
	}
	defer store.Close()

	rawKey, err := generateAPIKey()
	if err != nil {
		return err
	}
	sum := sha256.Sum256([]byte(rawKey))
	keyHash := hex.EncodeToString(sum[:])

	client, err := store.CreateClient(context.Background(), uuid.NewString(), *name, keyHash)
	if err != nil {
		return err
	}

	fmt.Fprintf(stdout, "client id:    %s\n", client.ID)
	fmt.Fprintf(stdout, "display name: %s\n", client.DisplayName)
	fmt.Fprintf(stdout, "api key:      %s\n", rawKey)
	fmt.Fprintln(stdout, "\nThis key is shown once and is not recoverable — store it now.")

	if *publicURL == "" {
		fmt.Fprintln(stdout, "\nPass --public-url to also print a freebeamer://connect provisioning link/QR payload for the mobile app (see docs/freebeamer-relay-v0-plan.md).")
		return nil
	}
	link := provisioningLink(*publicURL, rawKey)
	fmt.Fprintf(stdout, "\ndeep link (share with the client — tapping or scanning it configures and connects the app):\n%s\n", link)
	return nil
}

// provisioningLink builds the freebeamer://connect deep link the
// mobile app's ProvisioningPayload.tryParse expects (see
// mobile/lib/data/models/provisioning_payload.dart — the two must
// stay in sync). publicURL is the relay's own public base URL (e.g.
// https://telemetry.example.com); the telemetry ingest path is
// appended here so the printed link is immediately usable as-is.
func provisioningLink(publicURL, apiKey string) string {
	relayURL := strings.TrimSuffix(publicURL, "/") + "/v1/telemetry"
	query := url.Values{"relay_url": {relayURL}, "api_key": {apiKey}}
	link := url.URL{Scheme: "freebeamer", Host: "connect", RawQuery: query.Encode()}
	return link.String()
}

func clientList(args []string, stdout, stderr io.Writer) error {
	set := flag.NewFlagSet("client list", flag.ContinueOnError)
	set.SetOutput(stderr)
	dbPath := set.String("db", "freebeamer-relay.sqlite", "path to the SQLite database file")
	if err := set.Parse(args); err != nil {
		return err
	}

	store, err := relay.NewSQLiteStore(*dbPath)
	if err != nil {
		return err
	}
	defer store.Close()

	clients, err := store.ListClients(context.Background())
	if err != nil {
		return err
	}
	for _, c := range clients {
		status := "active"
		if c.RevokedAt != nil {
			status = "revoked"
		}
		fmt.Fprintf(stdout, "%s\t%s\t%s\t%s\n", c.ID, c.DisplayName, status, c.CreatedAt.Format("2006-01-02T15:04:05Z07:00"))
	}
	return nil
}

func clientRevoke(args []string, stdout, stderr io.Writer) error {
	set := flag.NewFlagSet("client revoke", flag.ContinueOnError)
	set.SetOutput(stderr)
	dbPath := set.String("db", "freebeamer-relay.sqlite", "path to the SQLite database file")
	if err := set.Parse(args); err != nil {
		return err
	}
	if set.NArg() != 1 {
		return errors.New("usage: freebeamer-relay client revoke ID [--db PATH]")
	}

	store, err := relay.NewSQLiteStore(*dbPath)
	if err != nil {
		return err
	}
	defer store.Close()

	if err := store.RevokeClient(context.Background(), set.Arg(0)); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "revoked %s\n", set.Arg(0))
	return nil
}

// generateAPIKey returns a fresh, opaque, cryptographically random
// client API key. Only its hash (see hashAPIKey in internal/relay) is
// ever stored — this raw value is shown to the operator exactly once,
// at creation.
func generateAPIKey() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate api key: %w", err)
	}
	return "fh_live_" + base64.RawURLEncoding.EncodeToString(buf), nil
}
