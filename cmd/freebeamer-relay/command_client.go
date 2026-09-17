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
	"time"

	"github.com/freebeamer/relay/relay"
)

// createPairingLink generates a fresh, opaque pairing token (the same
// entropy as the old static API keys — see generateAPIKey — even
// though this one is single-use and short-lived) and stores its hash,
// mirroring relay.pairingHandler's HTTP-facing equivalent for the CLI
// path.
func createPairingLink(ctx context.Context, store *relay.SQLiteStore, displayName string, ttl time.Duration) (token string, expiresAt time.Time, err error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", time.Time{}, fmt.Errorf("generate pairing token: %w", err)
	}
	token = base64.RawURLEncoding.EncodeToString(buf)
	sum := sha256.Sum256([]byte(token))
	link, err := store.CreatePairingLink(ctx, hex.EncodeToString(sum[:]), displayName, time.Now().Add(ttl).UTC())
	if err != nil {
		return "", time.Time{}, err
	}
	return token, link.ExpiresAt, nil
}

func clientCommand(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: freebeamer-relay client pairing-link|list|revoke")
	}
	switch args[0] {
	case "pairing-link":
		return clientPairingLink(args[1:], stdout, stderr)
	case "list":
		return clientList(args[1:], stdout, stderr)
	case "revoke":
		return clientRevoke(args[1:], stdout, stderr)
	default:
		return errors.New("usage: freebeamer-relay client pairing-link|list|revoke")
	}
}

func clientPairingLink(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] != "create" {
		return errors.New("usage: freebeamer-relay client pairing-link create --name NAME [--db PATH] [--public-url URL] [--ttl DURATION]")
	}
	set := flag.NewFlagSet("client pairing-link create", flag.ContinueOnError)
	set.SetOutput(stderr)
	name := set.String("name", "", "display name for the tuning session/device")
	dbPath := set.String("db", "freebeamer-relay.sqlite", "path to the SQLite database file")
	publicURL := set.String("public-url", "", "this relay's public base URL (e.g. https://telemetry.example.com), used to print a freebeamer://connect pairing link")
	ttl := set.Duration("ttl", 15*time.Minute, "how long the pairing link stays redeemable")
	if err := set.Parse(args[1:]); err != nil {
		return err
	}
	if *name == "" {
		return errors.New("client pairing-link create: --name is required")
	}

	store, err := relay.NewSQLiteStore(*dbPath)
	if err != nil {
		return err
	}
	defer store.Close()

	token, expiresAt, err := createPairingLink(context.Background(), store, *name, *ttl)
	if err != nil {
		return err
	}

	fmt.Fprintf(stdout, "display name: %s\n", *name)
	fmt.Fprintf(stdout, "pairing token: %s\n", token)
	fmt.Fprintf(stdout, "expires at:   %s\n", expiresAt.Format(time.RFC3339))
	fmt.Fprintln(stdout, "\nThis token is shown once and is not recoverable — a device must redeem it before it expires. It's single-use: once one device pairs with it, it's disposed and can't be reused.")

	if *publicURL == "" {
		fmt.Fprintln(stdout, "\nPass --public-url to also print a freebeamer://connect pairing link/QR payload for the mobile app (see docs/freebeamer-relay-v0-plan.md).")
		return nil
	}
	link := pairingLink(*publicURL, token, *name)
	fmt.Fprintf(stdout, "\ndeep link (share with the device — tapping or scanning it pairs and connects the app):\n%s\n", link)
	return nil
}

// pairingLink builds the freebeamer://connect deep link the mobile
// app's ProvisioningPayload.tryParse expects (see
// mobile/lib/data/models/provisioning_payload.dart — the two must
// stay in sync). publicURL is the relay's own public base URL (e.g.
// https://telemetry.example.com); the telemetry ingest path is
// appended here so the printed link is immediately usable as-is.
// Unlike the old API-key link, this one carries no long-lived secret.
func pairingLink(publicURL, pairingToken, displayName string) string {
	relayURL := strings.TrimSuffix(publicURL, "/") + "/v1/telemetry"
	query := url.Values{"relay_url": {relayURL}, "pairing_token": {pairingToken}, "name": {displayName}}
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
