package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return usageError()
	}
	switch args[0] {
	case "serve":
		return serveCommand(args[1:], stdout, stderr)
	case "client":
		return clientCommand(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return nil
	default:
		return usageError()
	}
}

const usage = `freebeamer-relay: FreeBeamer telemetry relay service

Usage:
  freebeamer-relay serve [--addr HOST:PORT] [--db PATH] [--admin-token TOKEN] [--prune-after DURATION] [--prune-interval DURATION]
  freebeamer-relay client pairing-link create --name NAME [--db PATH] [--public-url URL] [--ttl DURATION]
  freebeamer-relay client list [--db PATH]
  freebeamer-relay client revoke ID [--db PATH]

A device redeems a pairing link itself (POST /v1/pair with its own
Ed25519 public key) — there's no separate CLI step to install a key.

--admin-token defaults to $FREEBEAMER_RELAY_ADMIN_TOKEN.
`

func usageError() error {
	return errors.New(strings.TrimSpace(usage))
}
