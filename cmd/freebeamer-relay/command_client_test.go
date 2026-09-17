package main

import (
	"net/url"
	"testing"
)

func TestPairingLink(t *testing.T) {
	link := pairingLink("https://telemetry.pact.net", "tok_abc123", "Bay 3 - N55")

	parsed, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	// mobile/lib/data/models/provisioning_payload.dart's tryParse
	// requires exactly this shape: scheme "freebeamer", host "connect".
	if parsed.Scheme != "freebeamer" {
		t.Errorf("scheme = %q, want %q", parsed.Scheme, "freebeamer")
	}
	if parsed.Host != "connect" {
		t.Errorf("host = %q, want %q", parsed.Host, "connect")
	}
	if got := parsed.Query().Get("relay_url"); got != "https://telemetry.pact.net/v1/telemetry" {
		t.Errorf("relay_url = %q, want %q", got, "https://telemetry.pact.net/v1/telemetry")
	}
	if got := parsed.Query().Get("pairing_token"); got != "tok_abc123" {
		t.Errorf("pairing_token = %q, want %q", got, "tok_abc123")
	}
	if got := parsed.Query().Get("name"); got != "Bay 3 - N55" {
		t.Errorf("name = %q, want %q", got, "Bay 3 - N55")
	}
}

func TestPairingLinkTrimsTrailingSlash(t *testing.T) {
	link := pairingLink("https://telemetry.pact.net/", "tok_abc123", "Bay 3")
	parsed, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	if got := parsed.Query().Get("relay_url"); got != "https://telemetry.pact.net/v1/telemetry" {
		t.Errorf("relay_url = %q, want no double slash", got)
	}
}
