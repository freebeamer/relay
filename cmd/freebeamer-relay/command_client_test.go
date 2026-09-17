package main

import (
	"net/url"
	"testing"
)

func TestProvisioningLink(t *testing.T) {
	link := provisioningLink("https://telemetry.pact.net", "fh_live_abc123")

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
	if got := parsed.Query().Get("api_key"); got != "fh_live_abc123" {
		t.Errorf("api_key = %q, want %q", got, "fh_live_abc123")
	}
}

func TestProvisioningLinkTrimsTrailingSlash(t *testing.T) {
	link := provisioningLink("https://telemetry.pact.net/", "fh_live_abc123")
	parsed, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	if got := parsed.Query().Get("relay_url"); got != "https://telemetry.pact.net/v1/telemetry" {
		t.Errorf("relay_url = %q, want no double slash", got)
	}
}
