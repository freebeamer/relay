package relay

import (
	"testing"
	"time"

	"github.com/freebeamer/core/pkg/telemetry"
)

func TestHubPublishDeliversToSubscriber(t *testing.T) {
	hub := NewHub()
	ch, unsubscribe := hub.Subscribe("client-1")
	defer unsubscribe()

	sample := telemetry.Sample{DeviceID: "a", Values: map[string]float64{"RPM": 800}}
	hub.Publish("client-1", sample)

	select {
	case got := <-ch:
		if got.DeviceID != "a" {
			t.Fatalf("got = %+v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for published sample")
	}
}

func TestHubPublishOnlyReachesMatchingClient(t *testing.T) {
	hub := NewHub()
	chA, unsubA := hub.Subscribe("client-a")
	defer unsubA()
	chB, unsubB := hub.Subscribe("client-b")
	defer unsubB()

	hub.Publish("client-a", telemetry.Sample{DeviceID: "only-a"})

	select {
	case got := <-chA:
		if got.DeviceID != "only-a" {
			t.Fatalf("chA got = %+v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting on chA")
	}

	select {
	case got := <-chB:
		t.Fatalf("chB unexpectedly received %+v", got)
	case <-time.After(50 * time.Millisecond):
		// expected: nothing delivered to an unrelated client
	}
}

func TestHubPublishWithNoSubscribersDoesNotBlock(t *testing.T) {
	hub := NewHub()
	done := make(chan struct{})
	go func() {
		hub.Publish("nobody-listening", telemetry.Sample{DeviceID: "a"})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Publish blocked with no subscribers")
	}
}

func TestHubUnsubscribeStopsDelivery(t *testing.T) {
	hub := NewHub()
	ch, unsubscribe := hub.Subscribe("client-1")
	unsubscribe()

	if _, ok := <-ch; ok {
		t.Fatal("channel should be closed after unsubscribe")
	}

	// Publishing after unsubscribe must not panic or block.
	hub.Publish("client-1", telemetry.Sample{DeviceID: "a"})
}

func TestHubUnsubscribeIsIdempotent(t *testing.T) {
	hub := NewHub()
	_, unsubscribe := hub.Subscribe("client-1")
	unsubscribe()
	unsubscribe() // must not panic (double close)
}
