//go:build windows

package collector

import "testing"

func TestFormatChromiumVisitTime(t *testing.T) {
	got := formatVisitTime(chromiumTimeMode, 13388832000000000)
	if got != "2025-04-21T00:00:00Z" {
		t.Fatalf("unexpected chromium time: %q", got)
	}
}

func TestFormatChromiumVisitTimeZero(t *testing.T) {
	if got := formatVisitTime(chromiumTimeMode, 0); got != "" {
		t.Fatalf("expected empty chromium time, got %q", got)
	}
}

func TestFormatFirefoxVisitTime(t *testing.T) {
	got := formatVisitTime(firefoxTimeMode, 1745193600000000)
	if got != "2025-04-21T00:00:00Z" {
		t.Fatalf("unexpected firefox time: %q", got)
	}
}

func TestFormatVisitTimeUnknownMode(t *testing.T) {
	if got := formatVisitTime(browserTimeMode("unknown"), 1745193600); got != "" {
		t.Fatalf("expected empty time for unknown mode, got %q", got)
	}
}
