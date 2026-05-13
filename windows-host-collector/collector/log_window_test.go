package collector

import (
	"testing"
	"time"

	"windows-host-collector/models"
)

func TestEventWithinWindow(t *testing.T) {
	windowStart := mustParseRFC3339(t, "2026-04-20T00:00:00Z")

	if !eventWithinWindow("2026-04-20T00:00:00Z", windowStart) {
		t.Fatal("expected timestamp on window boundary to be kept")
	}
	if eventWithinWindow("2026-04-19T23:59:59Z", windowStart) {
		t.Fatal("expected timestamp before window to be dropped")
	}
	if eventWithinWindow("not-a-timestamp", windowStart) {
		t.Fatal("expected unparseable timestamp to be dropped")
	}
}

func TestParseEventXMLNormalizesTimestampToRFC3339(t *testing.T) {
	entry := parseEventXML(`<Event><System><Provider Name="TestProvider"></Provider><EventID>4624</EventID><Level>4</Level><TimeCreated SystemTime="2026-04-21T12:01:02.1234567Z"></TimeCreated><Computer>host</Computer></System><EventData><Data Name="ProcessName">powershell.exe</Data></EventData></Event>`, "security", 0)
	if entry == nil {
		t.Fatal("expected event XML to parse")
	}
	if entry.Timestamp != "2026-04-21T12:01:02Z" {
		t.Fatalf("expected RFC3339 timestamp, got %q", entry.Timestamp)
	}
}

func TestEventLogWindowDecisionStopsCurrentChannelAfterOlderEntry(t *testing.T) {
	windowStart := mustParseRFC3339(t, "2026-04-20T00:00:00Z")
	entries := []*models.WindowsLogItem{
		{Timestamp: "2026-04-21T12:01:02Z", Summary: "inside"},
		{Timestamp: "2026-04-19T23:59:59Z", Summary: "older"},
		{Timestamp: "2026-04-18T12:01:02Z", Summary: "must-not-be-consumed"},
	}

	var kept []models.WindowsLogItem
	consumed := 0
	for _, entry := range entries {
		consumed++
		keep, stop := eventLogWindowDecision(windowStart, entry)
		if keep {
			kept = append(kept, *entry)
		}
		if stop {
			break
		}
	}

	if consumed != 2 {
		t.Fatalf("expected channel processing to stop on first out-of-window event, consumed=%d", consumed)
	}
	if len(kept) != 1 {
		t.Fatalf("expected only the in-window event to be kept, got %#v", kept)
	}
	if kept[0].Summary != "inside" {
		t.Fatalf("expected the newest in-window event to be kept, got %#v", kept[0])
	}
}

func TestEventLogWindowDecisionDropsOlderEntryAndSignalsChannelStop(t *testing.T) {
	windowStart := mustParseRFC3339(t, "2026-04-20T00:00:00Z")

	keep, stop := eventLogWindowDecision(windowStart, &models.WindowsLogItem{
		Timestamp: "2026-04-19T23:59:59Z",
		Summary:   "older",
	})

	if keep {
		t.Fatal("expected first older entry to be dropped")
	}
	if !stop {
		t.Fatal("expected first older entry to stop further channel iteration")
	}
}

func TestEventLogWindowDecisionKeepsNewerEntriesUntilFirstOlderEntry(t *testing.T) {
	windowStart := mustParseRFC3339(t, "2026-04-20T00:00:00Z")
	entries := []*models.WindowsLogItem{
		{Timestamp: "2026-04-21T12:01:02Z", Summary: "newest"},
		{Timestamp: "2026-04-20T09:00:00Z", Summary: "boundary-day"},
		{Timestamp: "2026-04-19T23:59:59Z", Summary: "older"},
		{Timestamp: "2026-04-18T12:01:02Z", Summary: "never-reached"},
	}

	var kept []string
	for _, entry := range entries {
		keep, stop := eventLogWindowDecision(windowStart, entry)
		if keep {
			kept = append(kept, entry.Summary)
		}
		if stop {
			break
		}
	}

	if len(kept) != 2 {
		t.Fatalf("expected to keep entries only until first older event, got %#v", kept)
	}
	if kept[0] != "newest" || kept[1] != "boundary-day" {
		t.Fatalf("expected newest-to-oldest processing before stop, got %#v", kept)
	}
}

func mustParseRFC3339(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatalf("parse time %q: %v", value, err)
	}
	return parsed
}
