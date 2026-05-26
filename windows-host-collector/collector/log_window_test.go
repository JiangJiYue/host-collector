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

func TestEventLogWindowDecisionContinuesFullCollectionForSparseSecurityLog(t *testing.T) {
	windowStart := mustParseRFC3339(t, "2026-05-15T00:00:00Z")
	entries := []*models.WindowsLogItem{
		{EventID: 4624, Timestamp: "2026-05-22T09:38:00Z", Summary: "recent administrator logon"},
		{EventID: 4720, Timestamp: "2024-02-26T23:01:13Z", Summary: "Administrator created hack168$"},
		{EventID: 4722, Timestamp: "2024-02-26T23:01:13Z", Summary: "Administrator enabled hack168$"},
		{EventID: 4732, Timestamp: "2024-02-26T23:01:37Z", Summary: "hack168$ added to Administrators"},
		{EventID: 4624, LogonType: ptr(10), Timestamp: "2024-02-26T23:02:24Z", Summary: "hack168$ RDP logon"},
	}

	collection := newEventLogChannelWindow("Security", windowStart)
	var kept []models.WindowsLogItem
	for _, entry := range entries {
		keep, stop := collection.Decide(entry)
		if keep {
			kept = append(kept, *entry)
		}
		if stop {
			break
		}
	}

	if len(kept) != len(entries) {
		t.Fatalf("expected sparse Security log to keep full history, got %#v", kept)
	}
	if kept[1].EventID != 4720 || kept[4].LogonType == nil || *kept[4].LogonType != 10 {
		t.Fatalf("expected old account creation and RDP events to remain, got %#v", kept)
	}
	if !collection.FullCollectionEnabled() {
		t.Fatal("expected sparse Security collection to switch to full mode")
	}
}

func TestEventLogCollectionPlanUsesFullModeWhenAllChannelsAreSmall(t *testing.T) {
	plan := decideWindowsEventLogCollectionPlan([]eventLogChannelEstimate{
		{Channel: "Security", SizeBytes: 1024, RecordCount: 10, Status: "available"},
		{Channel: "System", SizeBytes: 2048, RecordCount: 20, Status: "available"},
	})

	if plan.Mode != "full" {
		t.Fatalf("expected small Windows event logs to use full collection, got %#v", plan)
	}
	if plan.TotalBytes != 3072 || plan.TotalEvents != 30 {
		t.Fatalf("expected channel totals, got %#v", plan)
	}
}

func TestEventLogChannelWindowKeepsFullPlanEntriesOutsideWindow(t *testing.T) {
	windowStart := mustParseRFC3339(t, "2026-05-15T00:00:00Z")
	collection := newEventLogChannelWindow("Application", windowStart)
	collection.ApplyPlanMode("full")

	keep, stop := collection.Decide(&models.WindowsLogItem{
		EventID:   1000,
		Timestamp: "2024-02-26T23:01:13Z",
		Summary:   "old application evidence",
	})

	if !keep || stop {
		t.Fatalf("expected full plan to keep old event without stopping, keep=%t stop=%t", keep, stop)
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
