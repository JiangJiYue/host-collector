package logplan

import "testing"

func TestDecideKeepsSmallCollectionsFull(t *testing.T) {
	plan := Decide(Request{
		Domain: "web_logs",
		Sources: []SourceEstimate{
			{Path: "/var/log/nginx/access.log", SizeBytes: 1024, EventCount: 10, Status: SourceAvailable},
			{Path: "/var/log/nginx/error.log", SizeBytes: 2048, EventCount: 2, Status: SourceAvailable},
		},
		Thresholds: Thresholds{MaxFullBytes: 4096, MaxFullEvents: 100},
	})

	if plan.Mode != ModeFull {
		t.Fatalf("expected small collection to use full mode, got %#v", plan)
	}
	if plan.TotalBytes != 3072 || plan.TotalEvents != 12 {
		t.Fatalf("expected totals to be calculated, got %#v", plan)
	}
	if plan.Reason != ReasonWithinBudget {
		t.Fatalf("expected within-budget reason, got %#v", plan)
	}
}

func TestDecideUsesBackfillForLargeCollectionsWithCriticalPatterns(t *testing.T) {
	plan := Decide(Request{
		Domain: "windows_event_logs",
		Sources: []SourceEstimate{
			{Path: "Security", SizeBytes: 10 * 1024 * 1024, EventCount: 200000, Status: SourceAvailable},
		},
		Thresholds: Thresholds{MaxFullBytes: 1024, MaxFullEvents: 100},
		Backfill:   BackfillPolicy{Enabled: true, Reason: "critical_security_events"},
	})

	if plan.Mode != ModeWindowWithBackfill {
		t.Fatalf("expected large critical collection to use backfill mode, got %#v", plan)
	}
	if plan.Reason != ReasonExceedsBudget {
		t.Fatalf("expected exceeds-budget reason, got %#v", plan)
	}
}
