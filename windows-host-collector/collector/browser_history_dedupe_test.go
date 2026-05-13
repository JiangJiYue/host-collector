package collector

import "testing"

func TestDedupeBrowserHistoryVisitsRemovesExactDuplicateVisit(t *testing.T) {
	visits := []browserHistoryVisit{
		{
			Browser:            "Chrome",
			URL:                "https://example.com",
			Title:              "Example",
			RawVisitTime:       1745193600000000,
			FormattedVisitTime: "2025-04-21T00:00:00Z",
		},
		{
			Browser:            "Chrome",
			URL:                "https://example.com",
			Title:              "Example",
			RawVisitTime:       1745193600000000,
			FormattedVisitTime: "2025-04-21T00:00:00Z",
		},
		{
			Browser:            "Chrome",
			URL:                "https://example.com/2",
			Title:              "Example 2",
			RawVisitTime:       1745193660000000,
			FormattedVisitTime: "2025-04-21T00:01:00Z",
		},
	}

	got := dedupeBrowserHistoryVisits(visits)
	if len(got) != 2 {
		t.Fatalf("expected 2 unique visits, got %d: %#v", len(got), got)
	}
}

func TestDedupeBrowserHistoryVisitsKeepsDistinctSameSecondVisits(t *testing.T) {
	visits := []browserHistoryVisit{
		{
			Browser:            "Firefox",
			URL:                "https://example.com",
			Title:              "Example",
			RawVisitTime:       1745193600000000,
			FormattedVisitTime: "2025-04-21T00:00:00Z",
		},
		{
			Browser:            "Firefox",
			URL:                "https://example.com",
			Title:              "Example",
			RawVisitTime:       1745193600999999,
			FormattedVisitTime: "2025-04-21T00:00:00Z",
		},
	}

	got := dedupeBrowserHistoryVisits(visits)
	if len(got) != 2 {
		t.Fatalf("expected 2 distinct visits in the same second, got %d: %#v", len(got), got)
	}
}
