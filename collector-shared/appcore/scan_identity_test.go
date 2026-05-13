package appcore

import (
	"testing"
	"time"
)

func TestFormatScanIDUsesSharedTimestampFormat(t *testing.T) {
	ts := time.Date(2026, 5, 2, 12, 30, 45, 900, time.UTC)

	got := FormatScanID(ts)

	if got != "20260502-123045" {
		t.Fatalf("expected shared scan id format, got %q", got)
	}
}

func TestFormatScanIDNormalizesZeroTime(t *testing.T) {
	if got := FormatScanID(time.Time{}); got != "" {
		t.Fatalf("expected empty scan id for zero time, got %q", got)
	}
}

func TestValidScanIDAcceptsSharedFormatOnly(t *testing.T) {
	valid := []string{
		"20260502-123045",
		"19991231-235959",
	}
	for _, scanID := range valid {
		if !ValidScanID(scanID) {
			t.Fatalf("expected %q to be valid", scanID)
		}
	}

	invalid := []string{
		"",
		"2026-05-02-123045",
		"20260502_123045",
		"20260502-12304",
		"20260502-123045.json",
		"../20260502-123045",
	}
	for _, scanID := range invalid {
		if ValidScanID(scanID) {
			t.Fatalf("expected %q to be invalid", scanID)
		}
	}
}
