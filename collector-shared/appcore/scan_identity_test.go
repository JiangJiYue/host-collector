package appcore

import (
	"errors"
	"regexp"
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

func TestNewScanIDAddsUniqueSuffix(t *testing.T) {
	ts := time.Date(2026, 5, 2, 12, 30, 45, 0, time.UTC)
	suffixes := [][]byte{
		{0x1a, 0x2b, 0x3c, 0x4d},
		{0x5e, 0x6f, 0x70, 0x81},
	}
	call := 0
	originalRead := readScanIDSuffix
	readScanIDSuffix = func(p []byte) (int, error) {
		copy(p, suffixes[call])
		call++
		return len(p), nil
	}
	t.Cleanup(func() {
		readScanIDSuffix = originalRead
	})

	first := NewScanID(ts)
	second := NewScanID(ts)

	if first != "20260502-123045-1a2b3c4d" {
		t.Fatalf("expected first deterministic suffixed scan id, got %q", first)
	}
	if second != "20260502-123045-5e6f7081" {
		t.Fatalf("expected second deterministic suffixed scan id, got %q", second)
	}
	if !regexp.MustCompile(`^20260502-123045-[0-9a-f]{8}$`).MatchString(first) {
		t.Fatalf("expected suffixed scan id, got %q", first)
	}
	if !regexp.MustCompile(`^20260502-123045-[0-9a-f]{8}$`).MatchString(second) {
		t.Fatalf("expected suffixed scan id, got %q", second)
	}
}

func TestNewScanIDFallsBackToValidSuffix(t *testing.T) {
	originalRead := readScanIDSuffix
	readScanIDSuffix = func([]byte) (int, error) {
		return 0, errors.New("entropy unavailable")
	}
	t.Cleanup(func() {
		readScanIDSuffix = originalRead
	})

	got := NewScanID(time.Date(2026, 5, 2, 12, 30, 45, 0, time.UTC))

	if !regexp.MustCompile(`^20260502-123045-[0-9a-f]{8}$`).MatchString(got) {
		t.Fatalf("expected fallback to preserve valid suffixed scan id, got %q", got)
	}
}

func TestNewScanIDNormalizesZeroTime(t *testing.T) {
	if got := NewScanID(time.Time{}); got != "" {
		t.Fatalf("expected empty scan id for zero time, got %q", got)
	}
}

func TestValidScanIDAcceptsLegacyAndSuffixedFormats(t *testing.T) {
	valid := []string{
		"20260502-123045",
		"20260502-123045-1a2b3c4d",
		"19991231-235959-ffffffff",
	}
	for _, scanID := range valid {
		if !ValidScanID(scanID) {
			t.Fatalf("expected %q to be valid", scanID)
		}
	}
}

func TestValidScanIDRejectsUnsupportedFormats(t *testing.T) {
	invalid := []string{
		"",
		"2026-05-02-123045",
		"20260502_123045",
		"20260502-12304",
		"20260502-123045.json",
		"../20260502-123045",
		"20260502-123045-ABCDEF12",
		"20260502-123045-1234567",
	}
	for _, scanID := range invalid {
		if ValidScanID(scanID) {
			t.Fatalf("expected %q to be invalid", scanID)
		}
	}
}
