package appcore

import (
	"regexp"
	"time"
)

const ScanIDTimeFormat = "20060102-150405"

var scanIDPattern = regexp.MustCompile(`^\d{8}-\d{6}$`)

func FormatScanID(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(ScanIDTimeFormat)
}

func ValidScanID(scanID string) bool {
	return scanIDPattern.MatchString(scanID)
}
