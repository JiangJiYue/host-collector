package appcore

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"regexp"
	"time"
)

const ScanIDTimeFormat = "20060102-150405"

var scanIDPattern = regexp.MustCompile(`^\d{8}-\d{6}(-[0-9a-f]{8})?$`)
var readScanIDSuffix = rand.Read

func FormatScanID(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(ScanIDTimeFormat)
}

func NewScanID(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	suffix := scanIDSuffix()
	if suffix == "" {
		suffix = "00000000"
	}
	return t.Format(ScanIDTimeFormat) + "-" + suffix
}

func ValidScanID(scanID string) bool {
	return scanIDPattern.MatchString(scanID)
}

func scanIDSuffix() string {
	var raw [4]byte
	if _, err := readScanIDSuffix(raw[:]); err == nil {
		return hex.EncodeToString(raw[:])
	}

	var fallback [4]byte
	binary.LittleEndian.PutUint32(fallback[:], uint32(time.Now().UTC().UnixNano()))
	return hex.EncodeToString(fallback[:])
}
