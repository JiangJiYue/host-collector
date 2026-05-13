package localoutputdir

import (
	"path/filepath"
	"strings"
)

const AutoDirPrefix = "host-collector-"

func Resolve(value string, scanID string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	cleaned := filepath.Clean(trimmed)
	if cleaned != "." {
		return value
	}
	name := AutoDirPrefix + strings.TrimSpace(scanID)
	if name == AutoDirPrefix {
		name = AutoDirPrefix + "scan"
	}
	base, err := filepath.Abs(trimmed)
	if err != nil {
		base = trimmed
	}
	return filepath.Join(base, name)
}
