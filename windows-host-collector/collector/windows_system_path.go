package collector

import (
	"os"
	"path/filepath"
)

func systemExecutablePath(parts ...string) string {
	systemRoot := os.Getenv("SystemRoot")
	if systemRoot == "" {
		systemRoot = `C:\Windows`
	}
	segments := append([]string{systemRoot, "System32"}, parts...)
	return filepath.Join(segments...)
}
