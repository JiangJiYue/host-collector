package appcore

import (
	"path/filepath"
	"testing"
)

func TestClientConfigDirUsesSharedDirectoryName(t *testing.T) {
	got := ClientConfigDir("/home/agent")

	if got != filepath.Join("/home/agent", ".host-collector") {
		t.Fatalf("unexpected config dir: %q", got)
	}
}

func TestClientHistoryDirUsesConfigDir(t *testing.T) {
	got := ClientHistoryDir("/home/agent")

	if got != filepath.Join("/home/agent", ".host-collector", "history") {
		t.Fatalf("unexpected history dir: %q", got)
	}
}

func TestLinuxScanOutputPathUsesScanID(t *testing.T) {
	got := LinuxScanOutputPath("/tmp", "scan-1")

	if got != filepath.Join("/tmp", "linux-host-collector", "scan-1", "scan.json") {
		t.Fatalf("unexpected output path: %q", got)
	}
}
