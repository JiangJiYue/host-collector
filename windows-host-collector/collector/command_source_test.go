package collector

import (
	"os"
	"strings"
	"testing"
)

func TestWindowsCollectorsUseSystemExecutablePaths(t *testing.T) {
	for _, path := range []string{
		"windows_account_netcommand_windows.go",
		"network_dns_windows.go",
		"network_windows_shares_hosts.go",
	} {
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		body := string(source)
		for _, forbidden := range []string{
			`exec.CommandContext(ctx, "cmd"`,
			`exec.CommandContext(ctx, "net"`,
			`exec.CommandContext(ctx, "powershell"`,
		} {
			if strings.Contains(body, forbidden) {
				t.Fatalf("%s must not launch %s through PATH search", path, forbidden)
			}
		}
	}
}
