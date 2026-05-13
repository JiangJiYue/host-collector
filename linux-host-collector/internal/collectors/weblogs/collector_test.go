package weblogs

import (
	"path/filepath"
	"testing"

	"linux-host-collector/internal/collectors/network"
	"linux-host-collector/internal/collectors/process"
)

func TestCollectDiscoversNginxLogsFromRuntimeSignals(t *testing.T) {
	root := filepath.Join("..", "testdata", "root")
	processResult, err := process.Collect(root)
	if err != nil {
		t.Fatalf("collect processes: %v", err)
	}
	networkResult, err := network.Collect(root)
	if err != nil {
		t.Fatalf("collect network: %v", err)
	}

	result, err := Collect(Config{
		Root:        root,
		Processes:   processResult.Processes,
		Connections: networkResult.Connections,
	})
	if err != nil {
		t.Fatalf("collect web logs: %v", err)
	}
	if len(result.Sources) != 1 {
		t.Fatalf("expected one source, got %#v", result.Sources)
	}
	source := result.Sources[0]
	if source.Path != "/var/log/nginx/access.log.txt" || source.ServerType != "nginx" || source.SourceMethod != "runtimeProcessConfig" {
		t.Fatalf("unexpected source: %#v", source)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("expected one entry, got %#v", result.Entries)
	}
	entry := result.Entries[0]
	if entry.ClientIP != "127.0.0.1" || entry.Method != "GET" || entry.URI != "/index.html" || entry.Status != 200 || entry.ServerType != "nginx" {
		t.Fatalf("unexpected entry: %#v", entry)
	}
}
