package history

import (
	"path/filepath"
	"testing"
)

func TestCollectParsesBashHistoryAsOperationRecords(t *testing.T) {
	result, err := Collect(filepath.Join("..", "testdata", "root"))
	if err != nil {
		t.Fatalf("collect history: %v", err)
	}
	if len(result.Records) != 5 {
		t.Fatalf("expected five operation records, got %#v", result.Records)
	}
	if len(result.Sources) != 2 || result.Sources[0] != filepath.Join("home", "alice", ".bash_history") || result.Sources[1] != filepath.Join("home", "alice", ".zsh_history") {
		t.Fatalf("unexpected history sources: %#v", result.Sources)
	}

	first := result.Records[0]
	if first.Event != "shell_history" || first.OperationTime != "2024-05-01T00:00:00Z" {
		t.Fatalf("unexpected first history record event/time: %#v", first)
	}
	if first.File != "sudo cat /etc/shadow" || first.FilePath != "home/alice/.bash_history" || first.Source != "alice:bash_history" {
		t.Fatalf("unexpected first history record details: %#v", first)
	}

	second := result.Records[1]
	if second.File != `curl -H "Authorization: Bearer [REDACTED]" https://example.test/api` {
		t.Fatalf("expected redacted token in second record, got %#v", second)
	}

	zshRecord := findRecordBySource(result.Records, "alice:zsh_history")
	if zshRecord.OperationTime != "2024-05-01T00:01:40Z" || zshRecord.File != "systemctl --user enable user-agent.service" {
		t.Fatalf("unexpected zsh history record: %#v", zshRecord)
	}
}

func TestCollectToleratesMissingHistoryFiles(t *testing.T) {
	result, err := Collect(t.TempDir())
	if err != nil {
		t.Fatalf("collect missing history files: %v", err)
	}
	if len(result.Records) != 0 {
		t.Fatalf("expected no operation records, got %#v", result.Records)
	}
	if len(result.Sources) != 0 {
		t.Fatalf("expected no sources, got %#v", result.Sources)
	}
}

func findRecordBySource(records []OperationRecord, source string) OperationRecord {
	for _, record := range records {
		if record.Source == source {
			return record
		}
	}
	return OperationRecord{}
}
