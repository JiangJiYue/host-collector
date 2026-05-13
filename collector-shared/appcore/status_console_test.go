package appcore

import (
	"bytes"
	"strings"
	"testing"
)

func TestConsoleStatusSinkPrintsReadableProgress(t *testing.T) {
	var output bytes.Buffer
	sink := NewConsoleStatusSink(&output)

	sink.EmitStatus(StatusEvent{
		Type:      EventScanProgress,
		StageName: "网络",
		State:     StateRunning,
		Current:   2,
		Total:     5,
		Detail:    "连接采集中",
	})

	line := output.String()
	for _, expected := range []string{"[运行中]", "网络", "(2/5)", "连接采集中"} {
		if !strings.Contains(line, expected) {
			t.Fatalf("expected %q in console line %q", expected, line)
		}
	}
}

func TestConsoleStatusSinkPrintsCompletionMessages(t *testing.T) {
	var output bytes.Buffer
	sink := NewConsoleStatusSink(&output)

	sink.EmitStatus(StatusEvent{
		Type:    EventScanCompleted,
		State:   StateCompleted,
		Message: "扫描完成",
	})

	line := output.String()
	if !strings.Contains(line, "[完成]") || !strings.Contains(line, "扫描完成") {
		t.Fatalf("unexpected completion line %q", line)
	}
}
