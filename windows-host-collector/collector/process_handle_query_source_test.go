package collector

import (
	"os"
	"strings"
	"testing"
)

func TestProcessHandleQueryDoesNotSpawnTimeoutGoroutine(t *testing.T) {
	source, err := os.ReadFile("process_handle_query_windows.go")
	if err != nil {
		t.Fatalf("read process handle query source: %v", err)
	}

	body := string(source)
	if strings.Contains(body, "go func()") {
		t.Fatal("process handle query must not spawn per-handle timeout goroutines around NtQueryObject")
	}
	if strings.Contains(body, "time.After(") {
		t.Fatal("process handle query must not use time.After timeout while caller owns the duplicated handle")
	}
}

func TestProcessHandleQueryValidatesUnicodeStringBounds(t *testing.T) {
	source, err := os.ReadFile("process_handle_query_windows.go")
	if err != nil {
		t.Fatalf("read process handle query source: %v", err)
	}

	body := string(source)
	for _, required := range []string{
		"decodeNTUnicodeString(buf []byte, maxChars int)",
		"uintptr(unsafe.Pointer(value.Buffer))",
		"bufferStart",
		"bufferEnd",
		"Length > value.MaximumLength",
	} {
		if !strings.Contains(body, required) {
			t.Fatalf("process handle unicode decoding must validate %q", required)
		}
	}
}
