//go:build !windows

package client

import (
	"os"
	"strings"
	"testing"
)

func TestEnsureElevatedIsNoopOnNonWindows(t *testing.T) {
	if err := EnsureElevated(); err != nil {
		t.Fatalf("expected EnsureElevated to be a no-op on non-Windows hosts, got %v", err)
	}
}

func TestBuildShellExecuteParametersEscapesArguments(t *testing.T) {
	params, err := buildShellExecuteParameters(`C:\Program Files\collector\collector.exe`, []string{"scan", `--output=C:\tmp dir\scan.json`, `quote"arg`})
	if err != nil {
		t.Fatalf("build parameters: %v", err)
	}
	if params.Executable != `C:\Program Files\collector\collector.exe` {
		t.Fatalf("unexpected executable: %q", params.Executable)
	}
	if !strings.Contains(params.Parameters, `"--output=C:\tmp dir\scan.json"`) {
		t.Fatalf("expected quoted output argument, got %q", params.Parameters)
	}
	if !strings.Contains(params.Parameters, `quote\"arg`) {
		t.Fatalf("expected embedded quote to be escaped, got %q", params.Parameters)
	}
}

func TestWindowsElevationUsesEscapedShellExecuteParameters(t *testing.T) {
	source, err := os.ReadFile("elevation_windows.go")
	if err != nil {
		t.Fatalf("read elevation windows source: %v", err)
	}
	body := string(source)
	if !strings.Contains(body, "buildShellExecuteParameters(exePath, os.Args[1:])") {
		t.Fatalf("windows elevation must escape ShellExecute arguments with buildShellExecuteParameters")
	}
	if strings.Contains(body, `strings.Join(os.Args[1:], " ")`) {
		t.Fatalf("windows elevation must not join os.Args without Windows command-line escaping")
	}
}
