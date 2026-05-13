package envvars

import (
	"path/filepath"
	"testing"
)

func TestCollectParsesEtcEnvironmentAndRedactsSensitiveValues(t *testing.T) {
	result, err := Collect(filepath.Join("..", "testdata", "root"))
	if err != nil {
		t.Fatalf("collect env vars: %v", err)
	}
	if len(result.Variables) != 4 {
		t.Fatalf("expected four environment variables, got %#v", result.Variables)
	}
	if len(result.Sources) != 1 || result.Sources[0] != filepath.Join("etc", "environment") {
		t.Fatalf("unexpected env sources: %#v", result.Sources)
	}

	pathVar := findVariable(t, result.Variables, "PATH")
	if pathVar.Key != "PATH" || pathVar.Value != "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin" || pathVar.Source != "etc/environment" || pathVar.Platform != "linux" {
		t.Fatalf("unexpected PATH variable: %#v", pathVar)
	}

	token := findVariable(t, result.Variables, "API_TOKEN")
	if token.Value != "[REDACTED]" || !token.Redacted {
		t.Fatalf("expected sensitive value to be redacted, got %#v", token)
	}
}

func TestCollectToleratesMissingEnvironmentFiles(t *testing.T) {
	result, err := Collect(t.TempDir())
	if err != nil {
		t.Fatalf("collect missing env files: %v", err)
	}
	if len(result.Variables) != 0 {
		t.Fatalf("expected no variables, got %#v", result.Variables)
	}
	if len(result.Sources) != 0 {
		t.Fatalf("expected no sources, got %#v", result.Sources)
	}
}

func findVariable(t *testing.T, variables []Variable, key string) Variable {
	t.Helper()
	for _, variable := range variables {
		if variable.Key == key {
			return variable
		}
	}
	t.Fatalf("expected variable %s in %#v", key, variables)
	return Variable{}
}
