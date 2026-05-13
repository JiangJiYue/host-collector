package contracts

import (
	"encoding/json"
	"testing"
)

func TestPlatformFactsJSONUsesStableCrossPlatformFields(t *testing.T) {
	facts := PlatformFacts{
		Platform:     PlatformLinux,
		Architecture: ArchitectureARM64,
		OSName:       "Ubuntu",
		OSVersion:    "24.04",
		Kernel:       "6.8.0",
		Hostname:     "srv-linux-1",
		Extensions: PlatformExtensions{
			Linux: map[string]any{
				"distroId": "ubuntu",
			},
		},
	}

	raw, err := json.Marshal(facts)
	if err != nil {
		t.Fatalf("marshal platform facts: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("decode platform facts: %v", err)
	}
	if decoded["platform"] != "linux" {
		t.Fatalf("expected linux platform, got %#v", decoded)
	}
	if decoded["architecture"] != "arm64" {
		t.Fatalf("expected arm64 architecture, got %#v", decoded)
	}
	extensions := decoded["platformExtensions"].(map[string]any)
	if _, ok := extensions["linux"]; !ok {
		t.Fatalf("expected linux extension bucket, got %#v", extensions)
	}
	if _, exists := decoded["distroId"]; exists {
		t.Fatalf("linux-only fields must not be promoted to top-level fields: %#v", decoded)
	}
}

func TestNormalizeArchitectureMapsGoArchToContractValues(t *testing.T) {
	cases := map[string]Architecture{
		"amd64":   ArchitectureAMD64,
		"x86_64":  ArchitectureAMD64,
		"arm64":   ArchitectureARM64,
		"aarch64": ArchitectureARM64,
		"386":     ArchitectureX86,
		"arm":     ArchitectureARM,
		"":        ArchitectureUnknown,
	}

	for input, want := range cases {
		if got := NormalizeArchitecture(input); got != want {
			t.Fatalf("NormalizeArchitecture(%q) = %q, want %q", input, got, want)
		}
	}
}
