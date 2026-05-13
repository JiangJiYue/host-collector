package localbundle

import (
	"strings"
	"testing"
)

func TestNormalizeSectionsReturnsMapPayload(t *testing.T) {
	sections := map[string]any{"system": map[string]any{"hostname": "host-1"}}

	got, err := NormalizeSections(sections)
	if err != nil {
		t.Fatalf("normalize sections: %v", err)
	}
	if got["system"].(map[string]any)["hostname"] != "host-1" {
		t.Fatalf("unexpected sections: %#v", got)
	}
}

func TestNormalizeSectionsUsesJSONTags(t *testing.T) {
	type envelope struct {
		System map[string]any `json:"system"`
	}

	got, err := NormalizeSections(envelope{System: map[string]any{"hostname": "host-1"}})
	if err != nil {
		t.Fatalf("normalize sections: %v", err)
	}
	if got["system"].(map[string]any)["hostname"] != "host-1" {
		t.Fatalf("unexpected sections: %#v", got)
	}
}

func TestNormalizeSectionsRejectsNonObjectPayload(t *testing.T) {
	_, err := NormalizeSections([]string{"not", "object"})
	if err == nil || !strings.Contains(err.Error(), "object") {
		t.Fatalf("expected object error, got %v", err)
	}
}
