package upload

import (
	"strings"
	"testing"
)

func TestNormalizePayloadMapReturnsMapPayload(t *testing.T) {
	payload := map[string]any{"system": map[string]any{"hostname": "host-1"}}

	got, err := NormalizePayloadMap(payload)
	if err != nil {
		t.Fatalf("normalize payload: %v", err)
	}
	if got["system"].(map[string]any)["hostname"] != "host-1" {
		t.Fatalf("unexpected payload: %#v", got)
	}
}

func TestNormalizePayloadMapUsesJSONTags(t *testing.T) {
	type payload struct {
		System map[string]any `json:"system"`
	}

	got, err := NormalizePayloadMap(payload{System: map[string]any{"hostname": "host-1"}})
	if err != nil {
		t.Fatalf("normalize payload: %v", err)
	}
	if got["system"].(map[string]any)["hostname"] != "host-1" {
		t.Fatalf("unexpected payload: %#v", got)
	}
}

func TestNormalizePayloadMapRejectsNonObjectPayload(t *testing.T) {
	_, err := NormalizePayloadMap([]string{"not", "object"})
	if err == nil || !strings.Contains(err.Error(), "object") {
		t.Fatalf("expected object error, got %v", err)
	}
}
