package contracts

import (
	"encoding/json"
	"testing"
)

func TestEvidenceKeepsPlatformSpecificDataInExtensions(t *testing.T) {
	evidence := Evidence{
		ID:         "ev-1",
		Kind:       EvidenceProcess,
		Source:     "procfs",
		Timestamp:  "2026-05-02T10:00:00Z",
		Summary:    "observed sshd process",
		Confidence: ConfidenceHigh,
		Subject: Subject{
			Type: SubjectProcess,
			ID:   "pid:123",
			Name: "sshd",
		},
		PlatformExtensions: PlatformExtensions{
			Linux: map[string]any{"namespaceId": "mnt:[1]"},
		},
	}

	raw, err := json.Marshal(evidence)
	if err != nil {
		t.Fatalf("marshal evidence: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("decode evidence: %v", err)
	}
	if decoded["kind"] != "process" {
		t.Fatalf("expected process evidence, got %#v", decoded)
	}
	if _, exists := decoded["namespaceId"]; exists {
		t.Fatalf("linux namespace must stay inside platformExtensions: %#v", decoded)
	}
}

func TestEvidenceJSONUsesPlannedFieldNames(t *testing.T) {
	evidence := Evidence{
		ID:         "ev-1",
		Kind:       EvidenceProcess,
		Source:     "procfs",
		Timestamp:  "2026-05-02T10:00:00Z",
		Summary:    "observed sshd process",
		Confidence: ConfidenceHigh,
		Subject: Subject{
			Type: SubjectProcess,
			ID:   "pid:123",
		},
		PlatformExtensions: PlatformExtensions{
			Linux: map[string]any{"namespaceId": "mnt:[1]"},
		},
	}

	raw, err := json.Marshal(evidence)
	if err != nil {
		t.Fatalf("marshal evidence: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("decode evidence: %v", err)
	}

	assertJSONField(t, decoded, "id", "ev-1")
	assertJSONField(t, decoded, "kind", "process")
	assertJSONField(t, decoded, "source", "procfs")
	assertJSONField(t, decoded, "timestamp", "2026-05-02T10:00:00Z")
	assertJSONField(t, decoded, "summary", "observed sshd process")
	assertJSONField(t, decoded, "confidence", "high")
	assertJSONMapField(t, decoded, "subject")
	assertJSONMapField(t, decoded, "platformExtensions")
	if _, exists := decoded["observedAt"]; exists {
		t.Fatalf("observedAt must not be emitted: %#v", decoded)
	}
	if _, exists := decoded["attributes"]; exists {
		t.Fatalf("attributes must not be emitted in phase 1: %#v", decoded)
	}
}

func TestTimelineEventJSONUsesPlannedFieldNames(t *testing.T) {
	event := TimelineEvent{
		ID:        "tl-1",
		Timestamp: "2026-05-02T10:00:00Z",
		EventType: "process.start",
		Subject: Subject{
			Type: SubjectProcess,
			ID:   "pid:123",
		},
		EvidenceIDs: []string{"ev-1"},
		PlatformExtensions: PlatformExtensions{
			Linux: map[string]any{"bootId": "boot-1"},
		},
	}

	raw, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshal timeline event: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("decode timeline event: %v", err)
	}

	assertJSONField(t, decoded, "id", "tl-1")
	assertJSONField(t, decoded, "timestamp", "2026-05-02T10:00:00Z")
	assertJSONField(t, decoded, "eventType", "process.start")
	assertJSONMapField(t, decoded, "subject")
	assertJSONSliceField(t, decoded, "evidenceIds")
	assertJSONMapField(t, decoded, "platformExtensions")
	if _, exists := decoded["time"]; exists {
		t.Fatalf("time must not be emitted: %#v", decoded)
	}
	if _, exists := decoded["kind"]; exists {
		t.Fatalf("kind must not be emitted: %#v", decoded)
	}
	if _, exists := decoded["source"]; exists {
		t.Fatalf("source must not be emitted: %#v", decoded)
	}
	if _, exists := decoded["summary"]; exists {
		t.Fatalf("summary must not be emitted on timeline events in phase 1: %#v", decoded)
	}
}

func assertJSONField(t *testing.T, decoded map[string]any, name string, want any) {
	t.Helper()

	if decoded[name] != want {
		t.Fatalf("expected %s field %q, got %#v", name, want, decoded)
	}
}

func assertJSONMapField(t *testing.T, decoded map[string]any, name string) {
	t.Helper()

	if _, ok := decoded[name].(map[string]any); !ok {
		t.Fatalf("expected %s object field, got %#v", name, decoded)
	}
}

func assertJSONSliceField(t *testing.T, decoded map[string]any, name string) {
	t.Helper()

	if _, ok := decoded[name].([]any); !ok {
		t.Fatalf("expected %s array field, got %#v", name, decoded)
	}
}
