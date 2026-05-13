package contracts

import (
	"encoding/json"
	"testing"
)

func TestTaskResultRecordsSkippedMissingCapabilities(t *testing.T) {
	result := TaskResult{
		TaskID: TaskID("linux.logs"),
		State:  TaskSkipped,
		Diagnostics: []TaskDiagnostic{
			{
				Code:    ErrorCapabilityMissing,
				Message: "journald unavailable",
				MissingCapabilities: []Capability{
					CapabilityJournaldRead,
				},
			},
		},
	}

	if result.State != TaskSkipped {
		t.Fatalf("expected skipped task")
	}
	if len(result.Diagnostics) != 1 {
		t.Fatalf("expected one diagnostic")
	}
	if result.Diagnostics[0].MissingCapabilities[0] != CapabilityJournaldRead {
		t.Fatalf("expected missing journald capability")
	}
}

func TestTaskResultJSONUsesMinimalPlanFields(t *testing.T) {
	result := TaskResult{
		TaskID:     TaskID("linux.logs"),
		State:      TaskCompleted,
		StartedAt:  "2026-05-02T10:00:00Z",
		FinishedAt: "2026-05-02T10:00:05Z",
		Diagnostics: []TaskDiagnostic{
			{
				Code:    ErrorCapabilityMissing,
				Message: "journald unavailable",
				MissingCapabilities: []Capability{
					CapabilityJournaldRead,
				},
			},
		},
	}

	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal task result: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("decode task result: %v", err)
	}

	assertJSONField(t, decoded, "taskId", "linux.logs")
	assertJSONField(t, decoded, "state", "completed")
	assertJSONSliceField(t, decoded, "diagnostics")
	assertJSONField(t, decoded, "startedAt", "2026-05-02T10:00:00Z")
	assertJSONField(t, decoded, "finishedAt", "2026-05-02T10:00:05Z")
	if _, exists := decoded["completedAt"]; exists {
		t.Fatalf("completedAt must not be emitted: %#v", decoded)
	}
	if _, exists := decoded["evidence"]; exists {
		t.Fatalf("evidence must not be emitted from task result in phase 1: %#v", decoded)
	}
	if _, exists := decoded["timeline"]; exists {
		t.Fatalf("timeline must not be emitted from task result in phase 1: %#v", decoded)
	}
	if _, exists := decoded["error"]; exists {
		t.Fatalf("error must not be emitted from task result in phase 1: %#v", decoded)
	}
	if _, exists := decoded["platformExtensions"]; exists {
		t.Fatalf("platformExtensions must not be emitted from task result in phase 1: %#v", decoded)
	}
}

func TestTaskDefinitionJSONUsesMinimalPlanFields(t *testing.T) {
	definition := TaskDefinition{
		ID:                   TaskID("linux.logs"),
		Name:                 "Linux logs",
		RequiredCapabilities: []Capability{CapabilityJournaldRead},
	}

	raw, err := json.Marshal(definition)
	if err != nil {
		t.Fatalf("marshal task definition: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("decode task definition: %v", err)
	}

	if _, exists := decoded["timeout"]; exists {
		t.Fatalf("timeout must not be emitted from task definition in phase 1: %#v", decoded)
	}
}
