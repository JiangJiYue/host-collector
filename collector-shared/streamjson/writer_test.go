package streamjson

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestWriteObjectStreamsSlicesAndMapsAsCompactJSON(t *testing.T) {
	var output bytes.Buffer

	err := WriteObject(&output, []Field{
		{Name: "name", Value: "scan-1"},
		{Name: "rows", Value: []map[string]any{
			{"id": "row-1", "count": float64(1)},
			{"id": "row-2", "count": float64(2)},
		}},
	})
	if err != nil {
		t.Fatalf("write object: %v", err)
	}
	if !json.Valid(output.Bytes()) {
		t.Fatalf("expected valid json, got %s", output.String())
	}
	if strings.Contains(output.String(), "\n  ") {
		t.Fatalf("expected compact json, got %s", output.String())
	}
	if !strings.Contains(output.String(), `"rows":[{"count":1,"id":"row-1"},{"count":2,"id":"row-2"}]`) {
		t.Fatalf("expected streamable rows, got %s", output.String())
	}
}
