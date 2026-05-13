package localbundle

import (
	"encoding/json"
	"fmt"
)

func NormalizeSections(data any) (map[string]any, error) {
	if sections, ok := data.(map[string]any); ok {
		return sections, nil
	}
	rawJSON, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("serialize local sections: %w", err)
	}
	var sections map[string]any
	if err := json.Unmarshal(rawJSON, &sections); err != nil {
		return nil, fmt.Errorf("normalize local sections to object: %w", err)
	}
	if sections == nil {
		return nil, fmt.Errorf("normalize local sections to object: payload must be a JSON object")
	}
	return sections, nil
}
