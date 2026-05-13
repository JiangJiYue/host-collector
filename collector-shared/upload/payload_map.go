package upload

import (
	"encoding/json"
	"fmt"
)

func NormalizePayloadMap(data any) (map[string]any, error) {
	if payloadMap, ok := data.(map[string]any); ok {
		return payloadMap, nil
	}
	rawJSON, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("serialize upload payload: %w", err)
	}
	var payloadMap map[string]any
	if err := json.Unmarshal(rawJSON, &payloadMap); err != nil {
		return nil, fmt.Errorf("normalize upload payload to object: %w", err)
	}
	if payloadMap == nil {
		return nil, fmt.Errorf("normalize upload payload to object: payload must be a JSON object")
	}
	return payloadMap, nil
}
