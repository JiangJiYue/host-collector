package envvars

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type Result struct {
	Variables []Variable `json:"variables"`
	Sources   []string   `json:"sources"`
}

type Variable struct {
	Key      string `json:"key"`
	Value    string `json:"value"`
	Source   string `json:"source,omitempty"`
	Redacted bool   `json:"redacted,omitempty"`
	Platform string `json:"platform"`
}

func Collect(root string) (Result, error) {
	var result Result
	if err := collectEnvironmentFile(root, &result); err != nil {
		return Result{}, err
	}
	sort.Slice(result.Variables, func(i, j int) bool {
		return result.Variables[i].Key < result.Variables[j].Key
	})
	sort.Strings(result.Sources)
	return result, nil
}

func collectEnvironmentFile(root string, result *Result) error {
	relativePath := filepath.Join("etc", "environment")
	variables, err := readEnvironmentFile(filepath.Join(root, relativePath), relativePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if len(variables) > 0 {
		result.Variables = append(result.Variables, variables...)
		result.Sources = append(result.Sources, relativePath)
	}
	return nil
}

func readEnvironmentFile(path string, source string) ([]Variable, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var variables []Variable
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		key, value, ok := parseEnvironmentLine(scanner.Text())
		if !ok {
			continue
		}
		redacted := isSensitiveKey(key)
		if redacted {
			value = "[REDACTED]"
		}
		variables = append(variables, Variable{
			Key:      key,
			Value:    value,
			Source:   source,
			Redacted: redacted,
			Platform: "linux",
		})
	}
	return variables, scanner.Err()
}

func parseEnvironmentLine(line string) (string, string, bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return "", "", false
	}
	key, value, ok := strings.Cut(trimmed, "=")
	if !ok {
		return "", "", false
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return "", "", false
	}
	return key, unquoteEnvironmentValue(strings.TrimSpace(value)), true
}

func unquoteEnvironmentValue(value string) string {
	if len(value) < 2 {
		return value
	}
	if (strings.HasPrefix(value, "\"") && strings.HasSuffix(value, "\"")) || (strings.HasPrefix(value, "'") && strings.HasSuffix(value, "'")) {
		return value[1 : len(value)-1]
	}
	return value
}

func isSensitiveKey(key string) bool {
	upper := strings.ToUpper(key)
	for _, marker := range []string{"PASSWORD", "PASSWD", "SECRET", "TOKEN", "API_KEY", "PRIVATE_KEY", "ACCESS_KEY"} {
		if strings.Contains(upper, marker) {
			return true
		}
	}
	return false
}
