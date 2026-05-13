package localcli

import (
	"fmt"
	"strings"
)

type Options struct {
	Include string
	Exclude string
	Days    int
}

type Resolved struct {
	Include []string `json:"include"`
	Exclude []string `json:"exclude"`
	Scope   []string `json:"scope"`
	Days    int      `json:"days"`
}

func Resolve(options Options) (Resolved, error) {
	includeValue := strings.TrimSpace(options.Include)
	include, err := ParseScopeList(includeValue)
	if err != nil {
		return Resolved{}, err
	}
	exclude, err := ParseScopeList(options.Exclude)
	if err != nil {
		return Resolved{}, err
	}
	days, err := ValidateDays(options.Days)
	if err != nil {
		return Resolved{}, err
	}
	scope := applyExclude(include, exclude)
	return Resolved{Include: include, Exclude: exclude, Scope: scope, Days: days}, nil
}

func ParseScopeList(value string) ([]string, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	seen := map[string]struct{}{}
	for _, part := range parts {
		item := strings.TrimSpace(part)
		if item == "" {
			return nil, fmt.Errorf("scope list contains empty item")
		}
		if _, exists := seen[item]; exists {
			continue
		}
		seen[item] = struct{}{}
		result = append(result, item)
	}
	return result, nil
}

func ValidateDays(days int) (int, error) {
	if days == 0 {
		return 7, nil
	}
	switch days {
	case 7, 14, 30:
		return days, nil
	default:
		return 0, fmt.Errorf("--days must be one of 7, 14, or 30")
	}
}

func applyExclude(include []string, exclude []string) []string {
	if len(include) == 0 || len(exclude) == 0 {
		return cloneScope(include)
	}
	excluded := map[string]struct{}{}
	for _, item := range exclude {
		excluded[item] = struct{}{}
	}
	scope := make([]string, 0, len(include))
	for _, item := range include {
		if _, skip := excluded[item]; skip {
			continue
		}
		scope = append(scope, item)
	}
	return scope
}

func cloneScope(scope []string) []string {
	if scope == nil {
		return nil
	}
	copied := make([]string, len(scope))
	copy(copied, scope)
	return copied
}
