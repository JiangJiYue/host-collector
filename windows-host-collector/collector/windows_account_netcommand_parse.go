package collector

import (
	"sort"
	"strings"
)

func parseNetUserListOutput(output string) []string {
	lines := strings.Split(strings.ReplaceAll(output, "\r\n", "\n"), "\n")
	results := make([]string, 0)
	seen := make(map[string]struct{})
	separatorSeen := false

	for _, rawLine := range lines {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		if isNetCommandSeparator(line) {
			separatorSeen = true
			continue
		}
		if !separatorSeen {
			continue
		}
		if isNetCommandFooter(line) {
			break
		}
		for _, field := range strings.Fields(line) {
			field = strings.TrimSpace(field)
			if field == "" || isNetCommandFooter(field) || isNetCommandNoise(field) {
				continue
			}
			if _, ok := seen[field]; ok {
				continue
			}
			seen[field] = struct{}{}
			results = append(results, field)
		}
	}

	sort.Strings(results)
	return results
}

func isNetCommandSeparator(line string) bool {
	if line == "" {
		return false
	}
	for _, r := range line {
		if r != '-' && r != '=' && r != '_' {
			return false
		}
	}
	return true
}

func isNetCommandFooter(line string) bool {
	line = strings.TrimSpace(strings.ToLower(line))
	if line == "" {
		return false
	}
	return strings.Contains(line, "the command completed successfully") || strings.Contains(line, "命令成功完成")
}

func isNetCommandNoise(field string) bool {
	field = strings.TrimSpace(field)
	if field == "" {
		return false
	}
	lower := strings.ToLower(field)
	if strings.Contains(lower, "command") || strings.Contains(lower, "completed") || strings.Contains(lower, "success") {
		return true
	}
	if strings.Contains(field, "成功") || strings.Contains(field, "完成") || strings.Contains(field, "命令") {
		return true
	}
	if strings.Contains(field, "�") {
		return true
	}
	return false
}
