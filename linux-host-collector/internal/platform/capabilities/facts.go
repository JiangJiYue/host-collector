package capabilities

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"collector-shared/contracts"
)

func readPlatformFacts(root string, goarch string) contracts.PlatformFacts {
	values := readOSRelease(filepath.Join(root, "etc", "os-release"))
	return contracts.PlatformFacts{
		Platform:     contracts.PlatformLinux,
		Architecture: contracts.NormalizeArchitecture(goarch),
		OSName:       values["NAME"],
		OSVersion:    values["VERSION_ID"],
		Kernel:       readFirstLine(filepath.Join(root, "proc", "version")),
		Extensions: contracts.PlatformExtensions{
			Linux: map[string]any{
				"distroId":    values["ID"],
				"buildFamily": linuxBuildFamily(values),
			},
		},
	}
}

func linuxBuildFamily(values map[string]string) string {
	for _, key := range []string{"ID_LIKE", "ID"} {
		value := strings.TrimSpace(values[key])
		if value == "" {
			continue
		}
		fields := strings.Fields(value)
		if len(fields) > 0 {
			return fields[0]
		}
	}
	return ""
}

func readOSRelease(path string) map[string]string {
	file, err := os.Open(path)
	if err != nil {
		return map[string]string{}
	}
	defer file.Close()

	values := map[string]string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		values[key] = strings.Trim(strings.TrimSpace(value), `"`)
	}
	return values
}

func readFirstLine(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	line, _, _ := strings.Cut(string(data), "\n")
	return strings.TrimSpace(line)
}
