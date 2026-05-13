package software

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type Result struct {
	Packages []Package `json:"packages"`
	Sources  []string  `json:"sources"`
}

type Package struct {
	Name            string `json:"name"`
	Version         string `json:"version,omitempty"`
	Publisher       string `json:"publisher,omitempty"`
	InstallLocation string `json:"installLocation,omitempty"`
	InstallDate     string `json:"installDate,omitempty"`
	Size            string `json:"size,omitempty"`
	PackageManager  string `json:"packageManager,omitempty"`
	Architecture    string `json:"architecture,omitempty"`
	Status          string `json:"status,omitempty"`
	Source          string `json:"source,omitempty"`
	Platform        string `json:"platform"`
}

func Collect(root string) (Result, error) {
	var result Result
	if err := collectDpkgStatus(root, &result); err != nil {
		return Result{}, err
	}
	if err := collectRpmSnapshot(root, &result); err != nil {
		return Result{}, err
	}
	if err := enrichFromAptHistory(root, &result); err != nil {
		return Result{}, err
	}
	if err := enrichFromDpkgLog(root, &result); err != nil {
		return Result{}, err
	}
	sort.Slice(result.Packages, func(i, j int) bool {
		left := result.Packages[i]
		right := result.Packages[j]
		if left.Name == right.Name {
			return left.Version < right.Version
		}
		return left.Name < right.Name
	})
	sort.Strings(result.Sources)
	return result, nil
}

func enrichFromDpkgLog(root string, result *Result) error {
	relativePath := filepath.Join("var", "log", "dpkg.log")
	events, err := readDpkgLog(filepath.Join(root, relativePath), relativePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if len(events) == 0 {
		return nil
	}
	latestByPackage := map[string]aptPackageEvent{}
	for _, event := range events {
		if event.Name == "" || event.Timestamp == "" {
			continue
		}
		if current, exists := latestByPackage[event.Name]; !exists || event.Timestamp > current.Timestamp {
			latestByPackage[event.Name] = event
		}
	}
	for idx := range result.Packages {
		if result.Packages[idx].InstallDate != "" {
			continue
		}
		event, exists := latestByPackage[result.Packages[idx].Name]
		if !exists {
			continue
		}
		result.Packages[idx].InstallDate = event.Timestamp
		result.Packages[idx].Source = event.Source
	}
	result.Sources = append(result.Sources, relativePath)
	return nil
}

func readDpkgLog(path string, source string) ([]aptPackageEvent, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var events []aptPackageEvent
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		action := fields[2]
		if action != "install" && action != "upgrade" {
			continue
		}
		timestamp := parseDpkgLogTimestamp(fields[0] + " " + fields[1])
		name, _, _ := strings.Cut(fields[3], ":")
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		events = append(events, aptPackageEvent{Name: name, Timestamp: timestamp, Source: source})
	}
	return events, scanner.Err()
}

func parseDpkgLogTimestamp(value string) string {
	parsed, err := time.Parse("2006-01-02 15:04:05", value)
	if err != nil {
		return ""
	}
	return parsed.UTC().Format(time.RFC3339)
}

type aptPackageEvent struct {
	Name      string
	Timestamp string
	Source    string
}

func enrichFromAptHistory(root string, result *Result) error {
	relativePath := filepath.Join("var", "log", "apt", "history.log")
	events, err := readAptHistory(filepath.Join(root, relativePath), relativePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if len(events) == 0 {
		return nil
	}
	latestByPackage := map[string]aptPackageEvent{}
	for _, event := range events {
		if event.Name == "" || event.Timestamp == "" {
			continue
		}
		if current, exists := latestByPackage[event.Name]; !exists || event.Timestamp > current.Timestamp {
			latestByPackage[event.Name] = event
		}
	}
	for idx := range result.Packages {
		event, exists := latestByPackage[result.Packages[idx].Name]
		if !exists {
			continue
		}
		result.Packages[idx].InstallDate = event.Timestamp
		result.Packages[idx].Source = event.Source
	}
	result.Sources = append(result.Sources, relativePath)
	return nil
}

func readAptHistory(path string, source string) ([]aptPackageEvent, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var events []aptPackageEvent
	var currentTimestamp string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "Start-Date:") {
			currentTimestamp = parseAptHistoryTimestamp(strings.TrimSpace(strings.TrimPrefix(line, "Start-Date:")))
			continue
		}
		for _, prefix := range []string{"Install:", "Upgrade:"} {
			if strings.HasPrefix(line, prefix) {
				for _, name := range parseAptPackageNames(strings.TrimSpace(strings.TrimPrefix(line, prefix))) {
					events = append(events, aptPackageEvent{Name: name, Timestamp: currentTimestamp, Source: source})
				}
			}
		}
	}
	return events, scanner.Err()
}

func parseAptHistoryTimestamp(value string) string {
	parsed, err := time.Parse("2006-01-02  15:04:05", value)
	if err != nil {
		return ""
	}
	return parsed.UTC().Format(time.RFC3339)
}

func parseAptPackageNames(value string) []string {
	var names []string
	for _, part := range strings.Split(value, "),") {
		part = strings.TrimSpace(strings.TrimSuffix(part, ")"))
		if part == "" {
			continue
		}
		nameArch, _, ok := strings.Cut(part, " ")
		if !ok {
			nameArch = part
		}
		name, _, _ := strings.Cut(nameArch, ":")
		name = strings.TrimSpace(name)
		if name != "" {
			names = append(names, name)
		}
	}
	return names
}

func collectDpkgStatus(root string, result *Result) error {
	relativePath := filepath.Join("var", "lib", "dpkg", "status")
	records, err := readDpkgStatus(filepath.Join(root, relativePath))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	for _, fields := range records {
		if fields["Package"] == "" || fields["Status"] != "install ok installed" {
			continue
		}
		result.Packages = append(result.Packages, Package{
			Name:            fields["Package"],
			Version:         fields["Version"],
			Publisher:       fields["Maintainer"],
			InstallLocation: relativePath,
			Size:            installedSize(fields["Installed-Size"]),
			PackageManager:  "dpkg",
			Architecture:    fields["Architecture"],
			Status:          fields["Status"],
			Source:          relativePath,
			Platform:        "linux",
		})
	}
	if len(result.Packages) > 0 {
		result.Sources = append(result.Sources, relativePath)
	}
	return nil
}

func collectRpmSnapshot(root string, result *Result) error {
	relativePath := filepath.Join("var", "lib", "rpm", "Packages.txt")
	records, err := readKeyValueRecords(filepath.Join(root, relativePath))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	for _, fields := range records {
		if fields["Name"] == "" {
			continue
		}
		result.Packages = append(result.Packages, Package{
			Name:            fields["Name"],
			Version:         fields["Version"],
			Publisher:       fields["Vendor"],
			InstallLocation: relativePath,
			InstallDate:     fields["InstallDate"],
			Size:            rpmSize(fields["Size"]),
			PackageManager:  "rpm",
			Architecture:    fields["Architecture"],
			Status:          "installed",
			Source:          relativePath,
			Platform:        "linux",
		})
	}
	if len(records) > 0 {
		result.Sources = append(result.Sources, relativePath)
	}
	return nil
}

func readDpkgStatus(path string) ([]map[string]string, error) {
	return readKeyValueRecords(path)
}

func readKeyValueRecords(path string) ([]map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var records []map[string]string
	current := map[string]string{}
	var lastKey string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			if len(current) > 0 {
				records = append(records, current)
				current = map[string]string{}
				lastKey = ""
			}
			continue
		}
		if strings.HasPrefix(line, " ") && lastKey != "" {
			current[lastKey] = strings.TrimSpace(current[lastKey] + "\n" + strings.TrimSpace(line))
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		lastKey = strings.TrimSpace(key)
		current[lastKey] = strings.TrimSpace(value)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(current) > 0 {
		records = append(records, current)
	}
	return records, nil
}

func installedSize(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	return value + " KB"
}

func rpmSize(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	return value + " B"
}
