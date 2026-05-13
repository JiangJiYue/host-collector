package startup

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type Result struct {
	Services         []Service         `json:"services"`
	Timers           []Timer           `json:"timers"`
	CronJobs         []CronJob         `json:"cronJobs"`
	PersistenceItems []PersistenceItem `json:"persistenceItems"`
	Sources          []string          `json:"sources"`
}

type Service struct {
	Name         string   `json:"name"`
	Source       string   `json:"source"`
	Description  string   `json:"description,omitempty"`
	ExecStart    string   `json:"execStart,omitempty"`
	WantedBy     string   `json:"wantedBy,omitempty"`
	SourceType   string   `json:"sourceType,omitempty"`
	EnabledState string   `json:"enabledState,omitempty"`
	ActiveState  string   `json:"activeState,omitempty"`
	User         string   `json:"user,omitempty"`
	Group        string   `json:"group,omitempty"`
	Requires     []string `json:"requires,omitempty"`
	Wants        []string `json:"wants,omitempty"`
}

type Timer struct {
	Name         string   `json:"name"`
	Source       string   `json:"source"`
	Description  string   `json:"description,omitempty"`
	OnCalendar   string   `json:"onCalendar,omitempty"`
	Unit         string   `json:"unit,omitempty"`
	WantedBy     string   `json:"wantedBy,omitempty"`
	SourceType   string   `json:"sourceType,omitempty"`
	EnabledState string   `json:"enabledState,omitempty"`
	ActiveState  string   `json:"activeState,omitempty"`
	Requires     []string `json:"requires,omitempty"`
	Wants        []string `json:"wants,omitempty"`
}

type CronJob struct {
	User     string `json:"user,omitempty"`
	Schedule string `json:"schedule"`
	Command  string `json:"command"`
	Source   string `json:"source"`
}

type PersistenceItem struct {
	Kind             string              `json:"kind"`
	Name             string              `json:"name"`
	Source           string              `json:"source"`
	Command          string              `json:"command,omitempty"`
	SourceType       string              `json:"sourceType,omitempty"`
	EnabledState     string              `json:"enabledState,omitempty"`
	ActiveState      string              `json:"activeState,omitempty"`
	User             string              `json:"user,omitempty"`
	Requires         []string            `json:"requires,omitempty"`
	Wants            []string            `json:"wants,omitempty"`
	SecurityFindings []SSHConfigFinding  `json:"securityFindings,omitempty"`
	Config           map[string][]string `json:"config,omitempty"`
}

type SSHConfigFinding struct {
	Key      string `json:"key"`
	Value    string `json:"value"`
	Severity string `json:"severity"`
	Reason   string `json:"reason"`
	Line     int    `json:"line,omitempty"`
}

func Collect(root string) (Result, error) {
	var result Result
	if err := collectSystemd(root, &result); err != nil {
		return Result{}, err
	}
	if err := collectCron(root, &result); err != nil {
		return Result{}, err
	}
	if err := collectAnacron(root, &result); err != nil {
		return Result{}, err
	}
	if err := collectLogrotateScripts(root, &result); err != nil {
		return Result{}, err
	}
	if err := collectAtJobs(root, &result); err != nil {
		return Result{}, err
	}
	if err := collectSSHDConfig(root, &result); err != nil {
		return Result{}, err
	}
	if err := collectSSHAuthorizedKeys(root, &result); err != nil {
		return Result{}, err
	}
	if err := collectDynamicLoaderPreload(root, &result); err != nil {
		return Result{}, err
	}
	if err := collectUdevRules(root, &result); err != nil {
		return Result{}, err
	}
	if err := collectKernelModules(root, &result); err != nil {
		return Result{}, err
	}
	if err := collectShellStartup(root, &result); err != nil {
		return Result{}, err
	}
	if err := collectLegacyStartup(root, &result); err != nil {
		return Result{}, err
	}
	if err := collectDesktopAutostart(root, &result); err != nil {
		return Result{}, err
	}
	sortResult(&result)
	return result, nil
}

func collectSystemd(root string, result *Result) error {
	enabled := collectEnabledUnits(root)
	for _, dir := range []string{
		filepath.Join("etc", "systemd", "system"),
		filepath.Join("usr", "lib", "systemd", "system"),
		filepath.Join("lib", "systemd", "system"),
	} {
		if err := collectSystemdUnitDirectory(root, dir, "", enabled, result); err != nil {
			return err
		}
	}
	if err := collectUserSystemd(root, enabled, result); err != nil {
		return err
	}
	return nil
}

func collectSystemdUnitDirectory(root string, dir string, owner string, enabled map[string]bool, result *Result) error {
	entries, err := os.ReadDir(filepath.Join(root, dir))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			if isSystemdDropInDir(entry.Name()) {
				if err := collectSystemdDropInDirectory(root, dir, entry.Name(), owner, result); err != nil {
					return err
				}
			}
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".service") && !strings.HasSuffix(name, ".timer") && !strings.HasSuffix(name, ".socket") && !strings.HasSuffix(name, ".path") {
			continue
		}
		relativePath := filepath.Join(dir, name)
		unit, err := parseUnitFile(filepath.Join(root, relativePath))
		if err != nil {
			return err
		}
		result.Sources = append(result.Sources, relativePath)
		if strings.HasSuffix(name, ".service") {
			user := unit["Service"]["User"]
			if user == "" {
				user = owner
			}
			service := Service{
				Name:         name,
				Source:       relativePath,
				Description:  unit["Unit"]["Description"],
				ExecStart:    unit["Service"]["ExecStart"],
				WantedBy:     unit["Install"]["WantedBy"],
				SourceType:   "systemd_service",
				EnabledState: enabledState(enabled, name),
				ActiveState:  "unavailable_offline_root",
				User:         user,
				Group:        unit["Service"]["Group"],
				Requires:     splitUnitList(unit["Unit"]["Requires"]),
				Wants:        splitUnitList(unit["Unit"]["Wants"]),
			}
			result.Services = append(result.Services, service)
			result.PersistenceItems = append(result.PersistenceItems, PersistenceItem{
				Kind:         "systemd_service",
				Name:         service.Name,
				Source:       service.Source,
				Command:      service.ExecStart,
				SourceType:   service.SourceType,
				EnabledState: service.EnabledState,
				ActiveState:  service.ActiveState,
				User:         service.User,
				Requires:     service.Requires,
				Wants:        service.Wants,
			})
		}
		if strings.HasSuffix(name, ".timer") {
			timer := Timer{
				Name:         name,
				Source:       relativePath,
				Description:  unit["Unit"]["Description"],
				OnCalendar:   unit["Timer"]["OnCalendar"],
				Unit:         unit["Timer"]["Unit"],
				WantedBy:     unit["Install"]["WantedBy"],
				SourceType:   "systemd_timer",
				EnabledState: enabledState(enabled, name),
				ActiveState:  "unavailable_offline_root",
				Requires:     splitUnitList(unit["Unit"]["Requires"]),
				Wants:        splitUnitList(unit["Unit"]["Wants"]),
			}
			result.Timers = append(result.Timers, timer)
			result.PersistenceItems = append(result.PersistenceItems, PersistenceItem{
				Kind:         "systemd_timer",
				Name:         timer.Name,
				Source:       timer.Source,
				Command:      timer.OnCalendar,
				SourceType:   timer.SourceType,
				EnabledState: timer.EnabledState,
				ActiveState:  timer.ActiveState,
				User:         owner,
				Requires:     timer.Requires,
				Wants:        timer.Wants,
			})
		}
		if strings.HasSuffix(name, ".socket") {
			sourceType := "systemd_socket"
			result.PersistenceItems = append(result.PersistenceItems, PersistenceItem{
				Kind:         sourceType,
				Name:         name,
				Source:       relativePath,
				Command:      unit["Socket"]["ListenStream"],
				SourceType:   sourceType,
				EnabledState: enabledState(enabled, name),
				ActiveState:  "unavailable_offline_root",
				User:         owner,
				Requires:     splitUnitList(unit["Unit"]["Requires"]),
				Wants:        splitUnitList(unit["Unit"]["Wants"]),
			})
		}
		if strings.HasSuffix(name, ".path") {
			config := systemdPathConfig(unit)
			result.PersistenceItems = append(result.PersistenceItems, PersistenceItem{
				Kind:             "systemd_path",
				Name:             name,
				Source:           relativePath,
				Command:          systemdPathSummary(config),
				SourceType:       "systemd_path",
				EnabledState:     enabledState(enabled, name),
				ActiveState:      "unavailable_offline_root",
				User:             owner,
				Requires:         splitUnitList(unit["Unit"]["Requires"]),
				Wants:            splitUnitList(unit["Unit"]["Wants"]),
				SecurityFindings: systemdPathFindings(config),
				Config:           config,
			})
		}
	}
	return nil
}

func isSystemdDropInDir(name string) bool {
	if !strings.HasSuffix(name, ".d") {
		return false
	}
	unitName := strings.TrimSuffix(name, ".d")
	return strings.HasSuffix(unitName, ".service") || strings.HasSuffix(unitName, ".timer") || strings.HasSuffix(unitName, ".socket")
}

func collectSystemdDropInDirectory(root string, dir string, dropInDir string, owner string, result *Result) error {
	relDir := filepath.Join(dir, dropInDir)
	entries, err := os.ReadDir(filepath.Join(root, relDir))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	unitName := strings.TrimSuffix(dropInDir, ".d")
	for _, entry := range entries {
		if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") || !strings.HasSuffix(entry.Name(), ".conf") {
			continue
		}
		relPath := filepath.Join(relDir, entry.Name())
		if err := collectSystemdDropInFile(filepath.Join(root, relPath), relPath, dropInDir, unitName, owner, result); err != nil {
			return err
		}
	}
	return nil
}

func collectSystemdDropInFile(absPath string, relPath string, dropInDir string, unitName string, owner string, result *Result) error {
	config, findings, err := parseSystemdDropInConfig(absPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if len(config) == 0 {
		return nil
	}
	config["unit"] = []string{unitName}
	config["dropIn"] = []string{dropInDir}
	user := firstConfigValue(config, "user")
	if user == "" {
		user = owner
	}
	if user == "" {
		user = "root"
	}
	item := PersistenceItem{
		Kind:             "systemd_dropin",
		Name:             filepath.Join(dropInDir, filepath.Base(relPath)),
		Source:           relPath,
		Command:          systemdDropInSummary(config),
		SourceType:       "systemd_dropin",
		EnabledState:     "configured",
		ActiveState:      "unavailable_offline_root",
		User:             user,
		Requires:         config["requires"],
		Wants:            config["wants"],
		SecurityFindings: findings,
		Config:           config,
	}
	result.PersistenceItems = append(result.PersistenceItems, item)
	result.Sources = append(result.Sources, relPath)
	return nil
}

func parseSystemdDropInConfig(path string) (map[string][]string, []SSHConfigFinding, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()

	config := map[string][]string{}
	var findings []SSHConfigFinding
	current := ""
	scanner := bufio.NewScanner(file)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			current = strings.TrimSuffix(strings.TrimPrefix(line, "["), "]")
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || current == "" {
			continue
		}
		normalizedKey := systemdDropInConfigKey(current, strings.TrimSpace(key))
		if normalizedKey == "" {
			continue
		}
		value = strings.TrimSpace(value)
		config[normalizedKey] = append(config[normalizedKey], value)
		findings = append(findings, systemdDropInFindings(strings.TrimSpace(key), value, lineNumber)...)
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}
	return config, findings, nil
}

func systemdDropInConfigKey(section string, key string) string {
	switch section + "." + key {
	case "Service.ExecStart":
		return "execStart"
	case "Service.Environment":
		return "environment"
	case "Service.User":
		return "user"
	case "Service.Group":
		return "group"
	case "Timer.OnCalendar":
		return "onCalendar"
	case "Timer.Unit":
		return "timerUnit"
	case "Socket.ListenStream":
		return "listenStream"
	case "Socket.ListenDatagram":
		return "listenDatagram"
	case "Unit.Requires":
		return "requires"
	case "Unit.Wants":
		return "wants"
	case "Unit.After":
		return "after"
	case "Unit.Before":
		return "before"
	}
	return ""
}

func systemdDropInFindings(key string, value string, lineNumber int) []SSHConfigFinding {
	var findings []SSHConfigFinding
	if key == "ExecStart" {
		findings = append(findings, SSHConfigFinding{
			Key:      key,
			Value:    value,
			Severity: "high",
			Reason:   "systemd_dropin_exec_override",
			Line:     lineNumber,
		})
	}
	if strings.Contains(value, "LD_PRELOAD") {
		findings = append(findings, SSHConfigFinding{
			Key:      key,
			Value:    value,
			Severity: "high",
			Reason:   "systemd_dropin_ld_preload",
			Line:     lineNumber,
		})
	}
	if containsTempExecutionPath(value) {
		findings = append(findings, SSHConfigFinding{
			Key:      key,
			Value:    value,
			Severity: "high",
			Reason:   "systemd_dropin_temp_path",
			Line:     lineNumber,
		})
	}
	if key == "Requires" || key == "Wants" {
		findings = append(findings, SSHConfigFinding{
			Key:      key,
			Value:    value,
			Severity: "medium",
			Reason:   "systemd_dropin_dependency_override",
			Line:     lineNumber,
		})
	}
	return findings
}

func containsTempExecutionPath(value string) bool {
	return strings.Contains(value, "/tmp/") || strings.Contains(value, "/var/tmp/") || strings.Contains(value, "/dev/shm/")
}

func firstConfigValue(config map[string][]string, key string) string {
	for _, value := range config[key] {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func systemdDropInSummary(config map[string][]string) string {
	parts := make([]string, 0)
	for _, key := range []string{"execStart", "environment", "onCalendar", "listenStream", "listenDatagram", "requires", "wants"} {
		for _, value := range nonEmptyValues(config[key]) {
			parts = append(parts, systemdDropInDisplayKey(key)+"="+value)
		}
	}
	if len(parts) > 0 {
		return strings.Join(parts, "; ")
	}
	return "systemd drop-in override"
}

func nonEmptyValues(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			result = append(result, value)
		}
	}
	return result
}

func systemdDropInDisplayKey(key string) string {
	switch key {
	case "execStart":
		return "ExecStart"
	case "environment":
		return "Environment"
	case "onCalendar":
		return "OnCalendar"
	case "listenStream":
		return "ListenStream"
	case "listenDatagram":
		return "ListenDatagram"
	case "requires":
		return "Requires"
	case "wants":
		return "Wants"
	}
	return key
}

func systemdPathConfig(unit map[string]map[string]string) map[string][]string {
	config := map[string][]string{}
	for _, key := range []string{"PathExists", "PathExistsGlob", "PathChanged", "PathModified", "DirectoryNotEmpty", "Unit"} {
		addConfigValue(config, lowerFirst(key), unit["Path"][key])
	}
	return config
}

func systemdPathSummary(config map[string][]string) string {
	var parts []string
	for _, key := range []string{"pathExists", "pathExistsGlob", "pathChanged", "pathModified", "directoryNotEmpty", "unit"} {
		for _, value := range config[key] {
			if strings.TrimSpace(value) == "" {
				continue
			}
			parts = append(parts, systemdPathDisplayKey(key)+"="+value)
		}
	}
	return strings.Join(parts, "; ")
}

func systemdPathFindings(config map[string][]string) []SSHConfigFinding {
	var findings []SSHConfigFinding
	for _, key := range []string{"pathExists", "pathExistsGlob", "pathChanged", "pathModified", "directoryNotEmpty"} {
		for _, value := range config[key] {
			findings = append(findings, SSHConfigFinding{
				Key:      systemdPathDisplayKey(key),
				Value:    value,
				Severity: "medium",
				Reason:   "systemd_path_trigger",
			})
			if containsTempExecutionPath(value) || strings.HasPrefix(value, "/tmp") || strings.HasPrefix(value, "/var/tmp") || strings.HasPrefix(value, "/dev/shm") {
				findings = append(findings, SSHConfigFinding{
					Key:      systemdPathDisplayKey(key),
					Value:    value,
					Severity: "high",
					Reason:   "systemd_path_temp_path",
				})
			}
		}
	}
	return findings
}

func systemdPathDisplayKey(key string) string {
	switch key {
	case "pathExists":
		return "PathExists"
	case "pathExistsGlob":
		return "PathExistsGlob"
	case "pathChanged":
		return "PathChanged"
	case "pathModified":
		return "PathModified"
	case "directoryNotEmpty":
		return "DirectoryNotEmpty"
	case "unit":
		return "Unit"
	default:
		return key
	}
}

func lowerFirst(value string) string {
	if value == "" {
		return ""
	}
	return strings.ToLower(value[:1]) + value[1:]
}

func collectUserSystemd(root string, enabled map[string]bool, result *Result) error {
	homeRoot := filepath.Join(root, "home")
	entries, err := os.ReadDir(homeRoot)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		user := entry.Name()
		dir := filepath.Join("home", user, ".config", "systemd", "user")
		if err := collectSystemdUnitDirectory(root, dir, user, enabled, result); err != nil {
			return err
		}
	}
	return nil
}

func collectCron(root string, result *Result) error {
	if err := collectCronFile(filepath.Join(root, "etc", "crontab"), filepath.Join("etc", "crontab"), "", true, result); err != nil {
		return err
	}
	if err := collectCronDirectory(filepath.Join(root, "etc", "cron.d"), filepath.Join("etc", "cron.d"), "", true, result); err != nil {
		return err
	}
	if err := collectCronDirectory(filepath.Join(root, "var", "spool", "cron"), filepath.Join("var", "spool", "cron"), "", false, result); err != nil {
		return err
	}
	for _, dir := range []struct {
		name     string
		schedule string
	}{
		{name: "cron.hourly", schedule: "@hourly"},
		{name: "cron.daily", schedule: "@daily"},
		{name: "cron.weekly", schedule: "@weekly"},
		{name: "cron.monthly", schedule: "@monthly"},
	} {
		if err := collectCronRunPartsDirectory(filepath.Join(root, "etc", dir.name), filepath.Join("etc", dir.name), dir.schedule, result); err != nil {
			return err
		}
	}
	return nil
}

func collectCronRunPartsDirectory(absDir string, relDir string, schedule string, result *Result) error {
	entries, err := os.ReadDir(absDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		relPath := filepath.Join(relDir, entry.Name())
		job := CronJob{
			Schedule: schedule,
			User:     "root",
			Command:  relPath,
			Source:   relPath,
		}
		result.CronJobs = append(result.CronJobs, job)
		result.PersistenceItems = append(result.PersistenceItems, PersistenceItem{
			Kind:       "cron_run_parts",
			Name:       entry.Name(),
			Source:     relPath,
			Command:    relPath,
			SourceType: "cron_run_parts",
			User:       "root",
		})
		result.Sources = append(result.Sources, relPath)
	}
	return nil
}

func collectCronDirectory(absDir string, relDir string, defaultUser string, hasUserField bool, result *Result) error {
	entries, err := os.ReadDir(absDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		user := defaultUser
		if !hasUserField {
			user = entry.Name()
		}
		relPath := filepath.Join(relDir, entry.Name())
		if err := collectCronFile(filepath.Join(absDir, entry.Name()), relPath, user, hasUserField, result); err != nil {
			return err
		}
	}
	return nil
}

func collectCronFile(absPath string, relPath string, defaultUser string, hasUserField bool, result *Result) error {
	file, err := os.Open(absPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	defer file.Close()

	var found bool
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		job, ok := parseCronLine(scanner.Text(), relPath, defaultUser, hasUserField)
		if !ok {
			continue
		}
		found = true
		result.CronJobs = append(result.CronJobs, job)
		result.PersistenceItems = append(result.PersistenceItems, PersistenceItem{
			Kind:       "cron_job",
			Name:       job.Schedule,
			Source:     job.Source,
			Command:    job.Command,
			SourceType: "cron",
			User:       job.User,
		})
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if found {
		result.Sources = append(result.Sources, relPath)
	}
	return nil
}

func collectAnacron(root string, result *Result) error {
	relPath := filepath.Join("etc", "anacrontab")
	file, err := os.Open(filepath.Join(root, relPath))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	defer file.Close()

	var found bool
	scanner := bufio.NewScanner(file)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.Contains(line, "=") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		period := fields[0]
		delay := fields[1]
		jobID := fields[2]
		command := strings.Join(fields[3:], " ")
		found = true
		result.PersistenceItems = append(result.PersistenceItems, PersistenceItem{
			Kind:             "anacron_job",
			Name:             jobID,
			Source:           relPath,
			Command:          command,
			SourceType:       "anacron_job",
			EnabledState:     "configured",
			ActiveState:      "unavailable_offline_root",
			User:             "root",
			SecurityFindings: anacronJobFindings(command, lineNumber),
			Config: map[string][]string{
				"period": []string{period},
				"delay":  []string{delay},
				"jobId":  []string{jobID},
			},
		})
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if found {
		result.Sources = append(result.Sources, relPath)
	}
	return nil
}

func anacronJobFindings(command string, lineNumber int) []SSHConfigFinding {
	findings := []SSHConfigFinding{
		{Key: "anacron", Value: command, Severity: "medium", Reason: "anacron_job_command", Line: lineNumber},
	}
	if containsTempExecutionPath(command) {
		findings = append(findings, SSHConfigFinding{Key: "anacron", Value: command, Severity: "high", Reason: "anacron_temp_path", Line: lineNumber})
	}
	if strings.Contains(command, "curl ") || strings.Contains(command, "wget ") || strings.Contains(command, "nc ") || strings.Contains(command, "ncat ") || strings.Contains(command, "socat ") {
		findings = append(findings, SSHConfigFinding{Key: "anacron", Value: command, Severity: "high", Reason: "anacron_network_tool", Line: lineNumber})
	}
	return findings
}

func collectEnabledUnits(root string) map[string]bool {
	enabled := map[string]bool{}
	systemdRoot := filepath.Join(root, "etc", "systemd", "system")
	filepath.WalkDir(systemdRoot, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry == nil || entry.IsDir() || !strings.Contains(filepath.Base(filepath.Dir(path)), ".") {
			return nil
		}
		parent := filepath.Base(filepath.Dir(path))
		if !strings.HasSuffix(parent, ".wants") && !strings.HasSuffix(parent, ".requires") {
			return nil
		}
		enabled[entry.Name()] = true
		return nil
	})
	return enabled
}

func enabledState(enabled map[string]bool, name string) string {
	if enabled[name] {
		return "enabled"
	}
	return "disabled"
}

func splitUnitList(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return strings.Fields(value)
}

func parseUnitFile(path string) (map[string]map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	sections := map[string]map[string]string{}
	current := ""
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			current = strings.TrimSuffix(strings.TrimPrefix(line, "["), "]")
			if _, exists := sections[current]; !exists {
				sections[current] = map[string]string{}
			}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || current == "" {
			continue
		}
		sections[current][strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	return sections, scanner.Err()
}

func parseCronLine(line string, source string, defaultUser string, hasUserField bool) (CronJob, bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.Contains(trimmed, "=") && !strings.HasPrefix(trimmed, "@") {
		return CronJob{}, false
	}
	fields := strings.Fields(trimmed)
	if len(fields) < 2 {
		return CronJob{}, false
	}
	if strings.HasPrefix(fields[0], "@") {
		if hasUserField {
			if len(fields) < 3 {
				return CronJob{}, false
			}
			return CronJob{Schedule: fields[0], User: fields[1], Command: strings.Join(fields[2:], " "), Source: source}, true
		}
		return CronJob{Schedule: fields[0], User: defaultUser, Command: strings.Join(fields[1:], " "), Source: source}, true
	}
	if hasUserField {
		if len(fields) < 7 {
			return CronJob{}, false
		}
		return CronJob{Schedule: strings.Join(fields[0:5], " "), User: fields[5], Command: strings.Join(fields[6:], " "), Source: source}, true
	}
	if len(fields) < 6 {
		return CronJob{}, false
	}
	return CronJob{Schedule: strings.Join(fields[0:5], " "), User: defaultUser, Command: strings.Join(fields[5:], " "), Source: source}, true
}

func collectLogrotateScripts(root string, result *Result) error {
	for _, relPath := range []string{filepath.Join("etc", "logrotate.conf")} {
		if err := collectLogrotateFile(filepath.Join(root, relPath), relPath, result); err != nil {
			return err
		}
	}
	relDir := filepath.Join("etc", "logrotate.d")
	entries, err := os.ReadDir(filepath.Join(root, relDir))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		relPath := filepath.Join(relDir, entry.Name())
		if err := collectLogrotateFile(filepath.Join(root, relPath), relPath, result); err != nil {
			return err
		}
	}
	return nil
}

func collectLogrotateFile(absPath string, relPath string, result *Result) error {
	file, err := os.Open(absPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	defer file.Close()

	var found bool
	var targets []string
	var scriptBlock string
	var scriptStartLine int
	scanner := bufio.NewScanner(file)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if scriptBlock != "" {
			if line == "endscript" {
				scriptBlock = ""
				scriptStartLine = 0
				continue
			}
			found = true
			result.PersistenceItems = append(result.PersistenceItems, PersistenceItem{
				Kind:             "logrotate_script",
				Name:             filepath.Base(relPath) + ":" + scriptBlock + ":" + strconv.Itoa(scriptStartLine),
				Source:           relPath,
				Command:          line,
				SourceType:       "logrotate_script",
				EnabledState:     "configured",
				ActiveState:      "unavailable_offline_root",
				User:             "root",
				SecurityFindings: logrotateScriptFindings(scriptBlock, line, lineNumber),
				Config: map[string][]string{
					"target": targets,
					"block":  []string{scriptBlock},
				},
			})
			continue
		}
		if strings.HasSuffix(line, "{") {
			targets = strings.Fields(strings.TrimSpace(strings.TrimSuffix(line, "{")))
			continue
		}
		if isLogrotateScriptBlock(line) {
			scriptBlock = line
			scriptStartLine = lineNumber
			continue
		}
		if line == "}" {
			targets = nil
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if found {
		result.Sources = append(result.Sources, relPath)
	}
	return nil
}

func isLogrotateScriptBlock(line string) bool {
	switch line {
	case "firstaction", "prerotate", "postrotate", "lastaction":
		return true
	default:
		return false
	}
}

func logrotateScriptFindings(block string, command string, lineNumber int) []SSHConfigFinding {
	findings := []SSHConfigFinding{
		{Key: block, Value: command, Severity: "medium", Reason: "logrotate_script_hook", Line: lineNumber},
	}
	if containsTempExecutionPath(command) {
		findings = append(findings, SSHConfigFinding{Key: block, Value: command, Severity: "high", Reason: "logrotate_temp_path", Line: lineNumber})
	}
	if strings.Contains(command, "curl ") || strings.Contains(command, "wget ") || strings.Contains(command, "nc ") || strings.Contains(command, "ncat ") || strings.Contains(command, "socat ") {
		findings = append(findings, SSHConfigFinding{Key: block, Value: command, Severity: "high", Reason: "logrotate_network_tool", Line: lineNumber})
	}
	return findings
}

func collectAtJobs(root string, result *Result) error {
	for _, relDir := range []string{
		filepath.Join("var", "spool", "atjobs"),
		filepath.Join("var", "spool", "at"),
		filepath.Join("var", "spool", "cron", "atjobs"),
	} {
		if err := collectAtJobDirectory(root, relDir, result); err != nil {
			return err
		}
	}
	return nil
}

func collectAtJobDirectory(root string, relDir string, result *Result) error {
	absDir := filepath.Join(root, relDir)
	entries, err := os.ReadDir(absDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		relPath := filepath.Join(relDir, entry.Name())
		if err := collectAtJobFile(filepath.Join(absDir, entry.Name()), relPath, result); err != nil {
			return err
		}
	}
	return nil
}

func collectAtJobFile(absPath string, relPath string, result *Result) error {
	file, err := os.Open(absPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	defer file.Close()

	config := map[string][]string{}
	var found bool
	scanner := bufio.NewScanner(file)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			collectAtJobMetadata(line, config)
			continue
		}
		if isAtJobBoilerplate(line) {
			continue
		}
		found = true
		result.PersistenceItems = append(result.PersistenceItems, PersistenceItem{
			Kind:             "at_job",
			Name:             filepath.Base(relPath) + ":" + strconv.Itoa(lineNumber),
			Source:           relPath,
			Command:          line,
			SourceType:       "at_job",
			EnabledState:     "queued",
			ActiveState:      "unavailable_offline_root",
			User:             atJobUser(config),
			SecurityFindings: atJobFindings(line, lineNumber),
			Config:           cloneConfig(config),
		})
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if found {
		result.Sources = append(result.Sources, relPath)
	}
	return nil
}

func collectAtJobMetadata(line string, config map[string][]string) {
	fields := strings.Fields(strings.TrimPrefix(line, "#"))
	for _, field := range fields {
		key, value, ok := strings.Cut(field, "=")
		if !ok {
			continue
		}
		switch key {
		case "uid", "gid":
			config[key] = []string{value}
		}
	}
}

func isAtJobBoilerplate(line string) bool {
	if strings.HasPrefix(line, "export ") || strings.HasPrefix(line, "cd ") || strings.HasPrefix(line, "umask ") {
		return true
	}
	key, value, ok := strings.Cut(line, "=")
	return ok && key != "" && value != "" && !strings.Contains(key, " ") && !strings.HasPrefix(line, "./") && !strings.HasPrefix(line, "/")
}

func atJobUser(config map[string][]string) string {
	if uid := firstConfigValue(config, "uid"); uid != "" {
		return "uid=" + uid
	}
	return "unknown"
}

func atJobFindings(command string, lineNumber int) []SSHConfigFinding {
	findings := []SSHConfigFinding{
		{Key: "at", Value: command, Severity: "medium", Reason: "at_job_command", Line: lineNumber},
	}
	if containsTempExecutionPath(command) {
		findings = append(findings, SSHConfigFinding{Key: "at", Value: command, Severity: "high", Reason: "at_job_temp_path", Line: lineNumber})
	}
	if strings.Contains(command, "curl ") || strings.Contains(command, "wget ") || strings.Contains(command, "nc ") || strings.Contains(command, "ncat ") || strings.Contains(command, "socat ") {
		findings = append(findings, SSHConfigFinding{Key: "at", Value: command, Severity: "high", Reason: "at_job_network_tool", Line: lineNumber})
	}
	return findings
}

func cloneConfig(config map[string][]string) map[string][]string {
	if len(config) == 0 {
		return nil
	}
	cloned := map[string][]string{}
	for key, values := range config {
		cloned[key] = append([]string{}, values...)
	}
	return cloned
}

func collectSSHDConfig(root string, result *Result) error {
	relPath := filepath.Join("etc", "ssh", "sshd_config")
	config, findings, err := parseSSHDConfig(filepath.Join(root, relPath))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if len(config) == 0 && len(findings) == 0 {
		return nil
	}
	result.Sources = append(result.Sources, relPath)
	result.PersistenceItems = append(result.PersistenceItems, PersistenceItem{
		Kind:             "sshd_config",
		Name:             "sshd_config",
		Source:           relPath,
		Command:          sshdConfigSummary(config),
		SourceType:       "sshd_config",
		EnabledState:     "configured",
		ActiveState:      "unavailable_offline_root",
		SecurityFindings: findings,
		Config:           config,
	})
	return nil
}

func collectSSHAuthorizedKeys(root string, result *Result) error {
	users, err := readPasswdUsers(filepath.Join(root, "etc", "passwd"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	for _, user := range users {
		if user.Home == "" || user.Home == "/nonexistent" {
			continue
		}
		relHome := strings.TrimPrefix(user.Home, string(filepath.Separator))
		for _, name := range []string{"authorized_keys", "authorized_keys2"} {
			relPath := filepath.Join(relHome, ".ssh", name)
			if err := collectSSHAuthorizedKeysFile(filepath.Join(root, relPath), relPath, user.Username, result); err != nil {
				return err
			}
		}
	}
	return nil
}

func collectSSHAuthorizedKeysFile(absPath string, relPath string, user string, result *Result) error {
	entries, err := readSSHAuthorizedKeys(absPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	for _, entry := range entries {
		config := map[string][]string{
			"keyType":     {entry.KeyType},
			"fingerprint": {entry.Fingerprint},
		}
		if entry.Comment != "" {
			config["comment"] = []string{entry.Comment}
		}
		for key, value := range entry.Options {
			config["option:"+key] = []string{value}
		}
		command := entry.Options["command"]
		result.PersistenceItems = append(result.PersistenceItems, PersistenceItem{
			Kind:             "ssh_authorized_key",
			Name:             user + ":" + filepath.Base(relPath) + ":" + strconv.Itoa(entry.Line),
			Source:           relPath,
			Command:          command,
			SourceType:       "ssh_authorized_key",
			EnabledState:     "configured",
			ActiveState:      "unavailable_offline_root",
			User:             user,
			SecurityFindings: sshAuthorizedKeyFindings(entry),
			Config:           config,
		})
	}
	if len(entries) > 0 {
		result.Sources = append(result.Sources, relPath)
	}
	return nil
}

type sshAuthorizedKeyEntry struct {
	Line        int
	KeyType     string
	Comment     string
	Fingerprint string
	Options     map[string]string
}

func readSSHAuthorizedKeys(path string) ([]sshAuthorizedKeyEntry, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var entries []sshAuthorizedKeyEntry
	scanner := bufio.NewScanner(file)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		entry, ok := parseSSHAuthorizedKeyLine(scanner.Text())
		if !ok {
			continue
		}
		entry.Line = lineNumber
		entries = append(entries, entry)
	}
	return entries, scanner.Err()
}

func parseSSHAuthorizedKeyLine(line string) (sshAuthorizedKeyEntry, bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return sshAuthorizedKeyEntry{}, false
	}
	fields := strings.Fields(trimmed)
	keyIndex := -1
	for index, field := range fields {
		if isSSHKeyType(field) {
			keyIndex = index
			break
		}
	}
	if keyIndex < 0 || keyIndex+1 >= len(fields) {
		return sshAuthorizedKeyEntry{}, false
	}
	entry := sshAuthorizedKeyEntry{
		KeyType:     fields[keyIndex],
		Fingerprint: sshKeyFingerprint(fields[keyIndex+1]),
		Options:     map[string]string{},
	}
	if keyIndex > 0 {
		entry.Options = parseSSHAuthorizedKeyOptions(strings.Join(fields[:keyIndex], " "))
	}
	if keyIndex+2 < len(fields) {
		entry.Comment = strings.Join(fields[keyIndex+2:], " ")
	}
	return entry, true
}

func isSSHKeyType(value string) bool {
	return strings.HasPrefix(value, "ssh-") ||
		strings.HasPrefix(value, "ecdsa-") ||
		strings.HasPrefix(value, "sk-ssh-") ||
		strings.HasPrefix(value, "sk-ecdsa-")
}

func parseSSHAuthorizedKeyOptions(value string) map[string]string {
	options := map[string]string{}
	for _, option := range splitSSHOptions(value) {
		key, optionValue, ok := strings.Cut(option, "=")
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		if ok {
			options[key] = strings.Trim(optionValue, `"`)
		} else {
			options[key] = "true"
		}
	}
	return options
}

func splitSSHOptions(value string) []string {
	var options []string
	var current strings.Builder
	inQuotes := false
	escaped := false
	for _, char := range value {
		switch {
		case escaped:
			current.WriteRune(char)
			escaped = false
		case char == '\\' && inQuotes:
			escaped = true
		case char == '"':
			inQuotes = !inQuotes
			current.WriteRune(char)
		case char == ',' && !inQuotes:
			options = append(options, strings.TrimSpace(current.String()))
			current.Reset()
		default:
			current.WriteRune(char)
		}
	}
	if strings.TrimSpace(current.String()) != "" {
		options = append(options, strings.TrimSpace(current.String()))
	}
	return options
}

func sshKeyFingerprint(keyMaterial string) string {
	decoded, err := base64.StdEncoding.DecodeString(keyMaterial)
	if err != nil || len(decoded) == 0 {
		return ""
	}
	sum := sha256.Sum256(decoded)
	return "SHA256:" + strings.TrimRight(base64.StdEncoding.EncodeToString(sum[:]), "=")
}

func sshAuthorizedKeyFindings(entry sshAuthorizedKeyEntry) []SSHConfigFinding {
	var findings []SSHConfigFinding
	if command := entry.Options["command"]; command != "" {
		findings = append(findings, SSHConfigFinding{
			Key:      "command",
			Value:    command,
			Severity: "high",
			Reason:   "ssh_authorized_key_forced_command",
			Line:     entry.Line,
		})
		if suspiciousCommandPath(command) {
			findings = append(findings, SSHConfigFinding{
				Key:      "command",
				Value:    command,
				Severity: "high",
				Reason:   "ssh_authorized_key_temp_command",
				Line:     entry.Line,
			})
		}
	}
	if from := entry.Options["from"]; from != "" {
		findings = append(findings, SSHConfigFinding{
			Key:      "from",
			Value:    from,
			Severity: "info",
			Reason:   "ssh_authorized_key_source_restriction",
			Line:     entry.Line,
		})
	}
	return findings
}

func suspiciousCommandPath(command string) bool {
	fields := strings.Fields(strings.TrimSpace(command))
	if len(fields) == 0 {
		return false
	}
	executable := strings.Trim(fields[0], `"'`)
	return strings.HasPrefix(executable, "/tmp/") ||
		strings.HasPrefix(executable, "/var/tmp/") ||
		strings.HasPrefix(executable, "/dev/shm/")
}

func collectDynamicLoaderPreload(root string, result *Result) error {
	relPath := filepath.Join("etc", "ld.so.preload")
	file, err := os.Open(filepath.Join(root, relPath))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	defer file.Close()

	var found bool
	scanner := bufio.NewScanner(file)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		found = true
		result.PersistenceItems = append(result.PersistenceItems, PersistenceItem{
			Kind:         "ld_preload",
			Name:         "ld.so.preload:" + strconv.Itoa(lineNumber),
			Source:       relPath,
			Command:      line,
			SourceType:   "ld_preload",
			EnabledState: "configured",
			User:         "root",
			SecurityFindings: []SSHConfigFinding{
				{
					Key:      "ld.so.preload",
					Value:    line,
					Severity: "high",
					Reason:   "dynamic_loader_preload",
					Line:     lineNumber,
				},
			},
		})
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if found {
		result.Sources = append(result.Sources, relPath)
	}
	return nil
}

func collectUdevRules(root string, result *Result) error {
	for _, relDir := range []string{
		filepath.Join("etc", "udev", "rules.d"),
		filepath.Join("run", "udev", "rules.d"),
		filepath.Join("usr", "lib", "udev", "rules.d"),
		filepath.Join("lib", "udev", "rules.d"),
	} {
		if err := collectUdevRuleDirectory(root, relDir, result); err != nil {
			return err
		}
	}
	return nil
}

func collectUdevRuleDirectory(root string, relDir string, result *Result) error {
	absDir := filepath.Join(root, relDir)
	entries, err := os.ReadDir(absDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") || !strings.HasSuffix(entry.Name(), ".rules") {
			continue
		}
		relPath := filepath.Join(relDir, entry.Name())
		if err := collectUdevRuleFile(filepath.Join(absDir, entry.Name()), relPath, result); err != nil {
			return err
		}
	}
	return nil
}

func collectUdevRuleFile(absPath string, relPath string, result *Result) error {
	file, err := os.Open(absPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	defer file.Close()

	var found bool
	scanner := bufio.NewScanner(file)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		config := parseUdevRuleLine(scanner.Text())
		runCommands := config["run"]
		if len(runCommands) == 0 {
			continue
		}
		found = true
		for _, command := range runCommands {
			result.PersistenceItems = append(result.PersistenceItems, PersistenceItem{
				Kind:             "udev_rule",
				Name:             filepath.Base(relPath) + ":" + strconv.Itoa(lineNumber),
				Source:           relPath,
				Command:          command,
				SourceType:       "udev_rule",
				EnabledState:     "configured",
				ActiveState:      "unavailable_offline_root",
				User:             "root",
				SecurityFindings: udevRuleFindings(command, lineNumber),
				Config:           config,
			})
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if found {
		result.Sources = append(result.Sources, relPath)
	}
	return nil
}

func parseUdevRuleLine(line string) map[string][]string {
	config := map[string][]string{}
	line = stripInlineComment(line)
	if line == "" {
		return config
	}
	for _, token := range splitUdevRuleTokens(line) {
		key, value, ok := splitUdevRuleToken(token)
		if !ok {
			continue
		}
		config[key] = append(config[key], value)
	}
	return config
}

func splitUdevRuleTokens(line string) []string {
	var tokens []string
	var current strings.Builder
	inQuote := false
	for _, r := range line {
		switch r {
		case '"':
			inQuote = !inQuote
			current.WriteRune(r)
		case ',':
			if inQuote {
				current.WriteRune(r)
				continue
			}
			if token := strings.TrimSpace(current.String()); token != "" {
				tokens = append(tokens, token)
			}
			current.Reset()
		default:
			current.WriteRune(r)
		}
	}
	if token := strings.TrimSpace(current.String()); token != "" {
		tokens = append(tokens, token)
	}
	return tokens
}

func splitUdevRuleToken(token string) (string, string, bool) {
	for _, op := range []string{"+=", "==", ":=", "="} {
		key, value, ok := strings.Cut(token, op)
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.Trim(strings.TrimSpace(value), `"`)
		if key == "" || value == "" {
			return "", "", false
		}
		return udevConfigKey(key), value, true
	}
	return "", "", false
}

func udevConfigKey(key string) string {
	key = strings.TrimSpace(key)
	key = strings.TrimPrefix(key, "ENV{")
	key = strings.TrimSuffix(key, "}")
	switch strings.ToUpper(key) {
	case "ACTION":
		return "action"
	case "SUBSYSTEM":
		return "subsystem"
	case "KERNEL":
		return "kernel"
	case "RUN":
		return "run"
	case "PROGRAM":
		return "program"
	case "IMPORT":
		return "import"
	case "SYMLINK":
		return "symlink"
	default:
		return strings.ToLower(key)
	}
}

func udevRuleFindings(command string, lineNumber int) []SSHConfigFinding {
	findings := []SSHConfigFinding{
		{Key: "RUN", Value: command, Severity: "medium", Reason: "udev_run_hook", Line: lineNumber},
	}
	if containsTempExecutionPath(command) {
		findings = append(findings, SSHConfigFinding{Key: "RUN", Value: command, Severity: "high", Reason: "udev_temp_path", Line: lineNumber})
	}
	if strings.Contains(command, "curl ") || strings.Contains(command, "wget ") || strings.Contains(command, "nc ") || strings.Contains(command, "ncat ") || strings.Contains(command, "socat ") {
		findings = append(findings, SSHConfigFinding{Key: "RUN", Value: command, Severity: "high", Reason: "udev_network_tool", Line: lineNumber})
	}
	return findings
}

func collectKernelModules(root string, result *Result) error {
	if err := collectLoadedKernelModules(root, result); err != nil {
		return err
	}
	if err := collectModuleLoadDirectories(root, result); err != nil {
		return err
	}
	return collectModprobePolicies(root, result)
}

func collectLoadedKernelModules(root string, result *Result) error {
	relPath := filepath.Join("proc", "modules")
	file, err := os.Open(filepath.Join(root, relPath))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	defer file.Close()

	var found bool
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 5 {
			continue
		}
		found = true
		moduleEvidence := collectLoadedModuleEvidence(root, fields[0])
		result.PersistenceItems = append(result.PersistenceItems, PersistenceItem{
			Kind:             "kernel_module_loaded",
			Name:             fields[0],
			Source:           relPath,
			Command:          "size=" + fields[1] + "; used_by=" + fields[2] + "; state=" + fields[4],
			SourceType:       "kernel_module_loaded",
			EnabledState:     "loaded",
			ActiveState:      fields[4],
			User:             "root",
			SecurityFindings: moduleEvidence.findings,
			Config:           moduleEvidence.config,
		})
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if found {
		result.Sources = append(result.Sources, relPath)
	}
	return nil
}

type loadedModuleEvidence struct {
	config   map[string][]string
	findings []SSHConfigFinding
}

func collectLoadedModuleEvidence(root string, moduleName string) loadedModuleEvidence {
	relDir := filepath.Join("sys", "module", moduleName)
	absDir := filepath.Join(root, relDir)
	config := map[string][]string{}
	addConfigValue(config, "initState", readTrimmed(filepath.Join(absDir, "initstate")))
	addConfigValue(config, "refcnt", readTrimmed(filepath.Join(absDir, "refcnt")))
	taint := readTrimmed(filepath.Join(absDir, "taint"))
	addConfigValue(config, "taint", taint)
	for key, value := range readModuleParameters(filepath.Join(absDir, "parameters")) {
		addConfigValue(config, "parameter:"+key, value)
	}
	return loadedModuleEvidence{
		config:   config,
		findings: moduleTaintFindings(moduleName, taint),
	}
}

func readModuleParameters(absDir string) map[string]string {
	entries, err := os.ReadDir(absDir)
	if err != nil {
		return map[string]string{}
	}
	values := map[string]string{}
	for _, entry := range entries {
		if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		value := readTrimmed(filepath.Join(absDir, entry.Name()))
		if value != "" {
			values[entry.Name()] = value
		}
	}
	return values
}

func addConfigValue(config map[string][]string, key string, value string) {
	if strings.TrimSpace(value) == "" {
		return
	}
	config[key] = []string{value}
}

func readTrimmed(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func moduleTaintFindings(moduleName string, taint string) []SSHConfigFinding {
	var findings []SSHConfigFinding
	if strings.Contains(taint, "O") {
		findings = append(findings, SSHConfigFinding{
			Key:      "module_taint",
			Value:    moduleName,
			Severity: "medium",
			Reason:   "kernel_module_out_of_tree",
		})
	}
	if strings.Contains(taint, "E") {
		findings = append(findings, SSHConfigFinding{
			Key:      "module_taint",
			Value:    moduleName,
			Severity: "high",
			Reason:   "kernel_module_unsigned",
		})
	}
	if strings.Contains(taint, "P") {
		findings = append(findings, SSHConfigFinding{
			Key:      "module_taint",
			Value:    moduleName,
			Severity: "medium",
			Reason:   "kernel_module_proprietary",
		})
	}
	if strings.Contains(taint, "F") {
		findings = append(findings, SSHConfigFinding{
			Key:      "module_taint",
			Value:    moduleName,
			Severity: "high",
			Reason:   "kernel_module_forced_load",
		})
	}
	return findings
}

func collectModuleLoadDirectories(root string, result *Result) error {
	for _, relDir := range []string{
		filepath.Join("etc", "modules-load.d"),
		filepath.Join("run", "modules-load.d"),
		filepath.Join("usr", "lib", "modules-load.d"),
	} {
		if err := collectModuleLoadDirectory(root, relDir, result); err != nil {
			return err
		}
	}
	return nil
}

func collectModuleLoadDirectory(root string, relDir string, result *Result) error {
	absDir := filepath.Join(root, relDir)
	entries, err := os.ReadDir(absDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") || !strings.HasSuffix(entry.Name(), ".conf") {
			continue
		}
		relPath := filepath.Join(relDir, entry.Name())
		if err := collectModuleLoadFile(filepath.Join(absDir, entry.Name()), relPath, result); err != nil {
			return err
		}
	}
	return nil
}

func collectModuleLoadFile(absPath string, relPath string, result *Result) error {
	file, err := os.Open(absPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	defer file.Close()

	var found bool
	scanner := bufio.NewScanner(file)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := stripInlineComment(scanner.Text())
		if line == "" {
			continue
		}
		moduleName := strings.Fields(line)[0]
		found = true
		result.PersistenceItems = append(result.PersistenceItems, PersistenceItem{
			Kind:         "kernel_module_autoload",
			Name:         moduleName,
			Source:       relPath,
			Command:      moduleName,
			SourceType:   "kernel_module_autoload",
			EnabledState: "configured",
			User:         "root",
			SecurityFindings: []SSHConfigFinding{
				{
					Key:      "modules-load",
					Value:    moduleName,
					Severity: "medium",
					Reason:   "kernel_module_autoload",
					Line:     lineNumber,
				},
			},
		})
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if found {
		result.Sources = append(result.Sources, relPath)
	}
	return nil
}

func collectModprobePolicies(root string, result *Result) error {
	for _, relDir := range []string{
		filepath.Join("etc", "modprobe.d"),
		filepath.Join("run", "modprobe.d"),
		filepath.Join("usr", "lib", "modprobe.d"),
	} {
		if err := collectModprobeDirectory(root, relDir, result); err != nil {
			return err
		}
	}
	return nil
}

func collectModprobeDirectory(root string, relDir string, result *Result) error {
	absDir := filepath.Join(root, relDir)
	entries, err := os.ReadDir(absDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") || !strings.HasSuffix(entry.Name(), ".conf") {
			continue
		}
		relPath := filepath.Join(relDir, entry.Name())
		if err := collectModprobeFile(filepath.Join(absDir, entry.Name()), relPath, result); err != nil {
			return err
		}
	}
	return nil
}

func collectModprobeFile(absPath string, relPath string, result *Result) error {
	file, err := os.Open(absPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	defer file.Close()

	var found bool
	scanner := bufio.NewScanner(file)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := stripInlineComment(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		directive := fields[0]
		switch directive {
		case "install":
			if len(fields) < 3 {
				continue
			}
			found = true
			moduleName := fields[1]
			command := strings.Join(fields[2:], " ")
			result.PersistenceItems = append(result.PersistenceItems, PersistenceItem{
				Kind:         "modprobe_policy",
				Name:         "install:" + moduleName,
				Source:       relPath,
				Command:      command,
				SourceType:   "modprobe_policy",
				EnabledState: "configured",
				User:         "root",
				SecurityFindings: []SSHConfigFinding{
					{
						Key:      "install",
						Value:    moduleName,
						Severity: "high",
						Reason:   "modprobe_install_hook",
						Line:     lineNumber,
					},
				},
			})
		case "blacklist":
			found = true
			moduleName := fields[1]
			result.PersistenceItems = append(result.PersistenceItems, PersistenceItem{
				Kind:         "modprobe_policy",
				Name:         "blacklist:" + moduleName,
				Source:       relPath,
				Command:      moduleName,
				SourceType:   "modprobe_policy",
				EnabledState: "configured",
				User:         "root",
			})
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if found {
		result.Sources = append(result.Sources, relPath)
	}
	return nil
}

func stripInlineComment(line string) string {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return ""
	}
	if before, _, ok := strings.Cut(trimmed, "#"); ok {
		return strings.TrimSpace(before)
	}
	return trimmed
}

func collectShellStartup(root string, result *Result) error {
	for _, relPath := range []string{
		filepath.Join("etc", "profile"),
		filepath.Join("etc", "bash.bashrc"),
		filepath.Join("etc", "zsh", "zshrc"),
	} {
		if err := collectShellStartupFile(filepath.Join(root, relPath), relPath, "root", result); err != nil {
			return err
		}
	}
	if err := collectShellStartupDirectory(filepath.Join(root, "etc", "profile.d"), filepath.Join("etc", "profile.d"), "root", result); err != nil {
		return err
	}
	users, err := readPasswdUsers(filepath.Join(root, "etc", "passwd"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	for _, user := range users {
		if user.Home == "" || user.Home == "/nonexistent" {
			continue
		}
		relHome := strings.TrimPrefix(user.Home, string(filepath.Separator))
		for _, name := range []string{".profile", ".bash_profile", ".bash_login", ".bashrc", ".zprofile", ".zshrc"} {
			relPath := filepath.Join(relHome, name)
			if err := collectShellStartupFile(filepath.Join(root, relPath), relPath, user.Username, result); err != nil {
				return err
			}
		}
	}
	return nil
}

func collectLegacyStartup(root string, result *Result) error {
	if err := collectRcLocal(root, result); err != nil {
		return err
	}
	return collectInitD(root, result)
}

func collectDesktopAutostart(root string, result *Result) error {
	if err := collectDesktopAutostartDirectory(filepath.Join(root, "etc", "xdg", "autostart"), filepath.Join("etc", "xdg", "autostart"), "root", result); err != nil {
		return err
	}
	users, err := readPasswdUsers(filepath.Join(root, "etc", "passwd"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	for _, user := range users {
		if user.Home == "" || user.Home == "/nonexistent" {
			continue
		}
		relDir := filepath.Join(strings.TrimPrefix(user.Home, string(filepath.Separator)), ".config", "autostart")
		if err := collectDesktopAutostartDirectory(filepath.Join(root, relDir), relDir, user.Username, result); err != nil {
			return err
		}
	}
	return nil
}

func collectDesktopAutostartDirectory(absDir string, relDir string, user string, result *Result) error {
	entries, err := os.ReadDir(absDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".desktop") {
			continue
		}
		relPath := filepath.Join(relDir, entry.Name())
		if err := collectDesktopAutostartFile(filepath.Join(absDir, entry.Name()), relPath, user, result); err != nil {
			return err
		}
	}
	return nil
}

func collectDesktopAutostartFile(absPath string, relPath string, user string, result *Result) error {
	data, err := parseUnitFile(absPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	execStart := data["Desktop Entry"]["Exec"]
	if strings.TrimSpace(execStart) == "" {
		return nil
	}
	result.PersistenceItems = append(result.PersistenceItems, PersistenceItem{
		Kind:       "desktop_autostart",
		Name:       filepath.Base(relPath),
		Source:     relPath,
		Command:    execStart,
		SourceType: "desktop_autostart",
		User:       user,
	})
	result.Sources = append(result.Sources, relPath)
	return nil
}

func collectRcLocal(root string, result *Result) error {
	relPath := filepath.Join("etc", "rc.local")
	commands, err := readShellStartupCommands(filepath.Join(root, relPath))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if len(commands) == 0 {
		return nil
	}
	result.PersistenceItems = append(result.PersistenceItems, PersistenceItem{
		Kind:       "legacy_startup",
		Name:       "rc.local",
		Source:     relPath,
		Command:    commands[0].Command,
		SourceType: "legacy_startup",
		User:       "root",
	})
	result.Sources = append(result.Sources, relPath)
	return nil
}

func collectInitD(root string, result *Result) error {
	relDir := filepath.Join("etc", "init.d")
	absDir := filepath.Join(root, relDir)
	entries, err := os.ReadDir(absDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") || strings.HasPrefix(entry.Name(), "README") {
			continue
		}
		relPath := filepath.Join(relDir, entry.Name())
		result.PersistenceItems = append(result.PersistenceItems, PersistenceItem{
			Kind:       "legacy_startup",
			Name:       entry.Name(),
			Source:     relPath,
			Command:    filepath.Join(string(filepath.Separator), relPath),
			SourceType: "legacy_startup",
			User:       "root",
		})
		result.Sources = append(result.Sources, relPath)
	}
	return nil
}

func collectShellStartupDirectory(absDir string, relDir string, user string, result *Result) error {
	entries, err := os.ReadDir(absDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		relPath := filepath.Join(relDir, entry.Name())
		if err := collectShellStartupFile(filepath.Join(absDir, entry.Name()), relPath, user, result); err != nil {
			return err
		}
	}
	return nil
}

func collectShellStartupFile(absPath string, relPath string, user string, result *Result) error {
	commands, err := readShellStartupCommands(absPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	for _, command := range commands {
		kind := "shell_startup"
		name := filepath.Base(relPath) + ":" + command.Line
		if command.Kind != "" {
			kind = command.Kind
		}
		if command.AliasName != "" {
			name = name + ":" + command.AliasName
		}
		result.PersistenceItems = append(result.PersistenceItems, PersistenceItem{
			Kind:             kind,
			Name:             name,
			Source:           relPath,
			Command:          command.Command,
			SourceType:       kind,
			User:             user,
			SecurityFindings: command.SecurityFindings,
			Config:           command.Config,
		})
	}
	if len(commands) > 0 {
		result.Sources = append(result.Sources, relPath)
	}
	return nil
}

type shellStartupCommand struct {
	Line             string
	Command          string
	Kind             string
	AliasName        string
	ReferenceName    string
	SecurityFindings []SSHConfigFinding
	Config           map[string][]string
}

func readShellStartupCommands(path string) ([]shellStartupCommand, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var commands []shellStartupCommand
	scanner := bufio.NewScanner(file)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		command, ok := parseShellStartupLine(scanner.Text())
		if !ok {
			continue
		}
		command.Line = strconv.Itoa(lineNumber)
		commands = append(commands, command)
	}
	return commands, scanner.Err()
}

func parseShellStartupLine(line string) (shellStartupCommand, bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return shellStartupCommand{}, false
	}
	if aliasName, ok := parseShellAlias(trimmed); ok {
		aliasTarget := parseShellAliasTarget(trimmed)
		return shellStartupCommand{
			Command:          trimmed,
			Kind:             "shell_alias",
			AliasName:        aliasName,
			Config:           shellAliasConfig(aliasName, aliasTarget),
			SecurityFindings: shellAliasFindings(aliasName, aliasTarget),
		}, true
	}
	if target, ok := parseShellSource(trimmed); ok {
		return shellStartupCommand{
			Command:       trimmed,
			Kind:          "shell_source",
			AliasName:     filepath.Base(target),
			ReferenceName: target,
			Config:        map[string][]string{"target": {target}},
		}, true
	}
	if functionName, ok := parseShellFunction(trimmed); ok {
		return shellStartupCommand{
			Command:   trimmed,
			Kind:      "shell_function",
			AliasName: functionName,
			Config:    map[string][]string{"function": {functionName}},
		}, true
	}
	if pathEntries, ok := parseShellPathAssignment(trimmed); ok {
		findings := shellPathFindings(pathEntries)
		return shellStartupCommand{
			Command:          trimmed,
			Kind:             "shell_path",
			AliasName:        "PATH",
			Config:           map[string][]string{"pathEntry": pathEntries},
			SecurityFindings: findings,
		}, true
	}
	fields := strings.Fields(trimmed)
	if len(fields) == 0 {
		return shellStartupCommand{}, false
	}
	switch fields[0] {
	case "export", "alias", "unalias", "source", ".", "if", "then", "fi", "case", "esac", "for", "do", "done", "function":
		return shellStartupCommand{}, false
	}
	if strings.Contains(fields[0], "=") && !strings.Contains(fields[0], "/") {
		return shellStartupCommand{}, false
	}
	return shellStartupCommand{Command: trimmed, Kind: "shell_startup"}, true
}

func parseShellAlias(line string) (string, bool) {
	rest := strings.TrimSpace(strings.TrimPrefix(line, "alias"))
	if rest == line || rest == "" {
		return "", false
	}
	name, _, ok := strings.Cut(rest, "=")
	name = strings.TrimSpace(name)
	if !ok || name == "" || strings.ContainsAny(name, " \t/") {
		return "", false
	}
	return name, true
}

func parseShellAliasTarget(line string) string {
	rest := strings.TrimSpace(strings.TrimPrefix(line, "alias"))
	_, value, ok := strings.Cut(rest, "=")
	if !ok {
		return ""
	}
	value = strings.TrimSpace(value)
	return strings.Trim(value, `"'`)
}

func shellAliasConfig(aliasName string, aliasTarget string) map[string][]string {
	config := map[string][]string{"alias": {aliasName}}
	if aliasTarget != "" {
		config["aliasTarget"] = []string{aliasTarget}
		if fields := strings.Fields(aliasTarget); len(fields) > 0 {
			config["aliasCommand"] = []string{fields[0]}
		}
	}
	return config
}

func shellAliasFindings(aliasName string, aliasTarget string) []SSHConfigFinding {
	var findings []SSHConfigFinding
	normalizedName := strings.ToLower(aliasName)
	normalizedTarget := strings.ToLower(strings.TrimSpace(aliasTarget))
	if isPrivilegedShellAlias(normalizedName) {
		findings = append(findings, SSHConfigFinding{
			Key:      "alias",
			Value:    aliasName,
			Severity: "high",
			Reason:   "shell_alias_privileged_command_override",
		})
	}
	if aliasTargetPathSuspicious(normalizedTarget) {
		findings = append(findings, SSHConfigFinding{
			Key:      "aliasTarget",
			Value:    aliasTarget,
			Severity: "medium",
			Reason:   "shell_alias_suspicious_target_path",
		})
	}
	return findings
}

func isPrivilegedShellAlias(aliasName string) bool {
	switch aliasName {
	case "sudo", "su", "ssh", "scp", "sftp", "curl", "wget", "bash", "sh", "zsh", "python", "python3", "perl", "ruby", "nc", "ncat", "socat", "ps", "top", "ls", "cat", "grep", "find":
		return true
	default:
		return false
	}
}

func aliasTargetPathSuspicious(target string) bool {
	if target == "" {
		return false
	}
	fields := strings.Fields(target)
	if len(fields) == 0 {
		return false
	}
	command := strings.Trim(fields[0], `"'`)
	return strings.HasPrefix(command, "/tmp/") ||
		strings.HasPrefix(command, "/var/tmp/") ||
		strings.HasPrefix(command, "/dev/shm/") ||
		strings.HasPrefix(command, "/home/")
}

func parseShellSource(line string) (string, bool) {
	fields := strings.Fields(line)
	if len(fields) < 2 || (fields[0] != "source" && fields[0] != ".") {
		return "", false
	}
	target := strings.Trim(fields[1], `"'`)
	if target == "" || strings.HasPrefix(target, "-") {
		return "", false
	}
	return target, true
}

func parseShellFunction(line string) (string, bool) {
	fields := strings.Fields(line)
	if len(fields) >= 2 && fields[0] == "function" {
		name := strings.TrimSuffix(fields[1], "()")
		name = strings.TrimSpace(strings.TrimRight(name, "{"))
		if validShellName(name) {
			return name, true
		}
	}
	if before, _, ok := strings.Cut(line, "()"); ok {
		name := strings.TrimSpace(before)
		if validShellName(name) {
			return name, true
		}
	}
	if before, _, ok := strings.Cut(line, "(){"); ok {
		name := strings.TrimSpace(before)
		if validShellName(name) {
			return name, true
		}
	}
	return "", false
}

func parseShellPathAssignment(line string) ([]string, bool) {
	assignment := strings.TrimSpace(line)
	if strings.HasPrefix(assignment, "export ") {
		assignment = strings.TrimSpace(strings.TrimPrefix(assignment, "export "))
	}
	if !strings.HasPrefix(assignment, "PATH=") {
		return nil, false
	}
	value := strings.TrimSpace(strings.TrimPrefix(assignment, "PATH="))
	value = strings.Trim(value, `"'`)
	var entries []string
	for _, entry := range strings.Split(value, ":") {
		entry = strings.TrimSpace(entry)
		if entry == "" || entry == "$PATH" || entry == "${PATH}" {
			continue
		}
		entries = append(entries, entry)
	}
	return entries, len(entries) > 0
}

func shellPathFindings(entries []string) []SSHConfigFinding {
	var findings []SSHConfigFinding
	for _, entry := range entries {
		normalized := strings.TrimRight(entry, string(filepath.Separator))
		switch {
		case normalized == "/tmp" || strings.HasPrefix(normalized, "/tmp/") ||
			normalized == "/var/tmp" || strings.HasPrefix(normalized, "/var/tmp/") ||
			normalized == "/dev/shm" || strings.HasPrefix(normalized, "/dev/shm/"):
			findings = append(findings, SSHConfigFinding{
				Key:      "PATH",
				Value:    entry,
				Severity: "high",
				Reason:   "shell_path_temp_directory",
			})
		case strings.HasPrefix(normalized, ".") || !strings.HasPrefix(normalized, "/") && !strings.HasPrefix(normalized, "$"):
			findings = append(findings, SSHConfigFinding{
				Key:      "PATH",
				Value:    entry,
				Severity: "medium",
				Reason:   "shell_path_relative_directory",
			})
		}
	}
	return findings
}

func validShellName(name string) bool {
	if name == "" {
		return false
	}
	for index, char := range name {
		if index == 0 {
			if !(char == '_' || char >= 'A' && char <= 'Z' || char >= 'a' && char <= 'z') {
				return false
			}
			continue
		}
		if !(char == '_' || char >= 'A' && char <= 'Z' || char >= 'a' && char <= 'z' || char >= '0' && char <= '9') {
			return false
		}
	}
	return true
}

type passwdUser struct {
	Username string
	Home     string
}

func readPasswdUsers(path string) ([]passwdUser, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var users []passwdUser
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ":")
		if len(fields) < 6 {
			continue
		}
		users = append(users, passwdUser{Username: fields[0], Home: fields[5]})
	}
	return users, scanner.Err()
}

func parseSSHDConfig(path string) (map[string][]string, []SSHConfigFinding, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()

	config := map[string][]string{}
	lineByKey := map[string]int{}
	scanner := bufio.NewScanner(file)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := splitSSHDDirective(line)
		if !ok {
			continue
		}
		config[key] = append(config[key], value)
		if _, exists := lineByKey[key]; !exists {
			lineByKey[key] = lineNumber
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}
	return config, sshdConfigFindings(config, lineByKey), nil
}

func splitSSHDDirective(line string) (string, string, bool) {
	key, value, ok := strings.Cut(line, " ")
	if !ok {
		key, value, ok = strings.Cut(line, "\t")
	}
	if !ok {
		return "", "", false
	}
	key = strings.TrimSpace(key)
	value = strings.TrimSpace(value)
	if key == "" || value == "" {
		return "", "", false
	}
	return key, value, true
}

func sshdConfigFindings(config map[string][]string, lineByKey map[string]int) []SSHConfigFinding {
	var findings []SSHConfigFinding
	if value := lastConfigValue(config, "PermitRootLogin"); strings.EqualFold(value, "yes") || strings.EqualFold(value, "without-password") || strings.EqualFold(value, "prohibit-password") {
		findings = append(findings, SSHConfigFinding{Key: "PermitRootLogin", Value: value, Severity: "high", Reason: "root_login_enabled", Line: lineByKey["PermitRootLogin"]})
	}
	if value := lastConfigValue(config, "PasswordAuthentication"); strings.EqualFold(value, "yes") {
		findings = append(findings, SSHConfigFinding{Key: "PasswordAuthentication", Value: value, Severity: "medium", Reason: "password_authentication_enabled", Line: lineByKey["PasswordAuthentication"]})
	}
	if value := lastConfigValue(config, "AuthorizedKeysFile"); strings.TrimSpace(value) != "" {
		findings = append(findings, SSHConfigFinding{Key: "AuthorizedKeysFile", Value: value, Severity: "info", Reason: "authorized_keys_paths_declared", Line: lineByKey["AuthorizedKeysFile"]})
	}
	return findings
}

func lastConfigValue(config map[string][]string, key string) string {
	values := config[key]
	if len(values) == 0 {
		return ""
	}
	return values[len(values)-1]
}

func sshdConfigSummary(config map[string][]string) string {
	parts := []string{}
	for _, key := range []string{"Port", "PermitRootLogin", "PasswordAuthentication", "AuthorizedKeysFile"} {
		if value := lastConfigValue(config, key); value != "" {
			parts = append(parts, key+"="+value)
		}
	}
	return strings.Join(parts, "; ")
}

func sortResult(result *Result) {
	sort.Slice(result.Services, func(i, j int) bool { return result.Services[i].Source < result.Services[j].Source })
	sort.Slice(result.Timers, func(i, j int) bool { return result.Timers[i].Source < result.Timers[j].Source })
	sort.Slice(result.CronJobs, func(i, j int) bool {
		left := result.CronJobs[i]
		right := result.CronJobs[j]
		return left.Source+"|"+left.User+"|"+left.Command < right.Source+"|"+right.User+"|"+right.Command
	})
	sort.Slice(result.PersistenceItems, func(i, j int) bool {
		left := result.PersistenceItems[i]
		right := result.PersistenceItems[j]
		return left.Kind+"|"+left.Source+"|"+left.Name < right.Kind+"|"+right.Source+"|"+right.Name
	})
	sort.Strings(result.Sources)
}
