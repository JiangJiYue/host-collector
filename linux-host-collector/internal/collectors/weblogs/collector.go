package weblogs

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"collector-shared/weblogdiscovery"
	"linux-host-collector/internal/collectors/network"
	"linux-host-collector/internal/collectors/process"
)

type Config struct {
	Root        string
	Processes   []process.Process
	Connections []network.Connection
}

type Result struct {
	Sources []Source `json:"webLogSources"`
	Entries []Entry  `json:"webLogEntries"`
}

type Source struct {
	ID           string   `json:"id"`
	Path         string   `json:"path"`
	ServerType   string   `json:"serverType,omitempty"`
	Format       string   `json:"format,omitempty"`
	Port         int      `json:"port,omitempty"`
	SourceMethod string   `json:"sourceMethod,omitempty"`
	Confidence   string   `json:"confidence,omitempty"`
	Evidence     []string `json:"evidence,omitempty"`
	Size         int64    `json:"size,omitempty"`
	ModifiedAt   string   `json:"modifiedAt,omitempty"`
}

type Entry struct {
	SourceID    string `json:"sourceId"`
	Timestamp   string `json:"timestamp,omitempty"`
	ClientIP    string `json:"clientIp,omitempty"`
	Method      string `json:"method,omitempty"`
	URI         string `json:"uri,omitempty"`
	Status      int    `json:"status,omitempty"`
	BytesSent   int64  `json:"bytesSent,omitempty"`
	UserAgent   string `json:"userAgent,omitempty"`
	Referer     string `json:"referer,omitempty"`
	Protocol    string `json:"protocol,omitempty"`
	ServerType  string `json:"serverType,omitempty"`
	ProcessName string `json:"processName,omitempty"`
	ProcessPID  int    `json:"processPid,omitempty"`
}

type candidateSource struct {
	Path         string
	ServerType   string
	Port         int
	SourceMethod string
	Evidence     []string
	ProcessName  string
	ProcessPID   int
}

var combinedLogPattern = regexp.MustCompile(`^(\S+) \S+ \S+ \[([^\]]+)\] "([A-Z]+) ([^ ]+) ([^"]+)" (\d{3}) (\d+|-) "([^"]*)" "([^"]*)"$`)

func Collect(config Config) (Result, error) {
	candidates, err := discoverCandidates(config)
	if err != nil {
		return Result{}, err
	}
	var result Result
	seenSources := map[string]struct{}{}
	for _, candidate := range candidates {
		fsPath := rootPath(config.Root, candidate.Path)
		body, info, err := readExistingFile(fsPath)
		if err != nil {
			continue
		}
		format, confidence, evidence := fingerprintLog(candidate, string(body))
		if format == "" {
			continue
		}
		sourceID := stableSourceID(candidate.Path)
		if _, ok := seenSources[sourceID]; !ok {
			result.Sources = append(result.Sources, Source{
				ID:           sourceID,
				Path:         candidate.Path,
				ServerType:   candidate.ServerType,
				Format:       format,
				Port:         candidate.Port,
				SourceMethod: candidate.SourceMethod,
				Confidence:   confidence,
				Evidence:     uniqueSorted(append(evidence, candidate.Evidence...)),
				Size:         info.Size(),
				ModifiedAt:   info.ModTime().Format(time.RFC3339),
			})
			seenSources[sourceID] = struct{}{}
		}
		lines := strings.Split(strings.ReplaceAll(string(body), "\r\n", "\n"), "\n")
		for _, line := range lines {
			entry, ok := parseLogLine(sourceID, candidate, format, line)
			if ok {
				result.Entries = append(result.Entries, entry)
			}
		}
	}
	sort.Slice(result.Sources, func(i, j int) bool { return result.Sources[i].Path < result.Sources[j].Path })
	sort.Slice(result.Entries, func(i, j int) bool {
		return result.Entries[i].Timestamp+result.Entries[i].URI < result.Entries[j].Timestamp+result.Entries[j].URI
	})
	return result, nil
}

func fingerprintLog(candidate candidateSource, text string) (format string, confidence string, evidence []string) {
	if looksLikeCombinedLog(text) {
		return "combined", "high", []string{"COMBINED_LOG_PATTERN"}
	}
	if strings.TrimSpace(text) == "" && isAccessLogPath(candidate.Path) {
		return "unknown", "medium", []string{"WEB_LOG_PATH_HINT"}
	}
	return "", "", nil
}

func parseLogLine(sourceID string, source candidateSource, format string, line string) (Entry, bool) {
	if format == "combined" {
		return parseCombinedLine(sourceID, source, line)
	}
	return Entry{}, false
}

func discoverCandidates(config Config) ([]candidateSource, error) {
	runtimeCandidates := weblogdiscovery.BuildRuntimeCandidates(weblogdiscovery.Context{
		Platform:  weblogdiscovery.PlatformLinux,
		Processes: processSignals(config.Processes),
		Listeners: listenerSignals(config.Connections),
	})
	candidates := make([]candidateSource, 0)
	for _, candidate := range runtimeCandidates {
		port := 0
		if len(candidate.ListenPorts) > 0 {
			port = candidate.ListenPorts[0]
		}
		for _, hint := range candidate.ConfigHints {
			configPath := rootPath(config.Root, hint)
			if _, err := os.Stat(configPath); err != nil {
				continue
			}
			paths, err := discoverLogPaths(configPath, candidate.ServerType, config.Root)
			if err != nil {
				return nil, err
			}
			for _, path := range paths {
				candidates = append(candidates, candidateSource{
					Path:         cleanGuestPath(path),
					ServerType:   candidate.ServerType,
					Port:         port,
					SourceMethod: runtimeSourceMethod(candidate),
					Evidence:     append([]string(nil), candidate.Evidence...),
					ProcessName:  candidate.ProcessName,
					ProcessPID:   candidate.ProcessPID,
				})
			}
		}
	}
	panelCandidates, err := discoverPanelWebsiteLogCandidates(config.Root)
	if err != nil {
		return nil, err
	}
	candidates = append(candidates, panelCandidates...)
	candidates = append(candidates, discoverPHPStudyDefaultLogCandidates(config.Root)...)
	return dedupeSources(candidates), nil
}

func processSignals(processes []process.Process) []weblogdiscovery.ProcessSignal {
	signals := make([]weblogdiscovery.ProcessSignal, 0, len(processes))
	for _, item := range processes {
		signals = append(signals, weblogdiscovery.ProcessSignal{
			PID:         item.PID,
			Name:        item.Name,
			CommandLine: item.CommandLine,
		})
	}
	return signals
}

func listenerSignals(connections []network.Connection) []weblogdiscovery.ListenerSignal {
	signals := make([]weblogdiscovery.ListenerSignal, 0, len(connections))
	for _, connection := range connections {
		if !connection.Listen {
			continue
		}
		signals = append(signals, weblogdiscovery.ListenerSignal{Port: connection.LocalPort})
	}
	return signals
}

func discoverLogPaths(configPath string, serverType string, root string) ([]string, error) {
	switch strings.ToLower(serverType) {
	case "nginx":
		return discoverNginxLogPaths(configPath, map[string]struct{}{}, root)
	case "openresty":
		return discoverNginxLogPaths(configPath, map[string]struct{}{}, root)
	case "apache":
		return discoverApacheLogPaths(configPath, root)
	case "tomcat":
		return discoverTomcatLogPaths(configPath, root)
	default:
		return nil, nil
	}
}

func discoverPanelWebsiteLogCandidates(root string) ([]candidateSource, error) {
	var candidates []candidateSource
	baota, err := discoverBaoTaWebsiteLogCandidates(root)
	if err != nil {
		return nil, err
	}
	candidates = append(candidates, baota...)
	onePanel, err := discoverOnePanelWebsiteLogCandidates(root)
	if err != nil {
		return nil, err
	}
	candidates = append(candidates, onePanel...)
	return candidates, nil
}

func discoverBaoTaWebsiteLogCandidates(root string) ([]candidateSource, error) {
	type panelVhostRoot struct {
		path         string
		serverType   string
		sourceMethod string
		evidence     string
	}
	roots := []panelVhostRoot{
		{
			path:         "/www/server/panel/vhost/nginx",
			serverType:   "nginx",
			sourceMethod: "baotaPanelVhostConfig",
			evidence:     "BAOTA_PANEL_VHOST_CONFIG",
		},
		{
			path:         "/www/server/panel/vhost/apache",
			serverType:   "apache",
			sourceMethod: "baotaPanelVhostConfig",
			evidence:     "BAOTA_PANEL_VHOST_CONFIG",
		},
	}

	var candidates []candidateSource
	for _, vhostRoot := range roots {
		dir := rootPath(root, vhostRoot.path)
		if _, err := os.Stat(dir); err != nil {
			continue
		}
		configs, err := globConfigFiles(dir)
		if err != nil {
			return nil, err
		}
		for _, configPath := range configs {
			paths, err := discoverLogPaths(configPath, vhostRoot.serverType, root)
			if err != nil {
				return nil, err
			}
			for _, path := range paths {
				candidates = append(candidates, candidateSource{
					Path:         cleanGuestPath(path),
					ServerType:   vhostRoot.serverType,
					SourceMethod: vhostRoot.sourceMethod,
					Evidence:     []string{vhostRoot.evidence},
				})
			}
		}
	}
	return candidates, nil
}

func discoverOnePanelWebsiteLogCandidates(root string) ([]candidateSource, error) {
	openRestyRoot := "/opt/1panel/apps/openresty/openresty"
	configDir := rootPath(root, filepath.Join(openRestyRoot, "conf", "conf.d"))
	if _, err := os.Stat(configDir); err != nil {
		return nil, nil
	}
	configs, err := globConfigFiles(configDir)
	if err != nil {
		return nil, err
	}

	var candidates []candidateSource
	for _, configPath := range configs {
		paths, err := discoverLogPaths(configPath, "openresty", root)
		if err != nil {
			return nil, err
		}
		for _, path := range paths {
			guestPath := mapOnePanelOpenRestyContainerPath(path)
			evidence := []string{"ONEPANEL_OPENRESTY_WEBSITE_CONFIG"}
			if guestPath != path {
				evidence = append(evidence, "ONEPANEL_CONTAINER_PATH_MAPPING")
			}
			candidates = append(candidates, candidateSource{
				Path:         cleanGuestPath(guestPath),
				ServerType:   "openresty",
				SourceMethod: "onePanelWebsiteConfig",
				Evidence:     evidence,
			})
		}
	}
	return candidates, nil
}

func discoverPHPStudyDefaultLogCandidates(root string) []candidateSource {
	roots := []string{"/phpstudy_pro", "/phpStudy"}
	if root != "" {
		for _, nested := range []string{"phpstudy_pro", "phpStudy"} {
			roots = append(roots, "/"+nested)
		}
	}

	var candidates []candidateSource
	for _, phpStudyRoot := range uniqueSorted(roots) {
		for _, server := range []struct {
			serverType string
			pattern    string
		}{
			{serverType: "apache", pattern: filepath.Join(phpStudyRoot, "Extensions", "Apache*", "logs")},
			{serverType: "nginx", pattern: filepath.Join(phpStudyRoot, "Extensions", "Nginx*", "logs")},
		} {
			logDirs, err := filepath.Glob(rootPath(root, server.pattern))
			if err != nil {
				continue
			}
			for _, logDir := range logDirs {
				for _, path := range accessLogFilesInDir(logDir) {
					guestPath := path
					if root != "" {
						if rel, err := filepath.Rel(root, path); err == nil && !strings.HasPrefix(rel, "..") {
							guestPath = "/" + filepath.ToSlash(rel)
						}
					}
					candidates = append(candidates, candidateSource{
						Path:         cleanGuestPath(guestPath),
						ServerType:   server.serverType,
						SourceMethod: "phpStudyDefaultLogPath",
						Evidence:     []string{"PHPSTUDY_DEFAULT_LOG_PATH"},
					})
				}
			}
		}
	}
	return candidates
}

func accessLogFilesInDir(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var paths []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if !isAccessLogPath(entry.Name()) {
			continue
		}
		paths = append(paths, filepath.Join(dir, entry.Name()))
	}
	return uniqueSorted(paths)
}

func globConfigFiles(dir string) ([]string, error) {
	patterns := []string{
		filepath.Join(dir, "*.conf"),
		filepath.Join(dir, "*.vhost"),
	}
	var files []string
	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return nil, err
		}
		files = append(files, matches...)
	}
	return uniqueSorted(files), nil
}

func mapOnePanelOpenRestyContainerPath(path string) string {
	cleaned := cleanGuestPath(path)
	const containerSiteRoot = "/www/sites/"
	if !strings.HasPrefix(cleaned, containerSiteRoot) {
		return cleaned
	}
	return filepath.ToSlash(filepath.Join("/opt/1panel/apps/openresty/openresty/www/sites", strings.TrimPrefix(cleaned, containerSiteRoot)))
}

func discoverNginxLogPaths(configPath string, visited map[string]struct{}, root string) ([]string, error) {
	configPath = filepath.Clean(configPath)
	if _, ok := visited[configPath]; ok {
		return nil, nil
	}
	visited[configPath] = struct{}{}
	body, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	baseDir := filepath.Dir(configPath)
	paths := make([]string, 0)
	for _, raw := range strings.Split(strings.ReplaceAll(string(body), "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, "include ") {
			pattern := resolveConfigPath(baseDir, extractDirectiveValue(line, "include"))
			matches, err := filepath.Glob(pattern)
			if err != nil {
				return nil, err
			}
			sort.Strings(matches)
			for _, match := range matches {
				subPaths, err := discoverNginxLogPaths(match, visited, root)
				if err != nil {
					return nil, err
				}
				paths = append(paths, subPaths...)
			}
			continue
		}
		if strings.Contains(line, "access_log ") {
			paths = append(paths, expandLogVariants(resolveConfigPath(baseDir, extractDirectiveValue(line, "access_log")), root)...)
		}
	}
	return uniqueSorted(paths), nil
}

func discoverApacheLogPaths(configPath string, root string) ([]string, error) {
	body, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	baseDir := filepath.Dir(configPath)
	var paths []string
	for _, raw := range strings.Split(strings.ReplaceAll(string(body), "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "CustomLog ") {
			paths = append(paths, expandLogVariants(resolveConfigPath(baseDir, extractQuotedOrFirstArg(strings.TrimPrefix(line, "CustomLog "))), root)...)
		}
	}
	return uniqueSorted(paths), nil
}

func discoverTomcatLogPaths(configPath string, root string) ([]string, error) {
	body, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	type valve struct {
		ClassName string `xml:"className,attr"`
		Directory string `xml:"directory,attr"`
		Prefix    string `xml:"prefix,attr"`
		Suffix    string `xml:"suffix,attr"`
	}
	type host struct {
		Valves []valve `xml:"Valve"`
	}
	type engine struct {
		Hosts []host `xml:"Host"`
	}
	type service struct {
		Engines []engine `xml:"Engine"`
	}
	type server struct {
		Services []service `xml:"Service"`
	}
	var parsed server
	if err := xml.Unmarshal(body, &parsed); err != nil {
		return nil, err
	}
	baseDir := filepath.Dir(configPath)
	var paths []string
	for _, svc := range parsed.Services {
		for _, eng := range svc.Engines {
			for _, h := range eng.Hosts {
				for _, v := range h.Valves {
					if !strings.Contains(v.ClassName, "AccessLogValve") {
						continue
					}
					dir := resolveConfigPath(baseDir, v.Directory)
					globDir := dir
					if filepath.IsAbs(dir) {
						globDir = rootPath(root, dir)
					}
					matches, err := filepath.Glob(filepath.Join(globDir, v.Prefix+"*"+v.Suffix))
					if err != nil {
						return nil, err
					}
					for _, match := range matches {
						guestPath := match
						if root != "" {
							if rel, err := filepath.Rel(root, match); err == nil && !strings.HasPrefix(rel, "..") {
								guestPath = "/" + filepath.ToSlash(rel)
							}
						}
						paths = append(paths, expandLogVariants(guestPath, root)...)
					}
				}
			}
		}
	}
	return uniqueSorted(paths), nil
}

func extractDirectiveValue(line string, directive string) string {
	idx := strings.Index(line, directive)
	if idx < 0 {
		return ""
	}
	rest := strings.TrimSpace(line[idx+len(directive):])
	rest = strings.TrimSuffix(rest, ";")
	return extractQuotedOrFirstArg(rest)
}

func extractQuotedOrFirstArg(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if value[0] == '"' || value[0] == '\'' {
		quote := value[0]
		end := strings.IndexByte(value[1:], quote)
		if end >= 0 {
			return value[1 : end+1]
		}
	}
	return strings.Fields(value)[0]
}

func resolveConfigPath(baseDir string, path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if filepath.IsAbs(path) {
		return filepath.Clean(path)
	}
	return filepath.Clean(filepath.Join(baseDir, path))
}

func rootPath(root string, guestPath string) string {
	if root == "" {
		return filepath.Clean(guestPath)
	}
	guestPath = filepath.Clean("/" + strings.TrimLeft(guestPath, "/"))
	return filepath.Join(root, strings.TrimLeft(guestPath, "/"))
}

func cleanGuestPath(path string) string {
	return filepath.Clean("/" + strings.TrimLeft(path, "/"))
}

func readExistingFile(path string) ([]byte, os.FileInfo, error) {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return nil, nil, err
	}
	if strings.HasSuffix(path, ".gz") {
		file, err := os.Open(path)
		if err != nil {
			return nil, nil, err
		}
		defer file.Close()
		reader, err := gzip.NewReader(file)
		if err != nil {
			return nil, nil, err
		}
		defer reader.Close()
		body, err := io.ReadAll(reader)
		return body, info, err
	}
	body, err := os.ReadFile(path)
	return body, info, err
}

func expandLogVariants(path string, root string) []string {
	var variants []string
	if path != "" {
		variants = append(variants, path)
	}
	if !isAccessLogPath(path) {
		return uniqueSorted(variants)
	}
	for _, candidate := range []string{path + ".1", path + ".2.gz", path + ".gz"} {
		if _, err := os.Stat(rootPath(root, candidate)); err == nil {
			variants = append(variants, candidate)
		}
	}
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	for _, pattern := range []string{base + ".*", strings.TrimSuffix(base, ".log") + "_*"} {
		hostPattern := filepath.Join(dir, pattern)
		if root != "" {
			hostPattern = rootPath(root, hostPattern)
		}
		matches, err := filepath.Glob(hostPattern)
		if err != nil {
			continue
		}
		for _, match := range matches {
			guestPath := match
			if root != "" {
				if rel, err := filepath.Rel(root, match); err == nil && !strings.HasPrefix(rel, "..") {
					guestPath = "/" + filepath.ToSlash(rel)
				}
			}
			if isAccessLogPath(guestPath) {
				variants = append(variants, guestPath)
			}
		}
	}
	return uniqueSorted(variants)
}

func looksLikeCombinedLog(text string) bool {
	for _, line := range strings.Split(strings.TrimSpace(text), "\n") {
		if combinedLogPattern.MatchString(strings.TrimSpace(line)) {
			return true
		}
	}
	return false
}

func isAccessLogPath(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	base = strings.TrimSuffix(base, ".gz")
	return base == "access" ||
		base == "access.log" ||
		strings.HasPrefix(base, "access.log.") ||
		strings.HasPrefix(base, "access_log") ||
		strings.HasPrefix(base, "access-log") ||
		strings.HasPrefix(base, "localhost_access_log")
}

func parseCombinedLine(sourceID string, source candidateSource, line string) (Entry, bool) {
	matches := combinedLogPattern.FindStringSubmatch(strings.TrimSpace(line))
	if len(matches) != 10 {
		return Entry{}, false
	}
	status, err := strconv.Atoi(matches[6])
	if err != nil {
		return Entry{}, false
	}
	bytesSent, err := strconv.ParseInt(strings.ReplaceAll(matches[7], "-", "0"), 10, 64)
	if err != nil {
		return Entry{}, false
	}
	timestamp := matches[2]
	if parsed, err := time.Parse("02/Jan/2006:15:04:05 -0700", matches[2]); err == nil {
		timestamp = parsed.Format(time.RFC3339)
	}
	return Entry{
		SourceID:    sourceID,
		Timestamp:   timestamp,
		ClientIP:    matches[1],
		Method:      matches[3],
		URI:         matches[4],
		Protocol:    matches[5],
		Status:      status,
		BytesSent:   bytesSent,
		Referer:     normalizeDash(matches[8]),
		UserAgent:   normalizeDash(matches[9]),
		ServerType:  source.ServerType,
		ProcessName: source.ProcessName,
		ProcessPID:  source.ProcessPID,
	}, true
}

func runtimeSourceMethod(candidate weblogdiscovery.RuntimeCandidate) string {
	for _, evidence := range candidate.Evidence {
		if evidence == weblogdiscovery.EvidenceProcessCommandLineConfig {
			return "runtimeProcessConfig"
		}
	}
	return "runtimeInstallHint"
}

func stableSourceID(path string) string {
	sum := sha256.Sum256([]byte(path))
	return "weblog-source:" + hex.EncodeToString(sum[:8])
}

func dedupeSources(candidates []candidateSource) []candidateSource {
	merged := map[string]candidateSource{}
	order := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		key := candidate.Path
		existing, ok := merged[key]
		if !ok {
			merged[key] = candidate
			order = append(order, key)
			continue
		}
		existing.Evidence = uniqueSorted(append(existing.Evidence, candidate.Evidence...))
		if existing.Port == 0 {
			existing.Port = candidate.Port
		}
		merged[key] = existing
	}
	out := make([]candidateSource, 0, len(order))
	for _, key := range order {
		out = append(out, merged[key])
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

func uniqueSorted(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func normalizeDash(value string) string {
	if value == "-" {
		return ""
	}
	return value
}
