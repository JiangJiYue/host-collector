package collector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"collector-shared/logplan"
	"windows-host-collector/models"
	"windows-host-collector/utils"
)

type webLogDiscoveryInputs struct {
	IISConfigs    []string
	NginxConfigs  []string
	ApacheConfigs []string
	TomcatConfigs []string
}

type WebLogDiscoveryContext struct {
	Processes       []*models.ProcessBasicInfo
	ProcessDetails  map[int]*models.ProcessDetail
	NetworkSessions []models.NetworkSession
	Software        []models.InstalledSoftwareItem
}

type WebLogScanOverrideConfig struct {
	MaxDepth          int
	MaxFilesPerRoot   int
	MaxTotalFiles     int
	MaxSampleBytes    int64
	AllowedExtensions []string
}

type WebLogDiscoveryOverrideConfig struct {
	IISConfigs    []string
	NginxConfigs  []string
	ApacheConfigs []string
	TomcatConfigs []string
	ScanOptions   WebLogScanOverrideConfig
}

var webLogDiscoveryTestOverride WebLogDiscoveryOverrideConfig
var webLogDiscoveryRootsForTesting []string
var webLogDiscoveryContextObserverForTesting struct {
	mu       sync.RWMutex
	observer func(WebLogDiscoveryContext)
}
var webLogCollectorWindowObserverForTesting struct {
	mu       sync.RWMutex
	observer func(time.Time)
}

func SetWebLogDiscoveryOverridesForTesting(cfg WebLogDiscoveryOverrideConfig) {
	webLogDiscoveryTestOverride = cfg
}

func setWebLogDiscoveryRootsForTesting(roots []string) {
	webLogDiscoveryRootsForTesting = append([]string(nil), roots...)
}

func SetWebLogDiscoveryContextObserverForTesting(observer func(WebLogDiscoveryContext)) func() {
	webLogDiscoveryContextObserverForTesting.mu.Lock()
	previous := webLogDiscoveryContextObserverForTesting.observer
	webLogDiscoveryContextObserverForTesting.observer = observer
	webLogDiscoveryContextObserverForTesting.mu.Unlock()

	return func() {
		webLogDiscoveryContextObserverForTesting.mu.Lock()
		webLogDiscoveryContextObserverForTesting.observer = previous
		webLogDiscoveryContextObserverForTesting.mu.Unlock()
	}
}

func webLogDiscoveryContextObserverSnapshot() func(WebLogDiscoveryContext) {
	webLogDiscoveryContextObserverForTesting.mu.RLock()
	defer webLogDiscoveryContextObserverForTesting.mu.RUnlock()
	return webLogDiscoveryContextObserverForTesting.observer
}

type WebLogCollector struct {
	inputs            webLogDiscoveryInputs
	scanOptions       webLogScanOptions
	context           WebLogDiscoveryContext
	windowStart       time.Time
	fullModeMaxBytes  int64
	fullModeMaxEvents int64
}

func NewWebLogCollector() *WebLogCollector {
	inputs := discoverDefaultWebLogInputs()
	return &WebLogCollector{
		inputs: inputs,
		scanOptions: webLogScanOptions{
			MaxDepth:          5,
			MaxFilesPerRoot:   5000,
			MaxTotalFiles:     30000,
			MaxSampleBytes:    10 * 1024 * 1024,
			AllowedExtensions: []string{".log", ".txt"},
		},
		fullModeMaxBytes: 256 * 1024 * 1024,
	}
}

func (wc *WebLogCollector) WithDiscoveryInputs(inputs webLogDiscoveryInputs) *WebLogCollector {
	wc.inputs = inputs
	return wc
}

func (wc *WebLogCollector) WithScanOptions(options webLogScanOptions) *WebLogCollector {
	wc.scanOptions = options
	return wc
}

func (wc *WebLogCollector) WithDiscoveryContext(ctx WebLogDiscoveryContext) *WebLogCollector {
	wc.context = ctx
	if observer := webLogDiscoveryContextObserverSnapshot(); observer != nil {
		observer(ctx)
	}
	return wc
}

func (wc *WebLogCollector) WithTimeWindow(start time.Time) *WebLogCollector {
	wc.windowStart = start
	if observer := webLogCollectorWindowObserverSnapshot(); observer != nil {
		observer(start)
	}
	return wc
}

func (wc *WebLogCollector) WithFullModeThresholds(maxBytes int64, maxEvents int64) *WebLogCollector {
	wc.fullModeMaxBytes = maxBytes
	wc.fullModeMaxEvents = maxEvents
	return wc
}

func SetWebLogCollectorWindowObserverForTesting(observer func(time.Time)) func() {
	webLogCollectorWindowObserverForTesting.mu.Lock()
	previous := webLogCollectorWindowObserverForTesting.observer
	webLogCollectorWindowObserverForTesting.observer = observer
	webLogCollectorWindowObserverForTesting.mu.Unlock()

	return func() {
		webLogCollectorWindowObserverForTesting.mu.Lock()
		webLogCollectorWindowObserverForTesting.observer = previous
		webLogCollectorWindowObserverForTesting.mu.Unlock()
	}
}

func webLogCollectorWindowObserverSnapshot() func(time.Time) {
	webLogCollectorWindowObserverForTesting.mu.RLock()
	defer webLogCollectorWindowObserverForTesting.mu.RUnlock()
	return webLogCollectorWindowObserverForTesting.observer
}

func (wc *WebLogCollector) Name() string {
	return "web_log"
}

type WebLogCollectionResult struct {
	Sources        []models.WebLogSource `json:"webLogSources"`
	Entries        []models.WebLogEntry  `json:"webLogEntries"`
	CollectionPlan *logplan.Plan         `json:"webLogCollectionPlan,omitempty"`
	Total          int                   `json:"total"`
}

func (wc *WebLogCollector) Collect(ctx context.Context) (interface{}, error) {
	utils.Info("Collector", "开始采集 Web 日志...")

	inputs := wc.inputs
	options := wc.scanOptions
	if webLogDiscoveryTestOverride.IISConfigs != nil {
		inputs.IISConfigs = webLogDiscoveryTestOverride.IISConfigs
	}
	if webLogDiscoveryTestOverride.NginxConfigs != nil {
		inputs.NginxConfigs = webLogDiscoveryTestOverride.NginxConfigs
	}
	if webLogDiscoveryTestOverride.ApacheConfigs != nil {
		inputs.ApacheConfigs = webLogDiscoveryTestOverride.ApacheConfigs
	}
	if webLogDiscoveryTestOverride.TomcatConfigs != nil {
		inputs.TomcatConfigs = webLogDiscoveryTestOverride.TomcatConfigs
	}
	if override := webLogDiscoveryTestOverride.ScanOptions; override.MaxDepth != 0 || override.MaxFilesPerRoot != 0 || override.MaxTotalFiles != 0 || override.MaxSampleBytes != 0 || len(override.AllowedExtensions) > 0 {
		options = webLogScanOptions{
			MaxDepth:          override.MaxDepth,
			MaxFilesPerRoot:   override.MaxFilesPerRoot,
			MaxTotalFiles:     override.MaxTotalFiles,
			MaxSampleBytes:    override.MaxSampleBytes,
			AllowedExtensions: override.AllowedExtensions,
		}
	}

	candidates, err := wc.discoverSources(inputs)
	if err != nil {
		return nil, err
	}
	counts := countWebLogCandidatesByServer(candidates)
	utils.Info("Collector", "Web日志最终候选来源汇总: iis=%d nginx=%d apache=%d tomcat=%d total=%d",
		counts["iis"], counts["nginx"], counts["apache"], counts["tomcat"], len(candidates))
	for _, candidate := range candidates {
		utils.Info("Collector", "Web日志候选来源命中: server=%s site=%s path=%s", candidate.ServerType, candidate.SiteName, candidate.Path)
	}

	roots := make([]string, 0, len(candidates))
	byPath := make(map[string]webLogSourceCandidate, len(candidates))
	for _, candidate := range candidates {
		byPath[candidate.Path] = candidate
		roots = append(roots, filepath.Dir(candidate.Path))
	}

	files, err := scanWebLogCandidateFiles(uniqueSorted(roots), options)
	if err != nil {
		return nil, err
	}
	utils.Info("Collector", "Web日志候选文件扫描完成: roots=%d files=%d", len(uniqueSorted(roots)), len(files))
	collectionPlan := decideWebLogCollectionPlan(files, logplan.Thresholds{
		MaxFullBytes:  wc.fullModeMaxBytes,
		MaxFullEvents: wc.fullModeMaxEvents,
	})
	utils.Info("Collector", "Web日志采集计划: mode=%s reason=%s total_bytes=%d files=%d",
		collectionPlan.Mode, collectionPlan.Reason, collectionPlan.TotalBytes, len(collectionPlan.Sources))

	sources := make([]models.WebLogSource, 0, len(files))
	entries := make([]models.WebLogEntry, 0)
	for _, file := range files {
		candidate, ok := byPath[file.Path]
		if !ok {
			utils.Debug("Collector", "Web日志文件跳过: 未匹配候选来源 path=%s", file.Path)
			continue
		}

		fingerprint := fingerprintWebLogSample(file.Path, file.Sample)
		utils.Info("Collector", "Web日志候选文件: server=%s path=%s format=%s confidence=%s evidence=%v size=%d",
			candidate.ServerType, file.Path, fingerprint.Format, fingerprint.Confidence, fingerprint.Evidence, file.Size)
		sourceID := stableWebLogSourceID(file.Path)
		source := models.WebLogSource{
			ID:         sourceID,
			Path:       file.Path,
			ServerType: candidate.ServerType,
			Format:     string(fingerprint.Format),
			SiteName:   candidate.SiteName,
			Confidence: string(fingerprint.Confidence),
			Size:       file.Size,
			Port:       candidate.Port,
		}
		source.SourceMethod = candidate.SourceMethod
		if source.SourceMethod == "" {
			source.SourceMethod = sourceMethodForServer(candidate.ServerType)
		}
		source.Evidence = uniqueSorted(append(append([]string(nil), fingerprint.Evidence...), candidate.Evidence...))
		sources = append(sources, source)

		state := webLogParseState{Format: fingerprint.Format}
		lines := strings.Split(strings.ReplaceAll(string(file.Sample), "\r\n", "\n"), "\n")
		entryCountBefore := len(entries)
		for _, line := range lines {
			entry, nextState, ok := parseWebLogLine(sourceID, candidate, state, line)
			state = nextState
			if !ok {
				continue
			}
			if !wc.entryWithinPlan(entry, collectionPlan) {
				continue
			}
			entries = append(entries, entry)
		}
		parsedCount := len(entries) - entryCountBefore
		if parsedCount == 0 {
			utils.Info("Collector", "Web日志文件未解析出记录: path=%s format=%s confidence=%s", file.Path, fingerprint.Format, fingerprint.Confidence)
		} else {
			utils.Info("Collector", "Web日志文件解析完成: path=%s parsed=%d", file.Path, parsedCount)
		}
	}

	sort.Slice(sources, func(i, j int) bool { return sources[i].Path < sources[j].Path })
	utils.Info("Collector", "Web 日志采集完成: %d来源, %d条记录", len(sources), len(entries))

	return &WebLogCollectionResult{
		Sources:        sources,
		Entries:        entries,
		CollectionPlan: &collectionPlan,
		Total:          len(entries),
	}, nil
}

func (wc *WebLogCollector) entryWithinPlan(entry models.WebLogEntry, plan logplan.Plan) bool {
	if plan.Mode == logplan.ModeFull {
		return true
	}
	if wc.windowStart.IsZero() {
		return true
	}
	return eventWithinWindow(entry.Timestamp, wc.windowStart)
}

func decideWebLogCollectionPlan(files []webLogFileCandidate, thresholds logplan.Thresholds) logplan.Plan {
	sources := make([]logplan.SourceEstimate, 0, len(files))
	for _, file := range files {
		status := logplan.SourceAvailable
		if file.Size == 0 {
			status = logplan.SourceEmpty
		}
		sources = append(sources, logplan.SourceEstimate{
			Path:      file.Path,
			SizeBytes: file.Size,
			Status:    status,
		})
	}
	return logplan.Decide(logplan.Request{
		Domain:     "web_logs",
		Sources:    sources,
		Thresholds: thresholds,
		Backfill: logplan.BackfillPolicy{
			Enabled: true,
			Reason:  "web_log_suspicious_patterns",
		},
	})
}

func discoverDefaultWebLogInputs() webLogDiscoveryInputs {
	roots := webLogDiscoveryRootsForTesting
	if len(roots) == 0 {
		roots = []string{
			`C:\Windows\System32\inetsrv\config`,
			`C:\phpstudy_pro`,
			`C:\phpStudy`,
			`D:\phpstudy_pro`,
			`D:\phpStudy`,
			`C:\nginx`,
			`C:\Apache24`,
			`C:\xampp`,
			`C:\tomcat`,
			`D:\web`,
			`D:\www`,
		}
	}

	inputs := webLogDiscoveryInputs{}
	for _, root := range roots {
		root = filepath.Clean(root)
		addIfExists := func(target *[]string, path string) {
			if path == "" {
				return
			}
			if _, err := os.Stat(path); err == nil {
				*target = append(*target, filepath.Clean(path))
			}
		}

		addGlob := func(target *[]string, pattern string) {
			matches, err := filepath.Glob(pattern)
			if err != nil {
				return
			}
			for _, match := range matches {
				if _, err := os.Stat(match); err == nil {
					*target = append(*target, filepath.Clean(match))
				}
			}
		}

		addIfExists(&inputs.IISConfigs, filepath.Join(root, "applicationHost.config"))
		addIfExists(&inputs.IISConfigs, filepath.Join(root, "config", "applicationHost.config"))
		addIfExists(&inputs.NginxConfigs, filepath.Join(root, "nginx.conf"))
		addIfExists(&inputs.NginxConfigs, filepath.Join(root, "conf", "nginx.conf"))
		addGlob(&inputs.NginxConfigs, filepath.Join(root, "Extensions", "Nginx*", "conf", "nginx.conf"))
		addGlob(&inputs.NginxConfigs, filepath.Join(root, "phpstudy_pro", "Extensions", "Nginx*", "conf", "nginx.conf"))
		addGlob(&inputs.NginxConfigs, filepath.Join(root, "phpStudy", "Extensions", "Nginx*", "conf", "nginx.conf"))
		addIfExists(&inputs.ApacheConfigs, filepath.Join(root, "httpd.conf"))
		addIfExists(&inputs.ApacheConfigs, filepath.Join(root, "conf", "httpd.conf"))
		addGlob(&inputs.ApacheConfigs, filepath.Join(root, "Extensions", "Apache*", "conf", "httpd.conf"))
		addGlob(&inputs.ApacheConfigs, filepath.Join(root, "phpstudy_pro", "Extensions", "Apache*", "conf", "httpd.conf"))
		addGlob(&inputs.ApacheConfigs, filepath.Join(root, "phpStudy", "Extensions", "Apache*", "conf", "httpd.conf"))
		addIfExists(&inputs.TomcatConfigs, filepath.Join(root, "conf", "server.xml"))
		addGlob(&inputs.TomcatConfigs, filepath.Join(root, "tomcat*", "conf", "server.xml"))
		addGlob(&inputs.TomcatConfigs, filepath.Join(root, "phpstudy_pro", "Extensions", "Tomcat*", "conf", "server.xml"))
		addGlob(&inputs.TomcatConfigs, filepath.Join(root, "phpStudy", "Extensions", "Tomcat*", "conf", "server.xml"))
	}

	inputs.IISConfigs = uniqueSorted(inputs.IISConfigs)
	inputs.NginxConfigs = uniqueSorted(inputs.NginxConfigs)
	inputs.ApacheConfigs = uniqueSorted(inputs.ApacheConfigs)
	inputs.TomcatConfigs = uniqueSorted(inputs.TomcatConfigs)
	utils.Info("Collector", "Web日志静态默认配置扫描: iis=%v nginx=%v apache=%v tomcat=%v",
		inputs.IISConfigs, inputs.NginxConfigs, inputs.ApacheConfigs, inputs.TomcatConfigs)
	return inputs
}

func (wc *WebLogCollector) discoverSources(inputs webLogDiscoveryInputs) ([]webLogSourceCandidate, error) {
	candidates := make([]webLogSourceCandidate, 0)

	for _, configPath := range inputs.IISConfigs {
		sources, err := discoverIISWebLogSources(configPath, wc.scanOptions.MaxFilesPerRoot)
		if err != nil {
			return nil, err
		}
		candidates = append(candidates, sources...)
	}

	appendConfigSources := func(paths []string, serverType string) error {
		for _, configPath := range paths {
			logPaths, err := discoverWebLogPathsFromConfig(configPath, serverType)
			if err != nil {
				return err
			}
			for _, path := range logPaths {
				candidates = append(candidates, webLogSourceCandidate{
					ID:           path,
					Path:         path,
					ServerType:   serverType,
					SourceMethod: sourceMethodForServer(serverType),
				})
			}
		}
		return nil
	}

	if err := appendConfigSources(inputs.NginxConfigs, "nginx"); err != nil {
		return nil, err
	}
	if err := appendConfigSources(inputs.ApacheConfigs, "apache"); err != nil {
		return nil, err
	}
	if err := appendConfigSources(inputs.TomcatConfigs, "tomcat"); err != nil {
		return nil, err
	}
	candidates = append(candidates, discoverPHPStudyDefaultLogSources()...)

	runtimeCandidates, err := wc.discoverRuntimeSources()
	if err != nil {
		return nil, err
	}
	candidates = append(candidates, runtimeCandidates...)

	mergedByPath := make(map[string]webLogSourceCandidate, len(candidates))
	order := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		path := filepath.Clean(candidate.Path)
		if isExistingDirectory(path) {
			utils.Info("Collector", "Web日志候选来源跳过: 路径是目录 server=%s path=%s", candidate.ServerType, path)
			continue
		}
		candidate.Path = path
		existing, ok := mergedByPath[path]
		if !ok {
			mergedByPath[path] = normalizeWebLogCandidate(candidate)
			order = append(order, path)
			continue
		}
		mergedByPath[path] = mergeWebLogSourceCandidates(existing, candidate)
	}

	unique := make([]webLogSourceCandidate, 0, len(order))
	for _, path := range order {
		unique = append(unique, mergedByPath[path])
	}
	sort.Slice(unique, func(i, j int) bool { return unique[i].Path < unique[j].Path })
	return unique, nil
}

func discoverPHPStudyDefaultLogSources() []webLogSourceCandidate {
	roots := webLogDiscoveryRootsForTesting
	if len(roots) == 0 {
		roots = []string{
			`C:\phpstudy_pro`,
			`C:\phpStudy`,
			`D:\phpstudy_pro`,
			`D:\phpStudy`,
		}
	}

	candidates := make([]webLogSourceCandidate, 0)
	for _, root := range roots {
		root = filepath.Clean(root)
		phpStudyRoots := []string{root}
		for _, nested := range []string{"phpstudy_pro", "phpStudy"} {
			nestedRoot := filepath.Join(root, nested)
			if nestedRoot != root {
				phpStudyRoots = append(phpStudyRoots, nestedRoot)
			}
		}
		for _, phpStudyRoot := range uniqueSorted(phpStudyRoots) {
			for _, server := range []struct {
				serverType string
				pattern    string
			}{
				{serverType: "apache", pattern: filepath.Join(phpStudyRoot, "Extensions", "Apache*", "logs")},
				{serverType: "nginx", pattern: filepath.Join(phpStudyRoot, "Extensions", "Nginx*", "logs")},
			} {
				logDirs, err := filepath.Glob(server.pattern)
				if err != nil {
					continue
				}
				for _, logDir := range logDirs {
					for _, path := range accessLogFilesInDir(logDir) {
						candidates = append(candidates, webLogSourceCandidate{
							ID:           path,
							Path:         path,
							ServerType:   server.serverType,
							SourceMethod: "phpStudyDefaultLogPath",
							Evidence:     []string{"PHPSTUDY_DEFAULT_LOG_PATH"},
						})
					}
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
	paths := make([]string, 0, len(entries))
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

func countWebLogCandidatesByServer(candidates []webLogSourceCandidate) map[string]int {
	counts := map[string]int{
		"iis":    0,
		"nginx":  0,
		"apache": 0,
		"tomcat": 0,
	}
	for _, candidate := range candidates {
		counts[strings.ToLower(candidate.ServerType)]++
	}
	return counts
}

func isExistingDirectory(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func (wc *WebLogCollector) discoverRuntimeSources() ([]webLogSourceCandidate, error) {
	runtimeCandidates := buildRuntimeWebLogCandidates(wc.context)
	discovered := make([]webLogSourceCandidate, 0)

	for _, candidate := range runtimeCandidates {
		configPaths, err := expandRuntimeConfigHints(candidate.ConfigHints)
		if err != nil {
			return nil, err
		}
		sourceMethod := runtimeSourceMethod(candidate)
		port := 0
		if len(candidate.ListenPorts) > 0 {
			port = candidate.ListenPorts[0]
		}

		for _, configPath := range configPaths {
			logPaths, err := discoverWebLogPathsFromConfig(configPath, candidate.ServerType)
			if err != nil {
				return nil, err
			}
			for _, logPath := range logPaths {
				logPath = filepath.Clean(logPath)
				utils.Info("Collector", "Web日志运行时补充发现命中: serverType=%s processName=%s processPid=%d port=%d configPath=%s path=%s installLocation=%s evidence=%v",
					candidate.ServerType,
					candidate.ProcessName,
					candidate.ProcessPID,
					port,
					filepath.Clean(runtimeHintToFSPath(configPath)),
					logPath,
					runtimeHintToFSPath(candidate.InstallLocation),
					candidate.Evidence,
				)
				discovered = append(discovered, webLogSourceCandidate{
					ID:           logPath,
					Path:         logPath,
					ServerType:   candidate.ServerType,
					Port:         port,
					SourceMethod: sourceMethod,
					Evidence:     append([]string(nil), candidate.Evidence...),
					ProcessName:  candidate.ProcessName,
					ProcessPID:   candidate.ProcessPID,
				})
			}
		}
	}

	return discovered, nil
}

func normalizeWebLogCandidate(candidate webLogSourceCandidate) webLogSourceCandidate {
	candidate.Evidence = uniqueSorted(candidate.Evidence)
	if candidate.SourceMethod == "" {
		candidate.SourceMethod = sourceMethodForServer(candidate.ServerType)
	}
	return candidate
}

func mergeWebLogSourceCandidates(existing, incoming webLogSourceCandidate) webLogSourceCandidate {
	existing = normalizeWebLogCandidate(existing)
	incoming = normalizeWebLogCandidate(incoming)

	existing.Evidence = uniqueSorted(append(existing.Evidence, incoming.Evidence...))
	if existing.Port == 0 {
		existing.Port = incoming.Port
	}
	if existing.ProcessName == "" {
		existing.ProcessName = incoming.ProcessName
	}
	if existing.ProcessPID == 0 {
		existing.ProcessPID = incoming.ProcessPID
	}
	if existing.SiteName == "" {
		existing.SiteName = incoming.SiteName
	}
	if existing.ServerType == "" {
		existing.ServerType = incoming.ServerType
	}
	if existing.ID == "" {
		existing.ID = incoming.ID
	}
	if existing.SourceMethod == "" {
		existing.SourceMethod = incoming.SourceMethod
	}

	return existing
}

func expandRuntimeConfigHints(hints []string) ([]string, error) {
	configPaths := make([]string, 0, len(hints))
	for _, hint := range hints {
		if hint == "" {
			continue
		}
		fsHint := runtimeHintToFSPath(hint)
		if hasGlobMeta(fsHint) {
			matches, err := globSorted(fsHint)
			if err != nil {
				return nil, err
			}
			configPaths = append(configPaths, matches...)
			continue
		}
		if _, err := os.Stat(fsHint); err == nil {
			configPaths = append(configPaths, filepath.Clean(fsHint))
		}
	}
	return uniqueSorted(configPaths), nil
}

func runtimeHintToFSPath(path string) string {
	path = strings.ReplaceAll(path, `\`, string(os.PathSeparator))
	if os.PathSeparator != '/' {
		path = strings.ReplaceAll(path, "/", string(os.PathSeparator))
	}
	return filepath.Clean(path)
}

func hasGlobMeta(path string) bool {
	return strings.ContainsAny(path, "*?[")
}

func expandAccessLogVariants(path string) []string {
	var variants []string
	if path != "" {
		variants = append(variants, filepath.Clean(path))
	}
	if !isAccessLogPath(path) {
		return uniqueSorted(variants)
	}
	for _, candidate := range []string{path + ".1", path + ".2.gz", path + ".gz"} {
		if _, err := os.Stat(candidate); err == nil {
			variants = append(variants, filepath.Clean(candidate))
		}
	}
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	for _, pattern := range []string{base + ".*", strings.TrimSuffix(base, ".log") + "_*"} {
		matches, err := filepath.Glob(filepath.Join(dir, pattern))
		if err != nil {
			continue
		}
		variants = append(variants, matches...)
	}
	filtered := make([]string, 0, len(variants))
	for _, candidate := range variants {
		if isAccessLogPath(candidate) {
			filtered = append(filtered, filepath.Clean(candidate))
		}
	}
	return uniqueSorted(filtered)
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

func runtimeSourceMethod(candidate webLogRuntimeCandidate) string {
	for _, evidence := range candidate.Evidence {
		if evidence == "PROCESS_COMMANDLINE_CONFIG" {
			return "runtimeProcessConfig"
		}
	}
	return "runtimeInstallHint"
}

func stableWebLogSourceID(path string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(filepath.Clean(path))))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func sourceMethodForServer(serverType string) string {
	switch serverType {
	case "iis":
		return "iisConfig"
	case "nginx":
		return "nginxConfig"
	case "apache":
		return "apacheConfig"
	case "tomcat":
		return "tomcatConfig"
	default:
		return "config"
	}
}
