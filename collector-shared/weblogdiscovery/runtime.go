package weblogdiscovery

import (
	"sort"
	"strconv"
	"strings"
)

const (
	PlatformWindows = "windows"
	PlatformLinux   = "linux"

	EvidenceProcessNameMatch         = "PROCESS_NAME_MATCH"
	EvidenceProcessCommandLineConfig = "PROCESS_COMMANDLINE_CONFIG"
	EvidenceProcessPathHint          = "PROCESS_PATH_HINT"
	EvidenceListenPortMatch          = "LISTEN_PORT_MATCH"
)

type ProcessSignal struct {
	PID            int
	Name           string
	ExecutablePath string
	CommandLine    string
}

type ListenerSignal struct {
	ProcessPID  int
	ProcessName string
	Port        int
}

type Context struct {
	Platform  string
	Processes []ProcessSignal
	Listeners []ListenerSignal
}

type RuntimeCandidate struct {
	ServerType     string
	ProcessName    string
	ProcessPID     int
	ListenPorts    []int
	ExecutablePath string
	CommandLine    string
	ConfigHints    []string
	Evidence       []string
}

func BuildRuntimeCandidates(ctx Context) []RuntimeCandidate {
	listenersByPID := map[int][]int{}
	listenersByName := map[string][]int{}
	for _, listener := range ctx.Listeners {
		if listener.Port == 0 {
			continue
		}
		if listener.ProcessPID != 0 {
			listenersByPID[listener.ProcessPID] = append(listenersByPID[listener.ProcessPID], listener.Port)
		}
		if listener.ProcessName != "" {
			listenersByName[strings.ToLower(listener.ProcessName)] = append(listenersByName[strings.ToLower(listener.ProcessName)], listener.Port)
		}
	}

	candidates := make([]RuntimeCandidate, 0, len(ctx.Processes))
	for _, process := range ctx.Processes {
		candidate, ok := buildProcessCandidate(ctx.Platform, process)
		if !ok {
			continue
		}
		for _, port := range listenersByPID[process.PID] {
			addInt(&candidate.ListenPorts, port)
			addString(&candidate.Evidence, EvidenceListenPortMatch)
		}
		if len(candidate.ListenPorts) == 0 {
			for _, port := range listenersByName[strings.ToLower(process.Name)] {
				addInt(&candidate.ListenPorts, port)
				addString(&candidate.Evidence, EvidenceListenPortMatch)
			}
		}
		if len(candidate.ConfigHints) == 0 {
			continue
		}
		sort.Ints(candidate.ListenPorts)
		sort.Strings(candidate.ConfigHints)
		sort.Strings(candidate.Evidence)
		candidates = append(candidates, candidate)
	}

	sort.SliceStable(candidates, func(i, j int) bool {
		return candidateSortKey(candidates[i]) < candidateSortKey(candidates[j])
	})
	return dedupeCandidates(candidates)
}

func buildProcessCandidate(platform string, process ProcessSignal) (RuntimeCandidate, bool) {
	candidate := RuntimeCandidate{
		ProcessName:    process.Name,
		ProcessPID:     process.PID,
		ExecutablePath: process.ExecutablePath,
		CommandLine:    process.CommandLine,
	}
	name := strings.ToLower(process.Name)
	switch platform {
	case PlatformWindows:
		return buildWindowsCandidate(candidate, name)
	case PlatformLinux:
		return buildLinuxCandidate(candidate, name)
	default:
		return RuntimeCandidate{}, false
	}
}

func buildWindowsCandidate(candidate RuntimeCandidate, name string) (RuntimeCandidate, bool) {
	switch name {
	case "nginx.exe":
		candidate.ServerType = "nginx"
		addString(&candidate.Evidence, EvidenceProcessNameMatch)
		addConfigFromCommandLine(&candidate, candidate.CommandLine, "-c")
		if candidate.ExecutablePath != "" {
			addString(&candidate.ConfigHints, joinPath(windowsDir(candidate.ExecutablePath), `\`, "conf", "nginx.conf"))
			addString(&candidate.Evidence, EvidenceProcessPathHint)
		}
	case "httpd.exe", "apache.exe":
		candidate.ServerType = "apache"
		addString(&candidate.Evidence, EvidenceProcessNameMatch)
		addConfigFromCommandLine(&candidate, candidate.CommandLine, "-f")
		if candidate.ExecutablePath != "" {
			execDir := windowsDir(candidate.ExecutablePath)
			baseDir := execDir
			if strings.EqualFold(pathBase(execDir), "bin") {
				baseDir = windowsDir(execDir)
			}
			addString(&candidate.ConfigHints, joinPath(baseDir, `\`, "conf", "httpd.conf"))
			addString(&candidate.Evidence, EvidenceProcessPathHint)
		}
	default:
		return RuntimeCandidate{}, false
	}
	return candidate, true
}

func buildLinuxCandidate(candidate RuntimeCandidate, name string) (RuntimeCandidate, bool) {
	switch name {
	case "nginx":
		candidate.ServerType = "nginx"
		addString(&candidate.Evidence, EvidenceProcessNameMatch)
		addConfigFromCommandLine(&candidate, candidate.CommandLine, "-c")
		if candidate.ExecutablePath != "" {
			addString(&candidate.ConfigHints, joinPath(posixDir(candidate.ExecutablePath), "/", "conf", "nginx.conf"))
			addString(&candidate.Evidence, EvidenceProcessPathHint)
		}
	case "httpd", "apache2", "apache":
		candidate.ServerType = "apache"
		addString(&candidate.Evidence, EvidenceProcessNameMatch)
		addConfigFromCommandLine(&candidate, candidate.CommandLine, "-f")
		addString(&candidate.ConfigHints, "/etc/apache2/apache2.conf")
		addString(&candidate.ConfigHints, "/etc/httpd/conf/httpd.conf")
		if candidate.ExecutablePath != "" {
			execDir := posixDir(candidate.ExecutablePath)
			baseDir := execDir
			if pathBase(execDir) == "bin" {
				baseDir = posixDir(execDir)
			}
			addString(&candidate.ConfigHints, joinPath(baseDir, "/", "conf", "httpd.conf"))
			addString(&candidate.Evidence, EvidenceProcessPathHint)
		}
	case "java":
		base := extractJavaProperty(candidate.CommandLine, "catalina.base")
		if base == "" {
			base = extractJavaProperty(candidate.CommandLine, "catalina.home")
		}
		if base == "" {
			return RuntimeCandidate{}, false
		}
		candidate.ServerType = "tomcat"
		addString(&candidate.Evidence, EvidenceProcessNameMatch)
		addString(&candidate.Evidence, EvidenceProcessCommandLineConfig)
		addString(&candidate.ConfigHints, joinPath(base, "/", "conf", "server.xml"))
	default:
		return RuntimeCandidate{}, false
	}
	return candidate, true
}

func addConfigFromCommandLine(candidate *RuntimeCandidate, commandLine string, flag string) {
	path := ExtractCommandLineConfigPath(commandLine, flag)
	if path == "" {
		return
	}
	addString(&candidate.ConfigHints, path)
	addString(&candidate.Evidence, EvidenceProcessCommandLineConfig)
}

func ExtractCommandLineConfigPath(commandLine string, flag string) string {
	tokens := SplitCommandLine(commandLine)
	for i := 0; i < len(tokens); i++ {
		token := tokens[i]
		if token == flag && i+1 < len(tokens) {
			return trimMatchingQuotes(tokens[i+1])
		}
		if strings.HasPrefix(token, flag+"=") {
			return trimMatchingQuotes(strings.TrimPrefix(token, flag+"="))
		}
	}
	return ""
}

func SplitCommandLine(commandLine string) []string {
	if commandLine == "" {
		return nil
	}
	var tokens []string
	var current strings.Builder
	var quote rune
	for _, r := range commandLine {
		switch r {
		case '\'', '"':
			if quote == 0 {
				quote = r
				continue
			}
			if quote == r {
				quote = 0
				continue
			}
			current.WriteRune(r)
		case ' ', '\t', '\n':
			if quote != 0 {
				current.WriteRune(r)
				continue
			}
			if current.Len() > 0 {
				tokens = append(tokens, current.String())
				current.Reset()
			}
		default:
			current.WriteRune(r)
		}
	}
	if current.Len() > 0 {
		tokens = append(tokens, current.String())
	}
	return tokens
}

func extractJavaProperty(commandLine string, property string) string {
	prefix := "-D" + property + "="
	for _, token := range SplitCommandLine(commandLine) {
		if strings.HasPrefix(token, prefix) {
			return trimMatchingQuotes(strings.TrimPrefix(token, prefix))
		}
	}
	return ""
}

func dedupeCandidates(candidates []RuntimeCandidate) []RuntimeCandidate {
	if len(candidates) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	deduped := make([]RuntimeCandidate, 0, len(candidates))
	for _, candidate := range candidates {
		key := candidateSortKey(candidate)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		deduped = append(deduped, candidate)
	}
	return deduped
}

func candidateSortKey(candidate RuntimeCandidate) string {
	return strings.Join([]string{
		candidate.ServerType,
		strings.ToLower(candidate.ProcessName),
		strconv.Itoa(candidate.ProcessPID),
		strings.ToLower(candidate.ExecutablePath),
		strings.Join(candidate.ConfigHints, "|"),
	}, "\x00")
}

func addString(target *[]string, value string) {
	if value == "" {
		return
	}
	for _, existing := range *target {
		if existing == value {
			return
		}
	}
	*target = append(*target, value)
}

func addInt(target *[]int, value int) {
	for _, existing := range *target {
		if existing == value {
			return
		}
	}
	*target = append(*target, value)
}

func trimMatchingQuotes(value string) string {
	if len(value) >= 2 {
		if value[0] == '"' && value[len(value)-1] == '"' {
			return value[1 : len(value)-1]
		}
		if value[0] == '\'' && value[len(value)-1] == '\'' {
			return value[1 : len(value)-1]
		}
	}
	return value
}

func windowsDir(path string) string {
	path = strings.TrimRight(path, `\/`)
	idx := strings.LastIndexAny(path, `\/`)
	if idx < 0 {
		return ""
	}
	return path[:idx]
}

func posixDir(path string) string {
	path = strings.TrimRight(path, "/")
	idx := strings.LastIndex(path, "/")
	if idx < 0 {
		return ""
	}
	if idx == 0 {
		return "/"
	}
	return path[:idx]
}

func pathBase(path string) string {
	path = strings.TrimRight(path, `\/`)
	idx := strings.LastIndexAny(path, `\/`)
	if idx < 0 {
		return path
	}
	return path[idx+1:]
}

func joinPath(base string, sep string, parts ...string) string {
	filtered := make([]string, 0, len(parts)+1)
	if base != "" {
		filtered = append(filtered, strings.TrimRight(base, `\/`))
	}
	for _, part := range parts {
		part = strings.Trim(part, `\/`)
		if part != "" {
			filtered = append(filtered, part)
		}
	}
	return strings.Join(filtered, sep)
}
