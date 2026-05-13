package collector

import (
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type iisApplicationHostConfig struct {
	Sites []iisSite `xml:"system.applicationHost>sites>site"`
}

type iisSite struct {
	Name     string       `xml:"name,attr"`
	ID       string       `xml:"id,attr"`
	LogFile  iisSiteLog   `xml:"logFile"`
	Bindings []iisBinding `xml:"bindings>binding"`
}

type iisSiteLog struct {
	Directory string `xml:"directory,attr"`
}

type iisBinding struct {
	Protocol           string `xml:"protocol,attr"`
	BindingInformation string `xml:"bindingInformation,attr"`
}

func discoverIISWebLogSources(configPath string, maxFiles int) ([]webLogSourceCandidate, error) {
	body, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("read applicationHost.config: %w", err)
	}

	var cfg iisApplicationHostConfig
	if err := xml.Unmarshal(body, &cfg); err != nil {
		return nil, fmt.Errorf("parse applicationHost.config: %w", err)
	}

	sources := make([]webLogSourceCandidate, 0)
	for _, site := range cfg.Sites {
		logDir := filepath.Clean(filepath.FromSlash(strings.TrimSpace(site.LogFile.Directory)))
		if logDir == "" {
			continue
		}
		files, err := globSorted(filepath.Join(logDir, "u_ex*.log"))
		if err != nil {
			return nil, err
		}
		for _, file := range files {
			sources = append(sources, webLogSourceCandidate{
				ID:         file,
				Path:       file,
				ServerType: "iis",
				SiteName:   site.Name,
			})
			if maxFiles > 0 && len(sources) >= maxFiles {
				return sources, nil
			}
		}
	}

	return sources, nil
}

func discoverWebLogPathsFromConfig(configPath string, serverType string) ([]string, error) {
	switch strings.ToLower(serverType) {
	case "nginx":
		return discoverNginxLogPaths(configPath, map[string]struct{}{})
	case "apache", "httpd":
		return discoverApacheLogPaths(configPath)
	case "tomcat":
		return discoverTomcatLogPaths(configPath)
	default:
		return nil, nil
	}
}

func discoverNginxLogPaths(configPath string, visited map[string]struct{}) ([]string, error) {
	configPath = filepath.Clean(configPath)
	if _, ok := visited[configPath]; ok {
		return nil, nil
	}
	visited[configPath] = struct{}{}

	body, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("read nginx config: %w", err)
	}

	paths := make([]string, 0)
	baseDir := filepath.Dir(configPath)
	lines := strings.Split(strings.ReplaceAll(string(body), "\r\n", "\n"), "\n")
	for _, rawLine := range lines {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, "include ") {
			includePattern := extractDirectiveValue(line, "include")
			if includePattern == "" {
				continue
			}
			if !filepath.IsAbs(includePattern) {
				includePattern = filepath.Join(baseDir, filepath.FromSlash(includePattern))
			}
			matches, err := globSorted(includePattern)
			if err != nil {
				return nil, err
			}
			for _, match := range matches {
				subPaths, err := discoverNginxLogPaths(match, visited)
				if err != nil {
					return nil, err
				}
				paths = append(paths, subPaths...)
			}
			continue
		}
		if strings.Contains(line, "access_log ") || strings.Contains(line, "error_log ") {
			directive := "access_log"
			if strings.Contains(line, "error_log ") {
				directive = "error_log"
			}
			value := extractDirectiveValue(line, directive)
			if value == "" {
				continue
			}
			path := filepath.Clean(filepath.FromSlash(value))
			if !filepath.IsAbs(path) {
				path = filepath.Join(baseDir, path)
			}
			paths = append(paths, path)
		}
	}

	return uniqueSorted(paths), nil
}

func discoverApacheLogPaths(configPath string) ([]string, error) {
	body, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("read apache config: %w", err)
	}
	baseDir := filepath.Dir(configPath)
	lines := strings.Split(strings.ReplaceAll(string(body), "\r\n", "\n"), "\n")
	paths := make([]string, 0)
	for _, rawLine := range lines {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		switch {
		case strings.HasPrefix(line, "CustomLog "):
			path := extractQuotedOrFirstArg(strings.TrimPrefix(line, "CustomLog "))
			if path != "" {
				paths = append(paths, resolveConfigPath(baseDir, path))
			}
		case strings.HasPrefix(line, "ErrorLog "):
			path := extractQuotedOrFirstArg(strings.TrimPrefix(line, "ErrorLog "))
			if path != "" {
				paths = append(paths, resolveConfigPath(baseDir, path))
			}
		}
	}
	return uniqueSorted(paths), nil
}

func discoverTomcatLogPaths(configPath string) ([]string, error) {
	body, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("read tomcat config: %w", err)
	}

	type tomcatValve struct {
		ClassName string `xml:"className,attr"`
		Directory string `xml:"directory,attr"`
		Prefix    string `xml:"prefix,attr"`
		Suffix    string `xml:"suffix,attr"`
	}
	type tomcatHost struct {
		Valves []tomcatValve `xml:"Valve"`
	}
	type tomcatEngine struct {
		Hosts []tomcatHost `xml:"Host"`
	}
	type tomcatService struct {
		Engines []tomcatEngine `xml:"Engine"`
	}
	type tomcatServer struct {
		Services []tomcatService `xml:"Service"`
	}

	var server tomcatServer
	if err := xml.Unmarshal(body, &server); err != nil {
		return nil, fmt.Errorf("parse tomcat server.xml: %w", err)
	}

	baseDir := filepath.Dir(configPath)
	paths := make([]string, 0)
	for _, service := range server.Services {
		for _, engine := range service.Engines {
			for _, host := range engine.Hosts {
				for _, valve := range host.Valves {
					if !strings.Contains(valve.ClassName, "AccessLogValve") {
						continue
					}
					dir := resolveConfigPath(baseDir, valve.Directory)
					pattern := filepath.Join(dir, valve.Prefix+"*"+valve.Suffix)
					matches, err := globSorted(pattern)
					if err != nil {
						return nil, err
					}
					paths = append(paths, matches...)
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
	if value[0] == '"' {
		if end := strings.Index(value[1:], `"`); end >= 0 {
			return value[1 : end+1]
		}
	}
	parts := strings.Fields(value)
	if len(parts) == 0 {
		return ""
	}
	return strings.Trim(parts[0], `";`)
}

func resolveConfigPath(baseDir string, path string) string {
	path = filepath.Clean(filepath.FromSlash(path))
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(baseDir, path)
}

func uniqueSorted(paths []string) []string {
	seen := make(map[string]struct{}, len(paths))
	out := make([]string, 0, len(paths))
	for _, path := range paths {
		path = filepath.Clean(path)
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		out = append(out, path)
	}
	sort.Strings(out)
	return out
}

func globSorted(pattern string) ([]string, error) {
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil, err
	}
	sort.Strings(matches)
	return matches, nil
}
