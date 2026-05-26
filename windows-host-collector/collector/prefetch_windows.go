//go:build windows

package collector

import (
	"os"
	"path/filepath"
	"strings"
	"windows-host-collector/forensics/prefetch"
	"windows-host-collector/models"
	"windows-host-collector/utils"
)

func (pc *PrefetchCollector) collectPrefetchEntries() []models.PrefetchEntry {
	prefetchDir := `C:\Windows\Prefetch`

	if _, err := os.Stat(prefetchDir); os.IsNotExist(err) {
		utils.Info("Collector", "Prefetch 目录不存在")
		return []models.PrefetchEntry{}
	}

	entries, err := os.ReadDir(prefetchDir)
	if err != nil {
		utils.LogError("Collector", "读取 Prefetch 目录失败: %v", err)
		return []models.PrefetchEntry{}
	}

	result := make([]models.PrefetchEntry, 0)
	idCounter := 0

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(strings.ToUpper(entry.Name()), ".PF") {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		fullPath := filepath.Join(prefetchDir, entry.Name())

		// 解析文件名：APPLICATION-XXXXXXXX.pf
		name := entry.Name()
		processName := strings.SplitN(name, "-", 2)[0]
		processName = strings.TrimSuffix(processName, ".EXE")
		processName = strings.TrimSuffix(processName, ".exe")

		prefetch := models.PrefetchEntry{
			File:             name,
			ProcessName:      processName,
			ProcessPath:      "",
			RunCount:         0,
			LastRunTime:      utils.FormatTime(info.ModTime()),
			FileHash:         getPrefetchHash(name),
			SourcePath:       fullPath,
			ParseStatus:      "unparsed",
			PrefetchFileSize: info.Size(),
			Exists:           true,
			CreateTime:       utils.FormatTime(info.ModTime()),
			ModifyTime:       utils.FormatTime(info.ModTime()),
		}
		if parsed, err := pc.parsePrefetchFile(fullPath, name); err != nil {
			prefetch.ParseStatus = "parse_failed"
			prefetch.ParseError = err.Error()
		} else {
			prefetch.ProcessName = parsed.ExecutableName
			prefetch.RunCount = parsed.RunCount
			prefetch.FormatVersion = parsed.FormatVersion
			prefetch.FileHash = parsed.FileHash
			prefetch.EmbeddedHash = parsed.EmbeddedHash
			prefetch.RunTimes = parsed.RunTimes
			prefetch.ReferencedFiles = parsed.ReferencedFiles
			prefetch.ProcessPath = parsed.ExecutablePath
			if parsed.LastRunTime != "" {
				prefetch.LastRunTime = parsed.LastRunTime
			}
			prefetch.ParseStatus = "parsed"
		}

		result = append(result, prefetch)
		idCounter++
	}

	return result
}

func (pc *PrefetchCollector) parsePrefetchFile(filePath string, evidenceName string) (prefetch.ParsedPrefetch, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return prefetch.ParsedPrefetch{}, err
	}
	return prefetch.Parse(data, evidenceName)
}

func getPrefetchHash(name string) string {
	// Prefetch 文件名格式: APPNAME-HASH.pf
	parts := strings.SplitN(name, "-", 2)
	if len(parts) == 2 {
		hash := strings.TrimSuffix(parts[1], ".pf")
		hash = strings.TrimSuffix(hash, ".PF")
		return hash
	}
	return ""
}
