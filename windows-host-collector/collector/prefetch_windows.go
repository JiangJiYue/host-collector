//go:build windows

package collector

import (
	"os"
	"path/filepath"
	"strings"
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
			File:        name,
			ProcessName: processName,
			ProcessPath: "",
			RunCount:    pc.parseRunCount(fullPath),
			LastRunTime: utils.FormatTime(info.ModTime()),
			Exists:      true,
			CreateTime:  utils.FormatTime(info.ModTime()),
			ModifyTime:  utils.FormatTime(info.ModTime()),
		}

		result = append(result, prefetch)
		idCounter++
	}

	return result
}

// parseRunCount 从 Prefetch 文件头解析运行次数
func (pc *PrefetchCollector) parseRunCount(filePath string) int {
	file, err := os.Open(filePath)
	if err != nil {
		return 0
	}
	defer file.Close()

	// Prefetch 文件格式（Windows 10+）：
	// 偏移 0x00: 版本签名 (4 bytes)
	// 偏移 0x70: 运行次数 (4 bytes, little-endian)
	// 简化实现：读取文件头的运行次数
	buf := make([]byte, 256)
	n, err := file.Read(buf)
	if err != nil || n < 0x74 {
		return 0
	}

	// 读取运行次数（偏移 0x70，4 字节 little-endian）
	runCount := int(buf[0x70]) | int(buf[0x71])<<8 | int(buf[0x72])<<16 | int(buf[0x73])<<24

	if runCount < 0 || runCount > 100000 {
		return 1
	}

	return runCount
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
