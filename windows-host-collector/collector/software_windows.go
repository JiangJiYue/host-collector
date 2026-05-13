//go:build windows

package collector

import (
	"context"
	"fmt"
	"windows-host-collector/models"
	"windows-host-collector/utils"

	"golang.org/x/sys/windows/registry"
)

func (sc *SoftwareCollector) collectPlatformSoftware(ctx context.Context) ([]models.InstalledSoftwareItem, error) {
	software := make([]models.InstalledSoftwareItem, 0)

	// 注册表路径：64位和32位
	regPaths := []string{
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`,
		`SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`,
	}

	idCounter := 0
	for _, regPath := range regPaths {
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, regPath, registry.READ)
		if err != nil {
			utils.LogError("Collector", "打开注册表路径失败 %s: %v", regPath, err)
			continue
		}

		subKeyNames, err := key.ReadSubKeyNames(0)
		if err != nil {
			key.Close()
			continue
		}

		for _, subKeyName := range subKeyNames {
			subKey, err := registry.OpenKey(key, subKeyName, registry.QUERY_VALUE)
			if err != nil {
				continue
			}

			name, _, _ := subKey.GetStringValue("DisplayName")
			if name == "" {
				subKey.Close()
				continue
			}

			publisher, _, _ := subKey.GetStringValue("Publisher")
			installDate, _, _ := subKey.GetStringValue("InstallDate")
			sizeStr, _, _ := subKey.GetStringValue("EstimatedSize")
			version, _, _ := subKey.GetStringValue("DisplayVersion")
			installLocation, _, _ := subKey.GetStringValue("InstallLocation")

			// 转换大小
			var size string
			if sizeStr != "" {
				var sizeKB int64
				fmt.Sscanf(sizeStr, "%d", &sizeKB)
				size = utils.FormatBytes(uint64(sizeKB * 1024))
			}

			item := models.InstalledSoftwareItem{
				Name:            name,
				Publisher:       publisher,
				InstallDate:     installDate,
				Size:            size,
				Version:         version,
				InstallLocation: installLocation,
			}

			software = append(software, item)
			idCounter++
			subKey.Close()
		}
		key.Close()
	}

	return software, nil
}
